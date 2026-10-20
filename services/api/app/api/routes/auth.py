"""Password sign-in, sign-out and self-service sign-up.

``/auth/signup`` and ``/auth/login`` are the only unauthenticated writes in the
API. Neither can grant access on its own: a sign-up waits for an admin
(``/workspace/signups``), and a login only succeeds for an approved member. The
session token a login returns is an ordinary, expiring API token.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.auth import Principal, PrincipalDep
from app.core.db import get_db
from app.domain.permissions import Role
from app.scans import accounts, throttle, workspace

router = APIRouter(prefix="/auth", tags=["auth"])


def _client(request: Request) -> str:
    # The direct peer. Forwarded headers are not trusted here: a client could
    # set them to rotate its own bucket.
    return request.client.host if request.client else "unknown"


def _too_many(seconds: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="too many attempts; try again later",
        headers={"Retry-After": str(seconds)},
    )


@router.post(
    "/signup",
    response_model=schemas.SignupAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
def signup(
    body: schemas.SignupIn, request: Request, db: Session = Depends(get_db)
) -> schemas.SignupAccepted:
    """Ask for an account. The answer is the same whether or not the email is
    already registered, so the endpoint cannot be used to list accounts.

    Every request counts against the caller's address, accepted or not, and
    is counted before the password is hashed: scrypt is the expensive part.
    """
    limit = throttle.signup_ip(_client(request))
    if throttle.hit(db, limit) > limit.max:
        db.commit()
        raise _too_many(throttle.retry_after(db, limit) or 1)
    accounts.request_signup(
        db,
        email=body.email,
        display_name=body.display_name,
        password=body.password,
    )
    db.commit()
    return schemas.SignupAccepted()


@router.post("/login", response_model=schemas.SessionOut)
def login(
    body: schemas.LoginIn, request: Request, db: Session = Depends(get_db)
) -> schemas.SessionOut:
    """Sign in. Failures count per email and per client address; a locked
    bucket answers 429 before the password is checked, so a correct guess
    during a lockout is indistinguishable from a wrong one."""
    by_email = throttle.login_email(body.email)
    by_ip = throttle.login_ip(_client(request))
    waits = [
        w
        for w in (throttle.retry_after(db, by_email), throttle.retry_after(db, by_ip))
        if w is not None
    ]
    if waits:
        raise _too_many(max(waits))
    try:
        membership = accounts.authenticate(
            db, email=body.email, password=body.password
        )
    except accounts.InvalidLogin as exc:
        throttle.hit(db, by_email)
        throttle.hit(db, by_ip)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
        ) from exc
    except accounts.AwaitingApproval as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="your account is awaiting approval",
        ) from exc
    except accounts.NoWorkspace as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="your account has no workspace access",
        ) from exc
    throttle.clear(db, by_email)
    raw, token = accounts.start_session(db, membership)
    user = membership.user
    role = Role(membership.role)
    workspace.record_audit(
        db,
        Principal(
            tenant=membership.tenant_slug,
            role=role,
            user_id=user.id,
            email=user.email,
        ),
        "session.started",
        "api_token",
        token.id,
    )
    db.commit()
    return schemas.SessionOut(
        token=raw,
        expires_at=token.expires_at,
        tenant=membership.tenant_slug,
        role=role,
        user=schemas.WorkspaceUserOut(
            id=user.id, email=user.email, display_name=user.display_name
        ),
    )


@router.post("/logout")
def logout(
    principal: PrincipalDep, db: Session = Depends(get_db)
) -> dict[str, str]:
    """End the presented session. An API token is not revoked by this."""
    if principal.token_id is not None and accounts.end_session(
        db, principal.token_id
    ):
        workspace.record_audit(
            db, principal, "session.ended", "api_token", principal.token_id
        )
        db.commit()
    return {"status": "signed_out"}
