"""vulnbank — an INTENTIONALLY VULNERABLE demo API.

⚠️  FOR LOCAL TESTING ONLY. Do not deploy. Every "vulnerability" here is
deliberate so the aidetector scanner has real findings to detect:

  - BOLA (API1):  GET /accounts/{id} returns any account regardless of owner.
  - Broken Auth (API2): GET /accounts/{id} accepts *any* non-empty token.
  - BFLA (API5):  POST /admin/users/{id}/promote has no role check.
  - BOLA on write (API1): PUT/POST /notes has no owner check — any identity can
    overwrite or create another user's note (the write oracle confirms this).
  - Injection reflection (proxy for API10/INJ): GET /search echoes `q` raw.
  - Verbose errors (API8): tracebacks leaked on bad input.

FastAPI publishes the OpenAPI spec at /openapi.json — that's what a scan
profile ingests.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="vulnbank (intentionally vulnerable demo)",
    version="0.1.0",
    description="Deliberately insecure API used as a local scan target.",
)

# --- Seed data: two users / roles, so BOLA & BFLA are testable ---
USERS = {
    1: {"id": 1, "username": "alice", "role": "user", "token": "alice-token"},
    2: {"id": 2, "username": "admin", "role": "admin", "token": "admin-token"},
}
ACCOUNTS = {
    1: {"id": 1, "owner_id": 1, "balance_cents": 42000, "iban": "PL10alice"},
    2: {"id": 2, "owner_id": 2, "balance_cents": 9900000, "iban": "PL20admin"},
}


class LoginBody(BaseModel):
    username: str
    password: str


class TransferBody(BaseModel):
    to_account: int
    amount_cents: int


def _user_from_token(token: str | None) -> dict:
    # VULN (API2): accepts any non-empty token; never verifies it maps to a user.
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    for u in USERS.values():
        if token == u["token"]:
            return u
    # Falls through to a default identity instead of rejecting — broken auth.
    return {"id": 0, "username": "unknown", "role": "user", "token": token}


@app.post("/login", tags=["auth"])
def login(body: LoginBody) -> dict:
    for u in USERS.values():
        if u["username"] == body.username:
            # VULN: password is never checked.
            return {"token": u["token"], "role": u["role"]}
    raise HTTPException(status_code=404, detail="no such user")


@app.get("/users/me", tags=["users"])
def me(authorization: str | None = Header(default=None)) -> dict:
    return _user_from_token(authorization)


@app.get("/accounts/{account_id}", tags=["accounts"])
def get_account(
    account_id: int, authorization: str | None = Header(default=None)
) -> dict:
    caller = _user_from_token(authorization)
    acct = ACCOUNTS.get(account_id)
    if not acct:
        raise HTTPException(status_code=404, detail="no such account")
    # VULN (API1 BOLA): returns the account with no owner check.
    _ = caller
    return acct


@app.post("/accounts/{account_id}/transfer", tags=["accounts"])
def transfer(
    account_id: int,
    body: TransferBody,
    authorization: str | None = Header(default=None),
) -> dict:
    caller = _user_from_token(authorization)
    src = ACCOUNTS.get(account_id)
    if not src:
        raise HTTPException(status_code=404, detail="no such account")
    # VULN (API1): no check that caller owns account_id.
    _ = caller
    return {"from": account_id, "to": body.to_account, "moved": body.amount_cents}


@app.post("/admin/users/{user_id}/promote", tags=["admin"])
def promote(user_id: int, authorization: str | None = Header(default=None)) -> dict:
    # VULN (API5 BFLA): privileged operation with no role/authorization check.
    _ = _user_from_token(authorization)
    u = USERS.get(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="no such user")
    u["role"] = "admin"
    return {"id": user_id, "role": "admin"}


class NoteBody(BaseModel):
    title: str = ""
    body: str = ""


# --- Notes: a CRUD resource with NO owner check on writes, so a low-privilege
#     identity can update/create another user's note (API1 BOLA on write). ---
NOTES: dict[int, dict] = {
    1: {"id": 1, "owner_id": 2, "title": "admin note", "body": "private"},
}


@app.get("/notes/{note_id}", tags=["notes"])
def get_note(note_id: int, authorization: str | None = Header(default=None)) -> dict:
    _ = _user_from_token(authorization)
    return NOTES.get(note_id, {"id": note_id, "title": "", "body": "", "owner_id": 0})


@app.put("/notes/{note_id}", tags=["notes"])
def put_note(
    note_id: int, body: NoteBody, authorization: str | None = Header(default=None)
) -> dict:
    # VULN (API1 BOLA on write): no owner check — any identity overwrites any note.
    _ = _user_from_token(authorization)
    note = NOTES.setdefault(note_id, {"id": note_id, "owner_id": 0})
    note["title"] = body.title
    note["body"] = body.body
    return note


@app.post("/notes", tags=["notes"])
def create_note(body: NoteBody, authorization: str | None = Header(default=None)) -> dict:
    # VULN: any identity can create; the new id is returned (read-back-able).
    user = _user_from_token(authorization)
    nid = (max(NOTES) + 1) if NOTES else 1
    NOTES[nid] = {"id": nid, "owner_id": user["id"], "title": body.title, "body": body.body}
    return NOTES[nid]


@app.delete("/notes/{note_id}", tags=["notes"])
def delete_note(note_id: int, authorization: str | None = Header(default=None)) -> dict:
    _ = _user_from_token(authorization)
    NOTES.pop(note_id, None)
    return {"deleted": note_id}


@app.get("/search", tags=["search"], response_class=HTMLResponse)
def search(q: str = "") -> str:
    # VULN (reflection / XSS surface): echoes user input into HTML unescaped.
    return f"<html><body>Results for: {q}</body></html>"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
