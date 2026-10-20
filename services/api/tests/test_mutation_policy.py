"""No HTTP write verb leaves the scanner unless mutate:true was selected."""
from __future__ import annotations

import jwt
import pytest

from app.engine.checks.advanced_rate_limit import AdvancedRateLimitCheck
from app.engine.checks.auth import BrokenAuthCheck
from app.engine.checks.authz import BflaCheck
from app.engine.checks.enumeration import EnumerationCheck
from app.engine.checks.jwt_confusion import JwtConfusionCheck
from app.engine.checks.ssrf import SsrfCheck
from tests import factories


@pytest.mark.parametrize(
    "check,operation,premium",
    [
        (BrokenAuthCheck(), factories.operation("POST", "/account", auth_scope="bearer"), False),
        (BflaCheck(), factories.operation("POST", "/admin/promote", auth_scope="admin"), False),
        (EnumerationCheck(), factories.operation("POST", "/password/reset", params=[]), False),
        (AdvancedRateLimitCheck(), factories.operation("POST", "/login", params=[]), True),
        (
            SsrfCheck(),
            factories.operation(
                "POST",
                "/webhook",
                params=[{"name": "url", "in": "query", "required": False}],
            ),
            False,
        ),
    ],
)
def test_mutating_checks_send_nothing_without_opt_in(check, operation, premium):
    ctx = factories.scan_context([operation], premium=premium, allow_mutation=False)
    assert check.run(ctx) == []
    assert ctx.probe.count == 0


def test_jwt_confusion_never_uses_an_unsafe_operation_without_opt_in():
    token = jwt.encode({"sub": "u"}, "secret", algorithm="HS256")
    cred = factories.credential("alice", "user", token)
    operation = factories.operation("POST", "/admin/promote", auth_scope="admin")
    ctx = factories.scan_context(
        [operation], credentials=[cred], premium=True, allow_mutation=False
    )

    JwtConfusionCheck().run(ctx)

    assert all(row["method"] in {"GET", "HEAD", "OPTIONS"} for row in ctx.probe.mutations)
