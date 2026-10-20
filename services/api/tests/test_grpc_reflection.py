"""gRPC reflection (premium): is the service catalogue exposed?"""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.checks.grpc_reflection import (
    GrpcReflectionCheck,
    _grpc_targets,
    grpc_reflection_request,
    grpc_reflection_response,
    parse_grpc_reflection_response,
)
from tests import factories

GRPC_OP = TargetOperation(id="op-grpc", method="POST", path="/grpc", params=[])


def test_reflection_response_round_trips():
    names = ["grpc.health.v1.Health", "grpc.reflection.v1alpha.ServerReflection"]
    assert parse_grpc_reflection_response(grpc_reflection_response(names)) == names


def test_reflection_request_is_list_services():
    assert b"\x3a\x00" in grpc_reflection_request()


def test_parse_returns_empty_for_non_reflection_bytes():
    assert parse_grpc_reflection_response(b"") == []
    assert parse_grpc_reflection_response(b"not a grpc frame") == []
    assert parse_grpc_reflection_response(b"\x00\x00") == []  # too short to frame
    # A well-framed message that is not a list_services_response yields nothing.
    assert parse_grpc_reflection_response(grpc_reflection_response([])) == []


def test_targets_fall_back_to_a_default_grpc_endpoint():
    # No operation looks like gRPC — the check still probes a conventional /grpc.
    ops = [TargetOperation(id="op-http", method="GET", path="/widgets", params=[])]
    targets = _grpc_targets(factories.scan_context(ops))
    assert [t.path for t in targets] == ["/grpc"]


def test_premium_check_noops_without_premium():
    assert factories.run_one(GrpcReflectionCheck(), [GRPC_OP]) == []


def test_reflection_is_flagged():
    findings = factories.run_one(GrpcReflectionCheck(), [GRPC_OP], premium=True)
    assert findings
    f = findings[0]
    assert f.check == "grpc_reflection"
    assert f.evidence["services"] == ["grpc.health.v1.Health"]
    assert f.confidence.value == "verified"
