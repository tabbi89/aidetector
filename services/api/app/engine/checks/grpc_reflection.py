"""gRPC server reflection (premium): is the service catalogue exposed?

gRPC's server-reflection service lets a client list every service and method —
the gRPC analogue of GraphQL introspection. This is the first, self-contained
slice of gRPC scanning: it sends a reflection list-services request over
gRPC-Web (gRPC's HTTP/1.1 variant, which the probe can reach) and flags when the
response enumerates services. Running the engine's checks against the resolved
protobuf RPCs is the larger follow-on.

The protobuf framing and the reflection message are hand-encoded so the check has
no dependency on a protobuf runtime. Premium: off unless ``premium: true``.
"""
from __future__ import annotations

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, TargetOperation, render_path
from app.engine.resource_map import path_values

_GRPC_CONTENT_TYPE = "application/grpc-web+proto"


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7


def _field(field: int, payload: bytes) -> bytes:
    """A length-delimited protobuf field (tag + length + payload)."""
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload


def grpc_reflection_request() -> bytes:
    """A framed ``ServerReflectionRequest{list_services}`` (field 7, empty)."""
    proto = b"\x3a\x00"
    return b"\x00" + len(proto).to_bytes(4, "big") + proto


def grpc_reflection_response(names: list[str]) -> bytes:
    """A framed ``ServerReflectionResponse`` listing services (for the test target)."""
    # ListServiceResponse{service: [ServiceResponse{name}]}
    services = b"".join(_field(1, _field(1, name.encode())) for name in names)
    response = _field(4, services)          # ServerReflectionResponse{list_services_response}
    return b"\x00" + len(response).to_bytes(4, "big") + response


def _service_name(msg: bytes) -> str:
    i = 0
    while i < len(msg):
        tag, i = _read_varint(msg, i)
        field, wire = tag >> 3, tag & 7
        if wire == 2:
            ln, i = _read_varint(msg, i)
            value = msg[i:i + ln]
            i += ln
            if field == 1:  # ServiceResponse.name
                return value.decode("utf-8", "replace")
        elif wire == 0:
            _, i = _read_varint(msg, i)
        elif wire == 5:
            i += 4
        else:
            break
    return ""


def _walk_names(msg: bytes) -> list[str]:
    """Service names from a ``ListServiceResponse`` body."""
    names: list[str] = []
    i = 0
    while i < len(msg):
        tag, i = _read_varint(msg, i)
        field, wire = tag >> 3, tag & 7
        if wire == 2:
            ln, i = _read_varint(msg, i)
            value = msg[i:i + ln]
            i += ln
            if field == 1:  # repeated ServiceResponse
                names.append(_service_name(value))
        elif wire == 0:
            _, i = _read_varint(msg, i)
        elif wire == 5:
            i += 4
        else:
            break
    return [n for n in names if n]


def parse_grpc_reflection_response(data: bytes) -> list[str]:
    """Service names from a gRPC-Web reflection response, or [] when not one."""
    try:
        if len(data) < 5:
            return []
        length = int.from_bytes(data[1:5], "big")
        body = data[5:5 + length]
        i = 0
        while i < len(body):
            tag, i = _read_varint(body, i)
            field, wire = tag >> 3, tag & 7
            if wire == 2:
                ln, i = _read_varint(body, i)
                value = body[i:i + ln]
                i += ln
                if field == 4:  # list_services_response
                    return _walk_names(value)
            elif wire == 0:
                _, i = _read_varint(body, i)
            elif wire == 5:
                i += 4
            else:
                break
    except (ValueError, IndexError):
        return []
    return []


def _grpc_targets(ctx: ScanContext) -> list[TargetOperation]:
    targets = [op for op in ctx.operations if "grpc" in op.path.lower()]
    if not targets:
        targets.append(TargetOperation(id=None, method="POST", path="/grpc", params=[]))
    return targets


class GrpcReflectionCheck:
    key = "grpc_reflection"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        headers = {**ctx.primary_headers(), "Content-Type": _GRPC_CONTENT_TYPE}
        findings: list[EngineFinding] = []
        for op in _grpc_targets(ctx):
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            r = ctx.probe.send("POST", path, headers=headers, content=grpc_reflection_request())
            if r is None:
                return findings
            services = parse_grpc_reflection_response(r.content or b"")
            if services:
                findings.append(self._finding(op, services))
        return findings

    def _finding(self, op: TargetOperation, services: list[str]) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id="API9:2023",
            severity=Severity.low,
            title=f"gRPC reflection enabled on POST {op.path}",
            description=(
                f"POST {op.path} answered a reflection list-services request with "
                f"{len(services)} service(s), so any caller can enumerate the gRPC "
                "surface. Disable reflection outside development."
            ),
            evidence={"method": "POST", "route": op.path, "services": services[:20]},
            operation_id=op.id,
        )
