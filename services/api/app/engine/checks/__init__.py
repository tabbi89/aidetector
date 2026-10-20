"""Registry of engine-tier checks. Order is display/run order."""
from functools import lru_cache

from app.engine.checks.advanced_rate_limit import AdvancedRateLimitCheck
from app.engine.checks.auth import BrokenAuthCheck
from app.engine.checks.authz import BflaCheck, BolaCheck
from app.engine.checks.business_flow import BusinessFlowCheck
from app.engine.checks.data_exposure import DataExposureCheck
from app.engine.checks.deserialization import DeserializationCheck
from app.engine.checks.design_review import DesignReviewCheck
from app.engine.checks.enumeration import EnumerationCheck
from app.engine.checks.graphql_behavior import GraphQLBehaviorCheck
from app.engine.checks.graphql_introspection import GraphQLIntrospectionCheck
from app.engine.checks.grpc_reflection import GrpcReflectionCheck
from app.engine.checks.host_header import HostHeaderCheck
from app.engine.checks.injection import ReflectedInjectionCheck
from app.engine.checks.jwt_confusion import JwtConfusionCheck
from app.engine.checks.mass_assignment import MassAssignmentCheck
from app.engine.checks.misconfig import InfoDisclosureCheck, SecurityHeadersCheck
from app.engine.checks.oob_injection import OobInjectionCheck
from app.engine.checks.potential_secrets import PotentialSecretsCheck
from app.engine.checks.race_condition import RaceConditionCheck
from app.engine.checks.request_smuggling import RequestSmugglingCheck
from app.engine.checks.resource_consumption import ResourceConsumptionCheck
from app.engine.checks.schema_fuzz import SchemaFuzzCheck
from app.engine.checks.seeded_bola import SeededBolaCheck
from app.engine.checks.signature_injection import SignatureInjectionCheck
from app.engine.checks.ssrf import SsrfCheck
from app.engine.checks.tls import TlsConfigCheck
from app.engine.checks.unsafe_consumption import UnsafeConsumptionCheck
from app.engine.checks.write_oracle import WriteOracleCheck
from app.engine.checks.xxe_confirmation import XxeConfirmationCheck
from app.engine.contracts import Check
from app.engine.contracts import premium as _is_premium

ALL_CHECKS: list[Check] = [
    BolaCheck(),
    BflaCheck(),
    BrokenAuthCheck(),
    # The header sweep is one cheap request per endpoint and runs ahead of the
    # fuzzing checks so the 750-request budget is still there to spend on it.
    SecurityHeadersCheck(),
    InfoDisclosureCheck(),
    # Reads the same sweep the two header checks fill, so it costs no requests.
    DataExposureCheck(),
    # Reuses the same response samples and scans the uploaded spec in an
    # isolated no-network subprocess; never retains candidate values.
    PotentialSecretsCheck(),
    EnumerationCheck(),
    # Read-only API4: a client-controlled page size with no effective cap. Runs
    # beside enumeration (both are business-logic signals needing no identity),
    # but tests response volume rather than request rate.
    ResourceConsumptionCheck(),
    WriteOracleCheck(),
    # Creates an object as one identity and reads it back as another — a stateful
    # sequence sharing the write oracle's create pairing. Writes, so mutate:true.
    SeededBolaCheck(),
    # Also writes to the target (mutate:true) and shares the write oracle's
    # resource pairing, so it runs beside it.
    MassAssignmentCheck(),
    # Fires a concurrent burst that bypasses the rate limiter; writes, so
    # opt-in and serial like the other write probes.
    RaceConditionCheck(),
    # Drives a bounded burst at sensitive business-flow endpoints (API6). Writes
    # (creates objects), so mutate:true and serial like the other write probes.
    BusinessFlowCheck(),
    ReflectedInjectionCheck(),
    SignatureInjectionCheck(),
    SsrfCheck(),
    OobInjectionCheck(),
    SchemaFuzzCheck(),
    TlsConfigCheck(),
    # Premium: spoofed-host probing, off unless premium:true.
    HostHeaderCheck(),
    # Premium: static spec design review (A06), off unless premium:true.
    DesignReviewCheck(),
    # Premium: sustained rate-limit probe, off unless premium:true.
    AdvancedRateLimitCheck(),
    # Premium: full XXE confirmation, off unless premium:true (and mutate:true).
    XxeConfirmationCheck(),
    # Premium: JWT key confusion + jku header injection, off unless premium:true.
    JwtConfusionCheck(),
    # Premium: insecure deserialization gadgets, off unless premium:true (+mutate).
    DeserializationCheck(),
    # Premium: OOB-confirmed unsafe consumption of an upstream API (API10), off
    # unless premium:true and a live OAST collector.
    UnsafeConsumptionCheck(),
    # Premium: GraphQL introspection exposure, off unless premium:true.
    GraphQLIntrospectionCheck(),
    # Premium: bounded suggestions + controlled alias/batch authorization.
    GraphQLBehaviorCheck(),
    # Premium: HTTP request smuggling (raw socket), off unless premium:true.
    RequestSmugglingCheck(),
    # Premium: gRPC reflection exposure, off unless premium:true.
    GrpcReflectionCheck(),
]



@lru_cache(maxsize=1)
def premium_check_keys() -> frozenset[str]:
    """Keys of every check reserved for the premium tier (``premium: true``).

    Derived from the registry so a finding can be labelled by origin without a
    hand-maintained list — the single source of truth is the check's own trait.
    """
    return frozenset(c.key for c in ALL_CHECKS if _is_premium(c))


__all__ = ["ALL_CHECKS", "premium_check_keys"]
