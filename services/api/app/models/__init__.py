"""Model registry — import all models so Alembic sees them on Base.metadata."""

from app.domain.enums import SEVERITY_RANK, AuthType, Severity, Verdict
from app.models.adjudication import AdjudicationCache
from app.models.agent_memory import AgentMemory
from app.models.base import Base
from app.models.credential import CredentialProfile
from app.models.domain import DomainVerification
from app.models.event import ScanEvent
from app.models.finding import Finding, sort_findings
from app.models.finding_work import FindingComment, FindingWork
from app.models.identity import (
    ApiToken,
    AuditLog,
    AuthThrottle,
    Membership,
    Tenant,
    User,
)
from app.models.ledger import TokenLedger
from app.models.notification import NotificationDelivery, NotificationEndpoint
from app.models.scan import Operation, Scan, ScanStatus

__all__ = [
    "Base",
    "Scan",
    "Operation",
    "ScanStatus",
    "CredentialProfile",
    "DomainVerification",
    "AuthType",
    "Finding",
    "FindingWork",
    "FindingComment",
    "ApiToken",
    "AuditLog",
    "AuthThrottle",
    "Membership",
    "Tenant",
    "User",
    "Severity",
    "Verdict",
    "SEVERITY_RANK",
    "sort_findings",
    "ScanEvent",
    "TokenLedger",
    "AdjudicationCache",
    "AgentMemory",
    "NotificationDelivery",
    "NotificationEndpoint",
]
