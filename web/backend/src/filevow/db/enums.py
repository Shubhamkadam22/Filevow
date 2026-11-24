"""Enumerations stored in the database (as strings, so rows stay readable)."""

from enum import StrEnum


class Role(StrEnum):
    """``user`` owns a private workspace; ``admin`` also manages accounts and the system.
    ``analyst`` and ``viewer`` are read-mostly roles kept for shared installations."""

    ADMIN = "admin"
    USER = "user"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class KeyPurpose(StrEnum):
    BASELINE = "baseline"
    AGENT = "agent"


class KeyStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class ObjectKind(StrEnum):
    BASELINE = "baseline"
    EVIDENCE = "evidence"


class FileType(StrEnum):
    REGULAR = "regular"
    LINK = "link"
    JUNCTION = "junction"
    DIRECTORY = "directory"
    MISSING = "missing"


class BaselineStatus(StrEnum):
    ACTIVE = "active"
    PENDING_REVIEW = "pending_review"
    DELETED = "deleted"


class RunType(StrEnum):
    SCHEDULED = "scheduled"
    STARTUP = "startup"
    MANUAL = "manual"
    REALTIME = "realtime"
    BASELINE = "baseline"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    MISSED = "missed"


class Outcome(StrEnum):
    """Result of verifying one file. Names follow the decision table in the manual."""

    OK = "OK"
    RECORD_TAMPERED = "RECORD_TAMPERED"
    ROLLBACK_DETECTED = "ROLLBACK_DETECTED"
    KEY_UNTRUSTED = "KEY_UNTRUSTED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_MODIFIED_NO_CLEAN_COPY = "FILE_MODIFIED_NO_CLEAN_COPY"
    FILE_DELETED = "FILE_DELETED"
    MIRROR_CORRUPTED = "MIRROR_CORRUPTED"
    TYPE_CHANGED = "TYPE_CHANGED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    OWNER_CHANGED = "OWNER_CHANGED"
    UNKNOWN_FILE_CREATED = "UNKNOWN_FILE_CREATED"
    UNREADABLE = "UNREADABLE"


class ReviewStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    ACCEPTED = "accepted"
    RESTORED = "restored"
    REJECTED = "rejected"
    ESCALATED = "escalated"


OPEN_REVIEW_STATUSES = (ReviewStatus.PENDING_REVIEW, ReviewStatus.ESCALATED)


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ChannelType(StrEnum):
    EMAIL = "email"
    DESKTOP = "desktop"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
