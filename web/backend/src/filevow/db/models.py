"""ORM models. The schema follows chapter 17 of the FileVow manual."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from filevow.db.base import Base, UTCDateTime, utcnow
from filevow.db.enums import (
    AlertStatus,
    BaselineStatus,
    ChannelType,
    FileType,
    KeyPurpose,
    KeyStatus,
    ObjectKind,
    ReviewStatus,
    Role,
    RunStatus,
    RunType,
    Severity,
)


def enum_column(enum_cls: type[StrEnum]) -> Enum:
    """Store enums as plain strings so every database (and every human) can read them."""
    return Enum(enum_cls, native_enum=False, length=32, values_callable=lambda e: [m.value for m in e])


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# --------------------------------------------------------------------------- users


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(enum_column(Role), default=Role.VIEWER)
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_totp_step: Mapped[int | None] = mapped_column(BigInteger)
    recovery_codes: Mapped[list[str] | None] = mapped_column(JSON)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    # Cloud sign-in (Supabase): the account's ID there, its verified e-mail address and
    # an encrypted refresh token used only for the once-a-day "in use" count.
    cloud_id: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(320))
    cloud_refresh_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    cloud_reported_on: Mapped[date | None] = mapped_column(Date)
    usage_reporting: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    @property
    def is_cloud(self) -> bool:
        return self.cloud_id is not None


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    issued_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    replaced_by_id: Mapped[int | None] = mapped_column(ForeignKey("refresh_tokens.id"))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))


# --------------------------------------------------------------------------- keys and paths


class SigningKey(TimestampMixin, Base):
    __tablename__ = "signing_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    key_id: Mapped[str] = mapped_column(String(16), unique=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    purpose: Mapped[KeyPurpose] = mapped_column(enum_column(KeyPurpose))
    algorithm: Mapped[str] = mapped_column(String(40))
    public_key_pem: Mapped[str] = mapped_column(Text)
    status: Mapped[KeyStatus] = mapped_column(enum_column(KeyStatus), default=KeyStatus.ACTIVE)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)  # NULL for the agent key
    key_file: Mapped[str | None] = mapped_column(Text)  # passphrase-encrypted private key on disk
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class MonitoredPath(TimestampMixin, Base):
    __tablename__ = "monitored_paths"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(Text, unique=True)
    is_directory: Mapped[bool] = mapped_column(Boolean)
    recursive: Mapped[bool] = mapped_column(Boolean, default=True)
    include_patterns: Mapped[list[str]] = mapped_column(JSON, default=list)
    exclude_patterns: Mapped[list[str]] = mapped_column(JSON, default=list)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity), default=Severity.HIGH)
    mirror_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    follow_symlinks: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), index=True
    )  # the workspace this folder belongs to
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    baselines: Mapped[list[FileBaseline]] = relationship(back_populates="monitored_path")


# --------------------------------------------------------------------------- vault and baselines


class MirrorObject(TimestampMixin, Base):
    __tablename__ = "mirror_objects"

    id: Mapped[int] = mapped_column(primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    storage_path: Mapped[str] = mapped_column(Text)
    original_size: Mapped[int] = mapped_column(BigInteger)
    stored_size: Mapped[int] = mapped_column(BigInteger)
    encryption: Mapped[str] = mapped_column(String(20), default="AES-256-GCM")
    compression: Mapped[str] = mapped_column(String(20), default="zstd")
    kind: Mapped[ObjectKind] = mapped_column(enum_column(ObjectKind))
    replicated: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class FileBaseline(TimestampMixin, Base):
    """The current signed integrity record for one monitored file."""

    __tablename__ = "file_baselines"

    id: Mapped[int] = mapped_column(primary_key=True)
    monitored_path_id: Mapped[int] = mapped_column(ForeignKey("monitored_paths.id"), index=True)
    file_path: Mapped[str] = mapped_column(Text, unique=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(BigInteger)
    file_id: Mapped[int | None] = mapped_column(BigInteger)
    permissions: Mapped[str | None] = mapped_column(String(64))
    owner: Mapped[str | None] = mapped_column(String(256))
    acl_hash: Mapped[str | None] = mapped_column(String(64))
    file_type: Mapped[FileType] = mapped_column(enum_column(FileType), default=FileType.REGULAR)
    mirror_object_id: Mapped[int | None] = mapped_column(ForeignKey("mirror_objects.id"))
    rsa_signature: Mapped[bytes] = mapped_column(LargeBinary)
    signing_key_id: Mapped[int] = mapped_column(ForeignKey("signing_keys.id"))
    signed_at: Mapped[datetime] = mapped_column(UTCDateTime())
    status: Mapped[BaselineStatus] = mapped_column(
        enum_column(BaselineStatus), default=BaselineStatus.ACTIVE, index=True
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)

    monitored_path: Mapped[MonitoredPath] = relationship(back_populates="baselines")
    mirror_object: Mapped[MirrorObject | None] = relationship()
    signing_key: Mapped[SigningKey] = relationship()
    versions: Mapped[list[FileVersion]] = relationship(
        back_populates="baseline", order_by="FileVersion.version"
    )


class FileVersion(TimestampMixin, Base):
    """Append-only history of every approved version of a file."""

    __tablename__ = "file_versions"
    __table_args__ = (
        UniqueConstraint("file_baseline_id", "version", name="uq_file_versions_baseline_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    file_baseline_id: Mapped[int] = mapped_column(ForeignKey("file_baselines.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(BigInteger)
    mirror_object_id: Mapped[int | None] = mapped_column(ForeignKey("mirror_objects.id"))
    signed_record: Mapped[dict[str, Any]] = mapped_column(JSON)
    rsa_signature: Mapped[bytes] = mapped_column(LargeBinary)
    signing_key_id: Mapped[int] = mapped_column(ForeignKey("signing_keys.id"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approval_reason: Mapped[str | None] = mapped_column(Text)
    change_event_id: Mapped[int | None] = mapped_column(ForeignKey("change_events.id"))

    baseline: Mapped[FileBaseline] = relationship(back_populates="versions")


# --------------------------------------------------------------------------- verification


class VerificationRun(Base):
    __tablename__ = "verification_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_type: Mapped[RunType] = mapped_column(enum_column(RunType))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    scheduled_for: Mapped[datetime | None] = mapped_column(UTCDateTime())
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    status: Mapped[RunStatus] = mapped_column(enum_column(RunStatus), default=RunStatus.RUNNING)
    files_checked: Mapped[int] = mapped_column(Integer, default=0)
    ok_count: Mapped[int] = mapped_column(Integer, default=0)
    issue_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    results_sha256: Mapped[str | None] = mapped_column(String(64))
    report_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    agent_signature: Mapped[bytes | None] = mapped_column(LargeBinary)
    error_message: Mapped[str | None] = mapped_column(Text)

    results: Mapped[list[VerificationResult]] = relationship(back_populates="run")


class VerificationResult(Base):
    __tablename__ = "verification_results"
    __table_args__ = (Index("ix_verification_results_baseline_checked", "file_baseline_id", "checked_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("verification_runs.id"), index=True)
    file_baseline_id: Mapped[int | None] = mapped_column(ForeignKey("file_baselines.id"))
    file_path: Mapped[str] = mapped_column(Text)
    signature_valid: Mapped[bool | None] = mapped_column(Boolean)
    version_valid: Mapped[bool | None] = mapped_column(Boolean)
    mirror_valid: Mapped[bool | None] = mapped_column(Boolean)
    content_match: Mapped[bool | None] = mapped_column(Boolean)
    metadata_match: Mapped[bool | None] = mapped_column(Boolean)
    observed_sha256: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(40))
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    run: Mapped[VerificationRun] = relationship(back_populates="results")


class ChangeEvent(Base):
    __tablename__ = "change_events"
    __table_args__ = (Index("ix_change_events_review_severity", "review_status", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    file_baseline_id: Mapped[int | None] = mapped_column(ForeignKey("file_baselines.id"))
    file_path: Mapped[str] = mapped_column(Text)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey("verification_runs.id"))
    event_type: Mapped[str] = mapped_column(String(40))
    severity: Mapped[Severity] = mapped_column(enum_column(Severity))
    expected_sha256: Mapped[str | None] = mapped_column(String(64))
    observed_sha256: Mapped[str | None] = mapped_column(String(64))
    expected_size: Mapped[int | None] = mapped_column(BigInteger)
    observed_size: Mapped[int | None] = mapped_column(BigInteger)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    evidence_object_id: Mapped[int | None] = mapped_column(ForeignKey("mirror_objects.id"))
    review_status: Mapped[ReviewStatus] = mapped_column(
        enum_column(ReviewStatus), default=ReviewStatus.PENDING_REVIEW
    )
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    review_reason: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    evidence: Mapped[MirrorObject | None] = relationship()


# --------------------------------------------------------------------------- alerts


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_severity", "status", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    change_event_id: Mapped[int | None] = mapped_column(ForeignKey("change_events.id"))
    owner_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), index=True
    )  # NULL for alerts about FileVow itself
    alert_type: Mapped[str] = mapped_column(String(40))
    severity: Mapped[Severity] = mapped_column(enum_column(Severity))
    title: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    status: Mapped[AlertStatus] = mapped_column(enum_column(AlertStatus), default=AlertStatus.NEW)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    escalation_level: Mapped[int] = mapped_column(Integer, default=0)
    next_escalation_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class NotificationChannel(TimestampMixin, Base):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    type: Mapped[ChannelType] = mapped_column(enum_column(ChannelType))
    config_enc: Mapped[bytes] = mapped_column(LargeBinary)
    min_severity: Mapped[Severity] = mapped_column(enum_column(Severity), default=Severity.HIGH)
    is_escalation_contact: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class NotificationLog(Base):
    __tablename__ = "notification_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), index=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("notification_channels.id"))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(10))
    error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# --------------------------------------------------------------------------- audit


class AuditEntry(Base):
    """One link in the hash-chained audit log."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    owner_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), index=True
    )  # whose workspace the entry concerns
    action: Mapped[str] = mapped_column(String(40))
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    # Unique prev_hash makes a forked chain impossible at the database level.
    prev_hash: Mapped[str] = mapped_column(String(64), unique=True)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True)


class AuditCheckpoint(TimestampMixin, Base):
    __tablename__ = "audit_checkpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    last_entry_id: Mapped[int] = mapped_column(ForeignKey("audit_log.id"))
    entry_hash: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[int | None] = mapped_column(ForeignKey("verification_runs.id"))
    agent_signature: Mapped[bytes] = mapped_column(LargeBinary)
    signing_key_id: Mapped[int] = mapped_column(ForeignKey("signing_keys.id"))


class AgentHeartbeat(Base):
    __tablename__ = "agent_heartbeats"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    agent_version: Mapped[str | None] = mapped_column(String(20))
    code_sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str | None] = mapped_column(String(20))
