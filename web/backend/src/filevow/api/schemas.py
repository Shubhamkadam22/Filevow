"""Request and response models. Pydantic validates every request body."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from filevow.api.deps import StepUp
from filevow.db.enums import ChannelType, Role, Severity

Reason = Field(min_length=3, max_length=500)


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- auth and users


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, max_length=12)


class UserOut(ORM):
    id: int
    username: str
    role: Role
    mfa_enabled: bool
    is_active: bool
    last_login_at: datetime | None


class MfaSetupOut(BaseModel):
    secret: str
    provisioning_uri: str
    qr_svg: str


class MfaConfirmIn(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class PasswordChangeIn(StepUp):
    new_password: str = Field(min_length=12, max_length=256)


class UserCreateIn(StepUp):
    username: str = Field(min_length=3, max_length=64)
    new_password: str = Field(min_length=12, max_length=256)
    role: Role = Role.VIEWER


class UserUpdateIn(StepUp):
    role: Role | None = None
    is_active: bool | None = None


# --------------------------------------------------------------------------- paths and files


class PathCreateIn(StepUp):
    path: str = Field(min_length=1, max_length=1024)
    severity: Severity = Severity.HIGH
    include: list[str] = Field(default_factory=list, max_length=50)
    exclude: list[str] = Field(default_factory=list, max_length=50)
    recursive: bool = True


class PathUpdateIn(StepUp):
    severity: Severity | None = None
    enabled: bool | None = None
    include: list[str] | None = Field(default=None, max_length=50)
    exclude: list[str] | None = Field(default=None, max_length=50)


class BaselineIn(StepUp):
    key_passphrase: str = Field(min_length=1, max_length=256)


class PathOut(BaseModel):
    id: int
    path: str
    is_directory: bool
    recursive: bool
    include_patterns: list[str]
    exclude_patterns: list[str]
    severity: Severity
    enabled: bool
    mirror_enabled: bool
    protected_files: int
    created_at: datetime


class BaselineOut(BaseModel):
    created: int
    already_protected: int
    mirrored: int
    too_large_to_mirror: list[str]
    unreadable: list[str]


class FileOut(BaseModel):
    id: int
    file_path: str
    name: str
    status: str
    current_version: int
    sha256: str
    file_size: int
    last_verified_at: datetime | None
    open_change_id: int | None


class VersionOut(BaseModel):
    version: int
    sha256: str
    file_size: int
    approved_by: str | None
    approval_reason: str | None
    created_at: datetime
    key_id: str


class FileDetailOut(FileOut):
    permissions: str | None
    owner: str | None
    mirrored: bool
    signed_at: datetime
    key_id: str
    versions: list[VersionOut]


# --------------------------------------------------------------------------- changes


class ChangeOut(BaseModel):
    id: int
    file_path: str
    name: str
    folder: str
    event_type: str
    title: str
    severity: Severity
    review_status: str
    expected_sha256: str | None
    observed_sha256: str | None
    expected_size: int | None
    observed_size: int | None
    approved_version: int | None
    detected_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    can_accept: bool
    can_restore: bool
    can_quarantine: bool


class LayerChecks(BaseModel):
    signature: bool | None
    version: bool | None
    mirror: bool | None
    content: bool | None
    metadata: bool | None


class DiffLineOut(BaseModel):
    kind: Literal["same", "add", "del", "mod"]
    old_number: int | None
    new_number: int | None
    old_text: str | None
    new_text: str | None


class DiffOut(BaseModel):
    lines: list[DiffLineOut]
    added: int
    removed: int


class ChangeDetailOut(ChangeOut):
    layers: LayerChecks
    metadata_changes: dict[str, list[str | None]]
    diff: DiffOut | None
    diff_note: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_reason: str | None
    run_id: int | None


class ReasonIn(BaseModel):
    reason: str = Reason


class RestoreIn(StepUp):
    reason: str = Reason


class AcceptIn(StepUp):
    reason: str = Reason
    key_passphrase: str = Field(min_length=1, max_length=256)
    expected_sha256: str | None = Field(default=None, min_length=64, max_length=64)


class BulkIn(StepUp):
    action: Literal["accept", "restore"]
    ids: list[int] = Field(min_length=1, max_length=500)
    reason: str = Reason
    key_passphrase: str | None = Field(default=None, max_length=256)


class DecisionOut(BaseModel):
    change_id: int
    action: str
    message: str
    new_version: int | None


class BulkOut(BaseModel):
    results: list[DecisionOut]
    skipped: dict[int, str]


# --------------------------------------------------------------------------- alerts, runs, audit


class AlertOut(ORM):
    id: int
    change_event_id: int | None
    alert_type: str
    severity: Severity
    title: str
    message: str
    status: str
    escalation_level: int
    created_at: datetime


class RunOut(ORM):
    id: int
    run_type: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    files_checked: int
    ok_count: int
    issue_count: int
    duration_ms: int | None
    signed: bool = False


class RunIssueOut(BaseModel):
    file_path: str
    outcome: str


class RunDetailOut(RunOut):
    issues: list[RunIssueOut]
    signature_valid: bool | None
    results_sha256: str | None


class AuditOut(BaseModel):
    id: int
    created_at: datetime
    action: str
    actor: str
    target_type: str | None
    target_id: str | None
    details: dict[str, object] | None
    ip_address: str | None
    entry_hash: str


class ChainOut(BaseModel):
    intact: bool
    entries_checked: int
    first_broken_id: int | None
    reason: str | None
    checkpoint_problems: list[str]


# --------------------------------------------------------------------------- dashboard, keys, channels


class LayerSummary(BaseModel):
    content_ok: int
    signatures_ok: int
    mirror_ok: int
    total: int


class RunPoint(BaseModel):
    id: int
    started_at: datetime
    issue_count: int
    duration_ms: int | None


class ActivityOut(BaseModel):
    created_at: datetime
    action: str
    actor: str
    summary: str


class DashboardOut(BaseModel):
    protected_files: int
    monitored_paths: int
    open_changes: int
    open_by_severity: dict[str, int]
    layers: LayerSummary
    last_run: RunOut | None
    next_run_at: datetime | None
    agent_last_seen: datetime | None
    agent_online: bool
    audit_intact: bool
    key_id: str | None
    runs_24h: list[RunPoint]
    activity: list[ActivityOut]
    open_alerts: int


class KeyOut(ORM):
    id: int
    key_id: str
    fingerprint: str
    purpose: str
    algorithm: str
    status: str
    pinned: bool = False
    created_at: datetime


class ChannelIn(StepUp):
    name: str = Field(min_length=1, max_length=64)
    type: ChannelType
    config: dict[str, object]
    min_severity: Severity = Severity.HIGH
    is_escalation_contact: bool = False
    enabled: bool = True


class ChannelOut(BaseModel):
    id: int
    name: str
    type: ChannelType
    min_severity: Severity
    is_escalation_contact: bool
    enabled: bool
    target: str  # e-mail recipients or webhook host, never secrets


class SystemInfoOut(BaseModel):
    version: str
    verification_interval_minutes: int
    monitoring_gap_minutes: int
    signing_key_configured: bool
    database: str


# --------------------------------------------------------------------------- sign-up, workspace, browser


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)


class AuthOptionsOut(BaseModel):
    allow_registration: bool
    has_accounts: bool


class WorkspaceOut(BaseModel):
    """What a new user still needs to set up; drives the "Get started" guide."""

    has_signing_key: bool
    key_id: str | None
    folders: int
    protected_files: int
    unprotected_folders: int
    mfa_enabled: bool
    channels: int
    open_changes: int


class SigningKeyIn(StepUp):
    key_passphrase: str = Field(min_length=12, max_length=256)


class FsEntry(BaseModel):
    name: str
    path: str
    kind: Literal["folder", "file", "drive"]
    size: int | None = None


class FsListing(BaseModel):
    path: str | None
    parent: str | None
    entries: list[FsEntry]
    truncated: bool


class FsPlace(BaseModel):
    label: str
    path: str
    icon: str
