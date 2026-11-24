"""Turn database rows into API response models."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.api.schemas import (
    ChangeDetailOut,
    ChangeOut,
    DiffLineOut,
    DiffOut,
    FileDetailOut,
    FileOut,
    LayerChecks,
    RunOut,
    VersionOut,
)
from filevow.db.enums import Outcome
from filevow.db.models import (
    ChangeEvent,
    FileBaseline,
    SigningKey,
    User,
    VerificationResult,
    VerificationRun,
)
from filevow.services.alerts import TITLES
from filevow.services.diffing import text_diff
from filevow.services.review import NOT_ACCEPTABLE, RESTORABLE
from filevow.vault import MirrorVault, VaultIntegrityError


def username(session: Session, user_id: int | None) -> str | None:
    if user_id is None:
        return None
    user = session.get(User, user_id)
    return user.username if user else f"user #{user_id}"


def change_out(session: Session, event: ChangeEvent) -> ChangeOut:
    baseline = session.get(FileBaseline, event.file_baseline_id) if event.file_baseline_id else None
    outcome = Outcome(event.event_type)
    path = Path(event.file_path)
    return ChangeOut(
        id=event.id,
        file_path=event.file_path,
        name=path.name,
        folder=path.parent.as_posix(),
        event_type=event.event_type,
        title=TITLES.get(event.event_type, event.event_type),
        severity=event.severity,
        review_status=str(event.review_status),
        expected_sha256=event.expected_sha256,
        observed_sha256=event.observed_sha256,
        expected_size=event.expected_size,
        observed_size=event.observed_size,
        approved_version=baseline.current_version if baseline else None,
        detected_at=event.detected_at,
        last_seen_at=event.last_seen_at,
        occurrence_count=event.occurrence_count,
        can_accept=outcome not in NOT_ACCEPTABLE,
        can_restore=outcome in RESTORABLE and baseline is not None and baseline.mirror_object_id is not None,
        can_quarantine=outcome is Outcome.UNKNOWN_FILE_CREATED,
    )


def change_detail(session: Session, vault: MirrorVault, event: ChangeEvent) -> ChangeDetailOut:
    summary = change_out(session, event)
    result = session.scalar(
        select(VerificationResult)
        .where(VerificationResult.file_path == event.file_path)
        .order_by(VerificationResult.id.desc())
        .limit(1)
    )
    layers = LayerChecks(
        signature=result.signature_valid if result else None,
        version=result.version_valid if result else None,
        mirror=result.mirror_valid if result else None,
        content=result.content_match if result else None,
        metadata=result.metadata_match if result else None,
    )
    diff, note = _diff_for(session, vault, event)
    metadata = (event.details or {}).get("metadata", {})
    return ChangeDetailOut(
        **summary.model_dump(),
        layers=layers,
        metadata_changes=metadata if isinstance(metadata, dict) else {},
        diff=diff,
        diff_note=note,
        reviewed_by=username(session, event.reviewed_by),
        reviewed_at=event.reviewed_at,
        review_reason=event.review_reason,
        run_id=event.run_id,
    )


def _load(vault: MirrorVault, sha: str | None) -> bytes | None:
    if not sha:
        return None
    try:
        return vault.load(sha)
    except VaultIntegrityError:
        return None


def _diff_for(session: Session, vault: MirrorVault, event: ChangeEvent) -> tuple[DiffOut | None, str | None]:
    baseline = session.get(FileBaseline, event.file_baseline_id) if event.file_baseline_id else None
    approved_sha = baseline.mirror_object.sha256 if baseline and baseline.mirror_object else None
    current_sha = event.evidence.sha256 if event.evidence else None
    if approved_sha and approved_sha == current_sha:
        return None, "Content is identical to the approved version; only metadata or the record changed."

    approved = _load(vault, approved_sha)
    current = _load(vault, current_sha)
    if approved_sha and approved is None:
        return None, "The approved copy in the vault is missing or damaged."
    if approved is None and current is None:
        return None, "No content is available to compare."
    diff = text_diff(approved, current)
    if diff is None:
        return None, "Binary or very large file: compare the SHA-256 values instead."
    return DiffOut(
        lines=[DiffLineOut(**line.__dict__) for line in diff.lines], added=diff.added, removed=diff.removed
    ), None


def open_change_ids(session: Session) -> dict[int, int]:
    """Map baseline id → newest open change id."""
    from filevow.db.enums import OPEN_REVIEW_STATUSES

    rows = session.execute(
        select(ChangeEvent.file_baseline_id, ChangeEvent.id)
        .where(ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES), ChangeEvent.file_baseline_id.is_not(None))
        .order_by(ChangeEvent.id)
    )
    return {int(baseline_id): change_id for baseline_id, change_id in rows if baseline_id is not None}


def file_out(baseline: FileBaseline, open_change_id: int | None) -> FileOut:
    return FileOut(
        id=baseline.id,
        file_path=baseline.file_path,
        name=Path(baseline.file_path).name,
        status=str(baseline.status),
        current_version=baseline.current_version,
        sha256=baseline.sha256,
        file_size=baseline.file_size,
        last_verified_at=baseline.last_verified_at,
        open_change_id=open_change_id,
    )


def file_detail(session: Session, baseline: FileBaseline, open_change_id: int | None) -> FileDetailOut:
    key_ids = {k.id: k.key_id for k in session.scalars(select(SigningKey))}
    versions = [
        VersionOut(
            version=v.version,
            sha256=v.sha256,
            file_size=v.file_size,
            approved_by=username(session, v.approved_by),
            approval_reason=v.approval_reason,
            created_at=v.created_at,
            key_id=key_ids.get(v.signing_key_id, "?"),
        )
        for v in sorted(baseline.versions, key=lambda v: v.version, reverse=True)
    ]
    return FileDetailOut(
        **file_out(baseline, open_change_id).model_dump(),
        permissions=baseline.permissions,
        owner=baseline.owner,
        mirrored=baseline.mirror_object_id is not None,
        signed_at=baseline.signed_at,
        key_id=key_ids.get(baseline.signing_key_id, "?"),
        versions=versions,
    )


def run_out(run: VerificationRun) -> RunOut:
    out = RunOut.model_validate(run)
    out.signed = run.agent_signature is not None
    return out
