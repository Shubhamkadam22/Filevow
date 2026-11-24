"""Creating signed file versions. Used by baselining and by accepting a change."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from filevow.crypto import keys
from filevow.db.base import utcnow
from filevow.db.enums import BaselineStatus, FileType
from filevow.db.models import FileBaseline, FileVersion, MirrorObject, SigningKey
from filevow.services.records import build_record, sign_record
from filevow.services.snapshot import FileSnapshot


def next_version_number(session: Session, baseline: FileBaseline) -> int:
    """Versions only move forward, even if the baseline row itself was tampered with."""
    if baseline.id is None:
        return 1
    highest = session.scalar(
        select(func.max(FileVersion.version)).where(FileVersion.file_baseline_id == baseline.id)
    )
    return (highest or 0) + 1


def sign_new_version(
    session: Session,
    baseline: FileBaseline,
    snapshot: FileSnapshot,
    mirror_object: MirrorObject | None,
    private_key: keys.PrivateKey,
    signing_key: SigningKey,
    *,
    actor_user_id: int | None,
    reason: str,
    change_event_id: int | None = None,
) -> FileVersion:
    """Point the baseline at the snapshot, sign the record and append it to the history."""
    if snapshot.sha256 is None or snapshot.size is None:
        raise ValueError("only regular, readable files can be signed")

    baseline.current_version = next_version_number(session, baseline)
    baseline.sha256 = snapshot.sha256
    baseline.file_size = snapshot.size
    baseline.file_id = snapshot.file_id
    baseline.permissions = snapshot.permissions
    baseline.owner = snapshot.owner
    baseline.acl_hash = snapshot.acl_hash
    baseline.file_type = FileType.REGULAR
    baseline.mirror_object = mirror_object
    baseline.signing_key = signing_key
    baseline.signed_at = utcnow().replace(microsecond=0)
    baseline.status = BaselineStatus.ACTIVE
    baseline.rsa_signature = baseline.rsa_signature or b""
    session.add(baseline)
    session.flush()  # the record contains the row id

    record = build_record(
        baseline,
        mirror_sha256=mirror_object.sha256 if mirror_object else None,
        key_id=signing_key.key_id,
    )
    baseline.rsa_signature = sign_record(private_key, record)
    version = FileVersion(
        baseline=baseline,
        version=baseline.current_version,
        sha256=snapshot.sha256,
        file_size=snapshot.size,
        mirror_object_id=mirror_object.id if mirror_object else None,
        signed_record=record,
        rsa_signature=baseline.rsa_signature,
        signing_key_id=signing_key.id,
        approved_by=actor_user_id,
        approval_reason=reason,
        change_event_id=change_event_id,
    )
    session.add(version)
    session.flush()
    return version
