"""Human decisions on detected changes: accept, restore, quarantine, reject, escalate.

Every decision is explicit, attributed to a user, carries a reason and lands in the
audit log. Accepting needs the baseline private key; nothing else does.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.config import Settings
from filevow.core.hashing import FileChangedDuringRead, sha256_bytes
from filevow.core.paths import is_within
from filevow.crypto import keys
from filevow.db.base import utcnow
from filevow.db.enums import (
    OPEN_REVIEW_STATUSES,
    BaselineStatus,
    FileType,
    ObjectKind,
    Outcome,
    ReviewStatus,
)
from filevow.db.models import ChangeEvent, FileBaseline, FileVersion, MirrorObject, MonitoredPath, SigningKey
from filevow.services import audit
from filevow.services.baseline import BaselineBuilder
from filevow.services.objects import register_object
from filevow.services.records import verify_record
from filevow.services.snapshot import FileSnapshot, take_snapshot
from filevow.services.trust import TrustedKeys
from filevow.services.versions import sign_new_version
from filevow.vault import MirrorVault, VaultIntegrityError

NOT_ACCEPTABLE = {Outcome.TYPE_CHANGED, Outcome.UNREADABLE}
RESTORABLE = {
    Outcome.FILE_MODIFIED,
    Outcome.FILE_DELETED,
    Outcome.PERMISSION_CHANGED,
    Outcome.TYPE_CHANGED,
    Outcome.RECORD_TAMPERED,
    Outcome.ROLLBACK_DETECTED,
    Outcome.KEY_UNTRUSTED,
    Outcome.FILE_MODIFIED_NO_CLEAN_COPY,
}


class ReviewError(Exception):
    """The requested decision is not possible for this change."""


class ConflictError(ReviewError):
    """The file changed again after the reviewer looked at it."""


@dataclass(frozen=True)
class ReviewResult:
    change_id: int
    action: str
    file_path: str
    message: str
    new_version: int | None = None


class ReviewService:
    def __init__(
        self, session: Session, settings: Settings, vault: MirrorVault, trusted: TrustedKeys
    ) -> None:
        self._session = session
        self._settings = settings
        self._vault = vault
        self._trusted = trusted

    # ------------------------------------------------------------------ lookups

    def open_change(self, change_id: int) -> ChangeEvent:
        event = self._session.get(ChangeEvent, change_id)
        if event is None:
            raise ReviewError(f"change #{change_id} does not exist")
        if event.review_status not in OPEN_REVIEW_STATUSES:
            raise ReviewError(f"change #{change_id} was already {event.review_status}")
        return event

    # ------------------------------------------------------------------ accept

    def accept(
        self,
        change_id: int,
        *,
        actor_user_id: int | None,
        reason: str,
        private_key: keys.PrivateKey,
        signing_key: SigningKey,
        expected_sha256: str | None = None,
    ) -> ReviewResult:
        event = self.open_change(change_id)
        outcome = Outcome(event.event_type)
        if outcome in NOT_ACCEPTABLE:
            raise ReviewError("only a readable regular file can be accepted; restore it instead")

        if outcome is Outcome.FILE_DELETED:
            baseline = self._baseline_for(event)
            baseline.status = BaselineStatus.DELETED
            self._close(event, ReviewStatus.ACCEPTED, actor_user_id, reason)
            self._audit("CHANGE_ACCEPTED", event, actor_user_id, reason, deleted=True)
            return ReviewResult(event.id, "accepted", event.file_path, "The deletion was accepted.")

        snapshot = self._live_snapshot(event.file_path)
        expected = expected_sha256 or event.observed_sha256
        if snapshot.sha256 != expected:
            raise ConflictError("the file changed again since this change was shown; review the new content")

        if outcome is Outcome.UNKNOWN_FILE_CREATED:
            monitored = self._monitored_path_for(event)
            builder = BaselineBuilder(
                self._session, self._settings, self._vault, private_key, signing_key, actor_user_id
            )
            protected = builder.protect_file(
                monitored, Path(event.file_path), reason=reason, change_event_id=event.id
            )
            if protected is None or protected.sha256 != expected:
                raise ConflictError("the file changed while it was being protected")
            event.file_baseline_id = protected.id
            baseline = protected
        else:
            baseline = self._baseline_for(event)
            sign_new_version(
                self._session,
                baseline,
                snapshot,
                self._mirror(baseline.monitored_path, snapshot),
                private_key,
                signing_key,
                actor_user_id=actor_user_id,
                reason=reason,
                change_event_id=event.id,
            )

        self._close(event, ReviewStatus.ACCEPTED, actor_user_id, reason)
        self._audit("CHANGE_ACCEPTED", event, actor_user_id, reason, version=baseline.current_version)
        return ReviewResult(
            event.id,
            "accepted",
            event.file_path,
            f"Protected as version {baseline.current_version}.",
            baseline.current_version,
        )

    # ------------------------------------------------------------------ restore

    def restore(self, change_id: int, *, actor_user_id: int | None, reason: str) -> ReviewResult:
        event = self.open_change(change_id)
        outcome = Outcome(event.event_type)
        if outcome not in RESTORABLE:
            raise ReviewError(self._why_not_restorable(outcome))

        baseline = self._baseline_for(event)
        monitored = baseline.monitored_path
        if not is_within(baseline.file_path, monitored.path):
            raise ReviewError("refusing to write outside the monitored folder")

        version, record = self._newest_trusted_version(baseline)
        mirror_sha = _text(record.get("mirror_object_sha256"))
        if not mirror_sha:
            raise ReviewError("this file has no mirror copy (mirroring was off or the file was too large)")
        try:
            content = self._vault.load(mirror_sha)
        except VaultIntegrityError as exc:
            raise ReviewError(
                "the approved copy in the vault is damaged; accept the current file instead"
            ) from exc

        target = Path(baseline.file_path)
        self._keep_evidence(event, target)
        self._write_atomically(target, content)
        self._apply_permissions(target, record.get("permissions"))

        restored = self._live_snapshot(baseline.file_path)
        if restored.sha256 != record["sha256"] or sha256_bytes(content) != record["sha256"]:
            raise ReviewError("the restored file does not match the approved version")

        self._repair_baseline(baseline, version, record, restored)
        self._close(event, ReviewStatus.RESTORED, actor_user_id, reason)
        metadata_note = ""
        if (record.get("owner"), record.get("acl_hash")) != (restored.owner, restored.acl_hash):
            metadata_note = " Owner or access list still differ; fix them in Windows file properties."
        self._audit("CHANGE_RESTORED", event, actor_user_id, reason, version=version.version)
        return ReviewResult(
            event.id,
            "restored",
            event.file_path,
            f"Restored approved version {version.version}.{metadata_note}",
            version.version,
        )

    # ------------------------------------------------------------------ quarantine / reject / escalate

    def quarantine(self, change_id: int, *, actor_user_id: int | None, reason: str) -> ReviewResult:
        """Remove an unknown file after keeping an encrypted evidence copy."""
        event = self.open_change(change_id)
        if Outcome(event.event_type) is not Outcome.UNKNOWN_FILE_CREATED:
            raise ReviewError("only unknown files can be quarantined; use restore for protected files")
        target = Path(event.file_path)
        if not is_within(target, self._monitored_path_for(event).path):
            raise ReviewError("refusing to remove a file outside the monitored folder")
        self._keep_evidence(event, target)
        if event.evidence is None:
            raise ReviewError("could not keep an evidence copy, so the file was not removed")
        target.unlink(missing_ok=True)
        self._close(event, ReviewStatus.RESTORED, actor_user_id, reason)
        self._audit("FILE_QUARANTINED", event, actor_user_id, reason, evidence=event.evidence.sha256)
        return ReviewResult(
            event.id, "quarantined", event.file_path, "Removed; an evidence copy is in the vault."
        )

    def reject(self, change_id: int, *, actor_user_id: int | None, reason: str) -> ReviewResult:
        event = self.open_change(change_id)
        event.review_status = ReviewStatus.REJECTED
        self._stamp(event, actor_user_id, reason)
        self._reactivate_if_clear(event)
        self._audit("CHANGE_REJECTED", event, actor_user_id, reason)
        return ReviewResult(event.id, "rejected", event.file_path, "Marked as a false positive.")

    def escalate(self, change_id: int, *, actor_user_id: int | None, reason: str) -> ReviewResult:
        event = self.open_change(change_id)
        event.review_status = ReviewStatus.ESCALATED
        self._stamp(event, actor_user_id, reason)
        self._audit("CHANGE_ESCALATED", event, actor_user_id, reason)
        return ReviewResult(event.id, "escalated", event.file_path, "Escalated to the security team.")

    # ------------------------------------------------------------------ helpers

    def _baseline_for(self, event: ChangeEvent) -> FileBaseline:
        baseline = self._session.get(FileBaseline, event.file_baseline_id) if event.file_baseline_id else None
        if baseline is None:
            raise ReviewError("this change is not linked to a protected file")
        return baseline

    def _monitored_path_for(self, event: ChangeEvent) -> MonitoredPath:
        owner = MonitoredPath.owner_id
        in_workspace = owner.is_(None) if event.owner_id is None else owner == event.owner_id
        candidates = [
            m
            for m in self._session.scalars(select(MonitoredPath).where(in_workspace))
            if is_within(event.file_path, m.path)
        ]
        if not candidates:
            raise ReviewError("the file is not inside any monitored path")
        return max(candidates, key=lambda m: len(m.path))

    def _live_snapshot(self, file_path: str) -> FileSnapshot:
        try:
            snapshot = take_snapshot(Path(file_path), self._settings.hash_chunk_size)
        except (PermissionError, FileChangedDuringRead, OSError) as exc:
            raise ReviewError(f"cannot read the file: {exc}") from exc
        if snapshot.file_type is not FileType.REGULAR:
            raise ReviewError(f"the path is now a {snapshot.file_type}, not a regular file")
        return snapshot

    def _mirror(self, monitored: MonitoredPath, snapshot: FileSnapshot) -> MirrorObject | None:
        if not monitored.mirror_enabled or snapshot.size is None:
            return None
        if snapshot.size > self._settings.max_mirror_file_bytes:
            return None
        stored = self._vault.store_file(snapshot.path, expected_sha256=snapshot.sha256)
        return register_object(self._session, stored, ObjectKind.BASELINE)

    def _newest_trusted_version(self, baseline: FileBaseline) -> tuple[FileVersion, dict[str, object]]:
        versions = sorted(baseline.versions, key=lambda v: v.version, reverse=True)
        if not versions:
            raise ReviewError("this file has no signed history")
        for version in versions:
            public_key = self._trusted.get(version.signing_key_id)
            record = version.signed_record
            genuine = public_key is not None and verify_record(public_key, record, version.rsa_signature)
            if (
                genuine
                and record.get("version") == version.version
                and record.get("file_path") == baseline.file_path
            ):
                if version is not versions[0]:
                    raise ReviewError(
                        "the newest signed version is not genuine; re-baseline with the signing key"
                    )
                return version, record
        raise ReviewError("no genuine signed version exists for this file")

    def _keep_evidence(self, event: ChangeEvent, target: Path) -> None:
        if event.evidence is not None or not target.is_file() or target.is_symlink():
            return
        if target.stat().st_size > self._settings.max_mirror_file_bytes:
            return
        stored = self._vault.store_file(target)
        event.evidence = register_object(self._session, stored, ObjectKind.EVIDENCE)

    @staticmethod
    def _write_atomically(target: Path, content: bytes) -> None:
        if target.is_symlink():
            target.unlink()
        elif target.is_dir():
            raise ReviewError("a folder now exists at this path; move it away and restore again")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(target.stat().st_mode | stat.S_IWRITE)  # os.replace cannot overwrite read-only files
        temporary = target.with_name(f".{target.name}.filevow-restore")
        temporary.write_bytes(content)
        os.replace(temporary, target)

    @staticmethod
    def _apply_permissions(target: Path, permissions: object) -> None:
        if not isinstance(permissions, str):
            return
        if sys.platform == "win32":
            mode = target.stat().st_mode
            target.chmod(mode & ~stat.S_IWRITE if permissions == "ro" else mode | stat.S_IWRITE)
        elif permissions.startswith("0o"):
            target.chmod(int(permissions, 8))

    def _repair_baseline(
        self, baseline: FileBaseline, version: FileVersion, record: dict[str, object], restored: FileSnapshot
    ) -> None:
        """Put the baseline row back to the genuine signed record (undoes database tampering)."""
        mirror_sha = record.get("mirror_object_sha256")
        baseline.current_version = version.version
        baseline.sha256 = str(record["sha256"])
        baseline.file_size = int(str(record["file_size"]))
        baseline.permissions = _text(record.get("permissions"))
        baseline.owner = _text(record.get("owner"))
        baseline.acl_hash = _text(record.get("acl_hash"))
        baseline.file_type = FileType.REGULAR
        baseline.file_id = restored.file_id
        baseline.signing_key_id = version.signing_key_id
        baseline.signed_at = datetime.strptime(str(record["signed_at"]), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
        baseline.rsa_signature = version.rsa_signature
        baseline.mirror_object = self._session.scalar(
            select(MirrorObject).where(MirrorObject.sha256 == mirror_sha)
        )
        baseline.status = BaselineStatus.ACTIVE

    def _close(self, event: ChangeEvent, status: ReviewStatus, actor: int | None, reason: str) -> None:
        """Close this change and any other open changes for the same file."""
        siblings = self._session.scalars(
            select(ChangeEvent).where(
                ChangeEvent.file_path == event.file_path,
                ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES),
                ChangeEvent.id != event.id,
            )
        )
        for sibling in siblings:
            sibling.review_status = status
            self._stamp(sibling, actor, f"resolved together with change #{event.id}")
        event.review_status = status
        self._stamp(event, actor, reason)

    @staticmethod
    def _stamp(event: ChangeEvent, actor: int | None, reason: str) -> None:
        event.reviewed_by = actor
        event.reviewed_at = utcnow()
        event.review_reason = reason

    def _reactivate_if_clear(self, event: ChangeEvent) -> None:
        if event.file_baseline_id is None:
            return
        still_open = self._session.scalar(
            select(ChangeEvent.id).where(
                ChangeEvent.file_baseline_id == event.file_baseline_id,
                ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES),
                ChangeEvent.id != event.id,
            )
        )
        baseline = self._session.get(FileBaseline, event.file_baseline_id)
        if baseline is not None and still_open is None and baseline.status is BaselineStatus.PENDING_REVIEW:
            baseline.status = BaselineStatus.ACTIVE

    def _audit(
        self, action: str, event: ChangeEvent, actor: int | None, reason: str, **details: object
    ) -> None:
        audit.record_event(
            self._session,
            action,
            actor_user_id=actor,
            owner_id=event.owner_id,
            target_type="change_event",
            target_id=event.id,
            details={"file": event.file_path, "event": event.event_type, "reason": reason, **details},
        )

    @staticmethod
    def _why_not_restorable(outcome: Outcome) -> str:
        if outcome is Outcome.UNKNOWN_FILE_CREATED:
            return "an unknown file has no approved version; quarantine it instead"
        if outcome is Outcome.MIRROR_CORRUPTED:
            return "the approved copy is damaged; accept the current (unchanged) file to re-mirror it"
        if outcome is Outcome.OWNER_CHANGED:
            return "file ownership must be changed back in Windows file properties"
        return f"{outcome} cannot be restored"


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None
