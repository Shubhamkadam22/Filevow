"""The three-layer verification engine.

For every protected file: (1) is the signed record genuine and current, (2) does the
file on disk still match it, (3) is the encrypted mirror copy intact. Differences
become change events that wait for a human. Nothing is ever accepted automatically.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session, selectinload

from filevow.config import Settings
from filevow.core.hashing import FileChangedDuringRead
from filevow.core.metadata import detect_file_type
from filevow.core.paths import is_within, normalize_path
from filevow.core.walker import iter_files, matches_any
from filevow.crypto import keys, signing
from filevow.crypto.canonical import canonical_json, format_timestamp
from filevow.db.base import utcnow
from filevow.db.enums import (
    OPEN_REVIEW_STATUSES,
    BaselineStatus,
    FileType,
    ObjectKind,
    Outcome,
    RunStatus,
    RunType,
    Severity,
)
from filevow.db.models import (
    ChangeEvent,
    FileBaseline,
    FileVersion,
    MirrorObject,
    MonitoredPath,
    VerificationResult,
    VerificationRun,
)
from filevow.services import audit
from filevow.services.objects import register_object
from filevow.services.records import record_for, verify_record
from filevow.services.snapshot import FileSnapshot, take_snapshot
from filevow.services.trust import TrustedKeys
from filevow.vault import MirrorVault, VaultIntegrityError

log = logging.getLogger(__name__)

CRITICAL_OUTCOMES = frozenset(
    {
        Outcome.RECORD_TAMPERED,
        Outcome.ROLLBACK_DETECTED,
        Outcome.KEY_UNTRUSTED,
        Outcome.FILE_MODIFIED_NO_CLEAN_COPY,
    }
)
EXECUTABLE_SUFFIXES = frozenset(
    {".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".php", ".py", ".sh", ".msi"}
)


@dataclass
class FileCheck:
    """Everything learned about one file during a run."""

    file_path: str
    outcome: Outcome = Outcome.OK
    signature_valid: bool | None = None
    version_valid: bool | None = None
    mirror_valid: bool | None = None
    content_match: bool | None = None
    metadata_match: bool | None = None
    observed: FileSnapshot | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def observed_sha256(self) -> str | None:
        return self.observed.sha256 if self.observed else None


@dataclass
class RunSummary:
    run_id: int
    files_checked: int
    ok_count: int
    issues: list[FileCheck]
    duration_ms: int
    signed: bool
    new_change_ids: list[int] = field(default_factory=list)

    @property
    def issue_count(self) -> int:
        return len(self.issues)


def severity_for(outcome: Outcome, path_severity: Severity, file_path: str) -> Severity:
    if outcome in CRITICAL_OUTCOMES:
        return Severity.CRITICAL
    if outcome is Outcome.FILE_MODIFIED:
        return path_severity
    if outcome in (Outcome.FILE_DELETED, Outcome.MIRROR_CORRUPTED, Outcome.TYPE_CHANGED):
        return max(Severity.HIGH, path_severity, key=lambda s: s.rank)
    if outcome in (Outcome.PERMISSION_CHANGED, Outcome.OWNER_CHANGED):
        return Severity.MEDIUM
    if outcome is Outcome.UNKNOWN_FILE_CREATED:
        return Severity.HIGH if Path(file_path).suffix.lower() in EXECUTABLE_SUFFIXES else Severity.MEDIUM
    return Severity.LOW


class Verifier:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        vault: MirrorVault,
        trusted_keys: TrustedKeys,
        agent_key: keys.PrivateKey | None = None,
        *,
        deep_mirror_check: bool = False,
        owner_id: int | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._vault = vault
        self._trusted = trusted_keys
        self._agent_key = agent_key
        self._deep_mirror = deep_mirror_check
        self._owner_id = owner_id  # one workspace per run; None is the shared/legacy workspace
        self._new_change_ids: list[int] = []

    def _in_workspace(self) -> ColumnElement[bool]:
        column = MonitoredPath.owner_id
        return column.is_(None) if self._owner_id is None else column == self._owner_id

    # ------------------------------------------------------------------ public API

    def run(self, run_type: RunType = RunType.MANUAL, only_paths: set[str] | None = None) -> RunSummary:
        """Verify every protected file, or only ``only_paths`` (normalised) for real-time checks."""
        started = time.monotonic()
        self._new_change_ids = []
        run = VerificationRun(run_type=run_type, status=RunStatus.RUNNING, owner_id=self._owner_id)
        self._session.add(run)
        self._session.flush()

        checks: list[FileCheck] = []
        baselines = self._session.scalars(
            select(FileBaseline)
            .join(MonitoredPath)
            .where(
                MonitoredPath.enabled.is_(True),
                self._in_workspace(),
                FileBaseline.status != BaselineStatus.DELETED,
            )
            .options(
                selectinload(FileBaseline.monitored_path),
                selectinload(FileBaseline.mirror_object),
                selectinload(FileBaseline.signing_key),
            )
            .order_by(FileBaseline.file_path)
        ).all()

        protected = {b.file_path for b in baselines}
        if only_paths is not None:
            baselines = [b for b in baselines if b.file_path in only_paths]

        for baseline in baselines:
            check = self.check_file(baseline)
            checks.append(check)
            self._store_result(run, baseline, check)
            if check.outcome is Outcome.OK:
                baseline.last_verified_at = utcnow()
            else:
                self._record_change(run, baseline, check, baseline.monitored_path.severity)

        unknown = (
            self._find_unknown_files(protected)
            if only_paths is None
            else self._find_unknown_among(only_paths - protected)
        )
        for check, monitored in unknown:
            checks.append(check)
            self._store_result(run, None, check)
            self._record_change(run, None, check, monitored.severity)

        issues = [c for c in checks if c.outcome is not Outcome.OK]
        duration_ms = int((time.monotonic() - started) * 1000)
        signed = self._finish_run(run, checks, issues, duration_ms)
        return RunSummary(
            run.id, len(checks), len(checks) - len(issues), issues, duration_ms, signed, self._new_change_ids
        )

    def check_file(self, baseline: FileBaseline) -> FileCheck:
        """Apply the three layers to one protected file and decide the outcome."""
        check = FileCheck(file_path=baseline.file_path)

        public_key = self._trusted.for_owner(baseline.signing_key_id, baseline.monitored_path.owner_id)
        if public_key is None:
            check.outcome = Outcome.KEY_UNTRUSTED
            check.details["reason"] = "record is signed by a key that is not pinned"
            return check

        record = record_for(baseline)
        check.signature_valid = verify_record(public_key, record, baseline.rsa_signature)
        if not check.signature_valid:
            check.outcome = Outcome.RECORD_TAMPERED
            return check

        check.version_valid = self._is_latest_version(baseline, record)
        if not check.version_valid:
            check.outcome = Outcome.ROLLBACK_DETECTED
            return check

        try:
            check.observed = take_snapshot(Path(baseline.file_path), self._settings.hash_chunk_size)
        except (PermissionError, FileChangedDuringRead, OSError) as exc:
            check.outcome = Outcome.UNREADABLE
            check.details["error"] = str(exc)
            return check

        observed = check.observed
        if observed.file_type is FileType.MISSING:
            check.mirror_valid = self._mirror_ok(baseline)
            check.outcome = Outcome.FILE_DELETED
            return check
        if observed.file_type is not FileType.REGULAR:
            check.outcome = Outcome.TYPE_CHANGED
            check.details["observed_type"] = str(observed.file_type)
            return check

        check.content_match = observed.sha256 == baseline.sha256
        if not check.content_match or self._deep_mirror:
            check.mirror_valid = self._mirror_ok(baseline)

        owner_changed = baseline.owner is not None and observed.owner != baseline.owner
        acl_changed = baseline.acl_hash is not None and observed.acl_hash != baseline.acl_hash
        mode_changed = observed.permissions != baseline.permissions
        check.metadata_match = not (owner_changed or acl_changed or mode_changed)
        metadata_changes: dict[str, list[str | None]] = {}
        if mode_changed:
            metadata_changes["permissions"] = [baseline.permissions, observed.permissions]
        if owner_changed:
            metadata_changes["owner"] = [baseline.owner, observed.owner]
        if acl_changed:
            metadata_changes["access_list"] = ["approved", "changed"]
        if metadata_changes:
            check.details["metadata"] = metadata_changes

        if not check.content_match:
            clean_copy_lost = check.mirror_valid is False
            check.outcome = Outcome.FILE_MODIFIED_NO_CLEAN_COPY if clean_copy_lost else Outcome.FILE_MODIFIED
        elif check.mirror_valid is False:
            check.outcome = Outcome.MIRROR_CORRUPTED
        elif owner_changed:
            check.outcome = Outcome.OWNER_CHANGED
        elif acl_changed or mode_changed:
            check.outcome = Outcome.PERMISSION_CHANGED
        return check

    # ------------------------------------------------------------------ layer helpers

    def _is_latest_version(self, baseline: FileBaseline, record: dict[str, Any]) -> bool:
        """The record must be the newest signed version, not an older genuine one."""
        latest_number = self._session.scalar(
            select(func.max(FileVersion.version)).where(FileVersion.file_baseline_id == baseline.id)
        )
        if latest_number != baseline.current_version:
            return False
        latest = self._session.scalar(
            select(FileVersion).where(
                FileVersion.file_baseline_id == baseline.id, FileVersion.version == latest_number
            )
        )
        return latest is not None and latest.signed_record == record

    def _mirror_ok(self, baseline: FileBaseline) -> bool | None:
        if baseline.mirror_object is None:
            return None  # mirroring disabled or file too large; nothing to verify
        try:
            data = self._vault.load(baseline.mirror_object.sha256)
        except VaultIntegrityError:
            return False
        if hashlib.sha256(data).hexdigest() != baseline.sha256:
            return False
        baseline.mirror_object.last_verified_at = utcnow()
        return True

    def _find_unknown_files(self, protected: set[str]) -> list[tuple[FileCheck, MonitoredPath]]:
        found: list[tuple[FileCheck, MonitoredPath]] = []
        monitored_paths = self._session.scalars(
            select(MonitoredPath).where(
                MonitoredPath.enabled.is_(True), MonitoredPath.is_directory.is_(True), self._in_workspace()
            )
        )
        for monitored in monitored_paths:
            files = iter_files(
                monitored.path,
                recursive=monitored.recursive,
                include=monitored.include_patterns,
                exclude=monitored.exclude_patterns,
                follow_symlinks=monitored.follow_symlinks,
            )
            for file_path in files:
                normalized = normalize_path(file_path)
                if normalized in protected:
                    continue
                check = FileCheck(file_path=normalized, outcome=Outcome.UNKNOWN_FILE_CREATED)
                try:
                    check.observed = take_snapshot(file_path, self._settings.hash_chunk_size)
                except (PermissionError, FileChangedDuringRead, OSError) as exc:
                    check.details["error"] = str(exc)
                found.append((check, monitored))
        return found

    def _find_unknown_among(self, paths: set[str]) -> list[tuple[FileCheck, MonitoredPath]]:
        """Real-time variant: only look at the paths the file watcher reported."""
        found: list[tuple[FileCheck, MonitoredPath]] = []
        monitored_paths = self._session.scalars(
            select(MonitoredPath).where(
                MonitoredPath.enabled.is_(True), MonitoredPath.is_directory.is_(True), self._in_workspace()
            )
        ).all()
        for normalized in sorted(paths):
            monitored = self._owning_path(normalized, monitored_paths)
            if monitored is None or detect_file_type(normalized) is not FileType.REGULAR:
                continue
            check = FileCheck(file_path=normalized, outcome=Outcome.UNKNOWN_FILE_CREATED)
            try:
                check.observed = take_snapshot(Path(normalized), self._settings.hash_chunk_size)
            except (PermissionError, FileChangedDuringRead, OSError) as exc:
                check.details["error"] = str(exc)
            found.append((check, monitored))
        return found

    @staticmethod
    def _owning_path(normalized: str, monitored_paths: Sequence[MonitoredPath]) -> MonitoredPath | None:
        for monitored in sorted(monitored_paths, key=lambda m: len(m.path), reverse=True):
            if not is_within(normalized, monitored.path):
                continue
            relative = normalized[len(monitored.path.rstrip("/")) + 1 :]
            if not monitored.recursive and "/" in relative:
                return None
            if monitored.exclude_patterns and matches_any(relative, monitored.exclude_patterns):
                return None
            if monitored.include_patterns and not matches_any(relative, monitored.include_patterns):
                return None
            return monitored
        return None

    # ------------------------------------------------------------------ persistence

    def _store_result(self, run: VerificationRun, baseline: FileBaseline | None, check: FileCheck) -> None:
        self._session.add(
            VerificationResult(
                run_id=run.id,
                file_baseline_id=baseline.id if baseline else None,
                file_path=check.file_path,
                signature_valid=check.signature_valid,
                version_valid=check.version_valid,
                mirror_valid=check.mirror_valid,
                content_match=check.content_match,
                metadata_match=check.metadata_match,
                observed_sha256=check.observed_sha256,
                outcome=str(check.outcome),
            )
        )

    def _record_change(
        self, run: VerificationRun, baseline: FileBaseline | None, check: FileCheck, path_severity: Severity
    ) -> ChangeEvent:
        """Create a pending change, or update the existing one if this is a repeat detection."""
        existing = self._session.scalar(
            select(ChangeEvent).where(
                ChangeEvent.file_path == check.file_path,
                ChangeEvent.event_type == str(check.outcome),
                ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES),
            )
        )
        if existing and existing.observed_sha256 == check.observed_sha256:
            existing.last_seen_at = utcnow()
            existing.occurrence_count += 1
            return existing

        event = ChangeEvent(
            file_baseline_id=baseline.id if baseline else None,
            file_path=check.file_path,
            owner_id=self._owner_id,
            run_id=run.id,
            event_type=str(check.outcome),
            severity=severity_for(check.outcome, path_severity, check.file_path),
            expected_sha256=baseline.sha256 if baseline else None,
            observed_sha256=check.observed_sha256,
            expected_size=baseline.file_size if baseline else None,
            observed_size=check.observed.size if check.observed else None,
            details=check.details or None,
            evidence=self._capture_evidence(check),
        )
        self._session.add(event)
        if baseline is not None:
            baseline.status = BaselineStatus.PENDING_REVIEW
        self._session.flush()
        self._new_change_ids.append(event.id)
        audit.record_event(
            self._session,
            "CHANGE_DETECTED",
            owner_id=self._owner_id,
            target_type="change_event",
            target_id=event.id,
            details={"file": check.file_path, "outcome": str(check.outcome), "severity": str(event.severity)},
        )
        return event

    def _capture_evidence(self, check: FileCheck) -> MirrorObject | None:
        """Keep a copy of the suspicious content before anyone touches it."""
        observed = check.observed
        if observed is None or observed.sha256 is None or observed.size is None:
            return None
        if observed.size > self._settings.max_mirror_file_bytes:
            return None
        try:
            stored = self._vault.store_file(observed.path, expected_sha256=observed.sha256)
        except (OSError, VaultIntegrityError) as exc:
            log.warning("could not capture evidence for %s: %s", observed.path, exc)
            return None
        return register_object(self._session, stored, ObjectKind.EVIDENCE)

    def _finish_run(
        self, run: VerificationRun, checks: list[FileCheck], issues: list[FileCheck], duration_ms: int
    ) -> bool:
        lines = [
            {"file": c.file_path, "outcome": str(c.outcome), "observed": c.observed_sha256} for c in checks
        ]
        run.finished_at = utcnow()
        run.status = RunStatus.COMPLETED
        run.files_checked = len(checks)
        run.ok_count = len(checks) - len(issues)
        run.issue_count = len(issues)
        run.duration_ms = duration_ms
        run.results_sha256 = hashlib.sha256(canonical_json(lines)).hexdigest()
        run.report_json = {
            "run_id": run.id,
            "run_type": str(run.run_type),
            "owner_id": self._owner_id,
            "started_at": format_timestamp(run.started_at),
            "finished_at": format_timestamp(run.finished_at),
            "files_checked": run.files_checked,
            "ok_count": run.ok_count,
            "issue_count": run.issue_count,
            "results_sha256": run.results_sha256,
            "issues": [line for line in lines if line["outcome"] != Outcome.OK],
        }
        if self._agent_key is not None:
            run.agent_signature = signing.sign_payload(self._agent_key, run.report_json)
        audit.record_event(
            self._session,
            "VERIFICATION_RUN",
            owner_id=self._owner_id,
            target_type="verification_run",
            target_id=run.id,
            details={"files": run.files_checked, "issues": run.issue_count, "type": str(run.run_type)},
        )
        return run.agent_signature is not None
