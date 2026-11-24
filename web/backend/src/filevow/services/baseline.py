"""Registering monitored paths and creating signed baselines."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.config import Settings
from filevow.core.hashing import FileChangedDuringRead
from filevow.core.paths import is_within, normalize_path
from filevow.core.walker import iter_files
from filevow.crypto import keys
from filevow.db.enums import FileType, ObjectKind, Severity
from filevow.db.models import FileBaseline, MonitoredPath, SigningKey
from filevow.services import audit
from filevow.services.objects import register_object
from filevow.services.snapshot import take_snapshot
from filevow.services.versions import sign_new_version
from filevow.vault import MirrorVault

log = logging.getLogger(__name__)


class MonitoredPathError(ValueError):
    pass


@dataclass
class BaselineSummary:
    created: int = 0
    already_protected: int = 0
    mirrored: int = 0
    too_large_to_mirror: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)


def add_monitored_path(
    session: Session,
    settings: Settings,
    path: str | Path,
    *,
    recursive: bool = True,
    include: Sequence[str] = (),
    exclude: Sequence[str] = (),
    severity: Severity = Severity.HIGH,
    actor_user_id: int | None = None,
    owner_id: int | None = None,
) -> MonitoredPath:
    native = Path(path)
    if not native.exists():
        raise MonitoredPathError(f"{native} does not exist")

    normalized = normalize_path(native)
    for internal in settings.internal_dirs:
        if is_within(normalized, internal) or is_within(internal, normalized):
            raise MonitoredPathError("FileVow's own data, vault, key and log folders cannot be monitored")
    existing = session.scalar(select(MonitoredPath).where(MonitoredPath.path == normalized))
    if existing is not None:
        if existing.owner_id == owner_id:
            raise MonitoredPathError(f"{native} is already in your workspace")
        raise MonitoredPathError(f"{native} is already protected in another workspace")

    monitored = MonitoredPath(
        path=normalized,
        is_directory=native.is_dir(),
        recursive=recursive,
        include_patterns=list(include),
        exclude_patterns=list(exclude),
        severity=severity,
        owner_id=owner_id,
        created_by=actor_user_id,
    )
    session.add(monitored)
    session.flush()
    audit.record_event(
        session,
        "PATH_ADDED",
        actor_user_id=actor_user_id,
        owner_id=owner_id,
        target_type="monitored_path",
        target_id=monitored.id,
        details={"path": normalized, "severity": str(severity)},
    )
    return monitored


class BaselineBuilder:
    """Hashes, mirrors and signs every file under a monitored path.

    The private key is held only for the lifetime of this object; the caller unlocks
    it with the passphrase right before and discards it right after.
    """

    def __init__(
        self,
        session: Session,
        settings: Settings,
        vault: MirrorVault,
        private_key: keys.PrivateKey,
        signing_key: SigningKey,
        actor_user_id: int | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._vault = vault
        self._private_key = private_key
        self._signing_key = signing_key
        self._actor = actor_user_id

    def protect(self, monitored: MonitoredPath) -> BaselineSummary:
        summary = BaselineSummary()
        known = set(
            self._session.scalars(
                select(FileBaseline.file_path).where(FileBaseline.monitored_path_id == monitored.id)
            )
        )
        files = iter_files(
            monitored.path,
            recursive=monitored.recursive,
            include=monitored.include_patterns,
            exclude=monitored.exclude_patterns,
            follow_symlinks=monitored.follow_symlinks,
        )
        for file_path in files:
            if normalize_path(file_path) in known:
                summary.already_protected += 1
                continue
            self.protect_file(monitored, file_path, summary)

        audit.record_event(
            self._session,
            "BASELINE_CREATED",
            actor_user_id=self._actor,
            owner_id=monitored.owner_id,
            target_type="monitored_path",
            target_id=monitored.id,
            details={"path": monitored.path, "files": summary.created, "key_id": self._signing_key.key_id},
        )
        return summary

    def protect_file(
        self,
        monitored: MonitoredPath,
        file_path: Path,
        summary: BaselineSummary | None = None,
        *,
        reason: str = "initial baseline",
        change_event_id: int | None = None,
    ) -> FileBaseline | None:
        """Hash, mirror and sign one file as version 1. Returns ``None`` if it cannot be read."""
        summary = summary if summary is not None else BaselineSummary()
        try:
            snapshot = take_snapshot(file_path, self._settings.hash_chunk_size)
        except (PermissionError, FileChangedDuringRead, OSError) as exc:
            log.warning("cannot read %s: %s", file_path, exc)
            summary.unreadable.append(str(file_path))
            return None
        if snapshot.file_type is not FileType.REGULAR or snapshot.sha256 is None or snapshot.size is None:
            return None

        mirror_object = None
        if monitored.mirror_enabled:
            if snapshot.size <= self._settings.max_mirror_file_bytes:
                stored = self._vault.store_file(file_path, expected_sha256=snapshot.sha256)
                mirror_object = register_object(self._session, stored, ObjectKind.BASELINE)
                summary.mirrored += 1
            else:
                summary.too_large_to_mirror.append(str(file_path))

        baseline = FileBaseline(monitored_path_id=monitored.id, file_path=normalize_path(file_path))
        sign_new_version(
            self._session,
            baseline,
            snapshot,
            mirror_object,
            self._private_key,
            self._signing_key,
            actor_user_id=self._actor,
            reason=reason,
            change_event_id=change_event_id,
        )
        summary.created += 1
        return baseline
