"""A point-in-time description of a file on disk."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from filevow.core.hashing import DEFAULT_CHUNK_SIZE, hash_file_stable
from filevow.core.metadata import describe_permissions, detect_file_type, read_security_info
from filevow.db.enums import FileType


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    path: Path
    file_type: FileType
    sha256: str | None = None
    size: int | None = None
    file_id: int | None = None
    permissions: str | None = None
    owner: str | None = None
    acl_hash: str | None = None

    @property
    def exists(self) -> bool:
        return self.file_type is not FileType.MISSING


def take_snapshot(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> FileSnapshot:
    """Describe a file. Only regular files are hashed; links are never followed.

    Raises ``PermissionError`` or ``FileChangedDuringRead`` when the content cannot
    be read reliably; callers report those as ``UNREADABLE``.
    """
    file_type = detect_file_type(path)
    if file_type is not FileType.REGULAR:
        return FileSnapshot(path=path, file_type=file_type)

    digest = hash_file_stable(path, chunk_size)
    security = read_security_info(path)
    return FileSnapshot(
        path=path,
        file_type=file_type,
        sha256=digest.sha256,
        size=digest.size,
        file_id=digest.file_id,
        permissions=describe_permissions(os.stat(path).st_mode),
        owner=security.owner,
        acl_hash=security.acl_hash,
    )
