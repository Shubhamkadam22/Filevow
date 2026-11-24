"""SHA-256 hashing of files and bytes."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CHUNK_SIZE = 64 * 1024


class FileChangedDuringRead(Exception):
    """The file was modified while it was being hashed, so the digest is unreliable."""


@dataclass(frozen=True, slots=True)
class HashResult:
    sha256: str
    size: int
    mtime_ns: int
    file_id: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Hash a file in chunks so large files never need to fit in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(chunk_size):
            digest.update(block)
    return digest.hexdigest()


def hash_file_stable(
    path: str | os.PathLike[str], chunk_size: int = DEFAULT_CHUNK_SIZE, attempts: int = 3
) -> HashResult:
    """Hash a file and prove it did not change while being read (TOCTOU protection).

    The size and modification time are taken from the *open handle* before and after
    reading. If they differ, the read is retried; after ``attempts`` failures we give up
    rather than report a digest that describes no real version of the file.
    """
    for _ in range(attempts):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            before = os.fstat(handle.fileno())
            while block := handle.read(chunk_size):
                digest.update(block)
            after = os.fstat(handle.fileno())
        if (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns):
            return HashResult(digest.hexdigest(), after.st_size, after.st_mtime_ns, after.st_ino)
    raise FileChangedDuringRead(Path(path))
