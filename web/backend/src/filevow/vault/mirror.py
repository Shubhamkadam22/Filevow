"""The mirror vault: encrypted, content-addressed reference copies.

Objects are named by the SHA-256 of their plaintext. Each object is compressed with
zstd and then sealed with AES-256-GCM, using the object name as associated data so a
renamed or swapped object fails authentication.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import zstandard

from filevow.core.hashing import sha256_bytes
from filevow.crypto.aead import DecryptionError, seal, unseal

_COMPRESSION_LEVEL = 10


class VaultIntegrityError(Exception):
    """A vault object is missing, was modified, or does not match its name."""


@dataclass(frozen=True, slots=True)
class StoredObject:
    sha256: str
    storage_path: str  # relative to the vault root, with forward slashes
    original_size: int
    stored_size: int
    created: bool  # False when the content was already in the vault (deduplicated)


class MirrorVault:
    def __init__(self, root: Path, key: bytes) -> None:
        self._root = root
        self._key = key

    @property
    def root(self) -> Path:
        return self._root

    def relative_path(self, sha256: str) -> str:
        return f"objects/{sha256[:2]}/{sha256}"

    def object_path(self, sha256: str) -> Path:
        return self._root / self.relative_path(sha256)

    def contains(self, sha256: str) -> bool:
        return self.object_path(sha256).is_file()

    def store(self, data: bytes, expected_sha256: str | None = None) -> StoredObject:
        actual = sha256_bytes(data)
        if expected_sha256 and actual != expected_sha256:
            raise VaultIntegrityError(
                "content does not match the expected SHA-256 (file changed during read?)"
            )

        target = self.object_path(actual)
        if target.is_file():
            return StoredObject(
                actual, self.relative_path(actual), len(data), target.stat().st_size, created=False
            )

        sealed = seal(
            zstandard.ZstdCompressor(level=_COMPRESSION_LEVEL).compress(data), self._key, actual.encode()
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_bytes(sealed)
        os.replace(temporary, target)  # atomic on the same volume: the object is either complete or absent
        return StoredObject(actual, self.relative_path(actual), len(data), len(sealed), created=True)

    def store_file(self, path: Path, expected_sha256: str | None = None) -> StoredObject:
        return self.store(path.read_bytes(), expected_sha256)

    def load(self, sha256: str) -> bytes:
        """Decrypt an object and prove it still matches its name."""
        target = self.object_path(sha256)
        try:
            sealed = target.read_bytes()
        except FileNotFoundError as exc:
            raise VaultIntegrityError(f"object {sha256[:12]}… is missing") from exc
        try:
            data = zstandard.ZstdDecompressor().decompress(unseal(sealed, self._key, sha256.encode()))
        except (DecryptionError, zstandard.ZstdError) as exc:
            raise VaultIntegrityError(f"object {sha256[:12]}… failed authentication") from exc
        if sha256_bytes(data) != sha256:
            raise VaultIntegrityError(f"object {sha256[:12]}… does not match its name")
        return data

    def is_intact(self, sha256: str) -> bool:
        try:
            self.load(sha256)
        except VaultIntegrityError:
            return False
        return True
