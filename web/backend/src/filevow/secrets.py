"""Secret storage.

On Windows FileVow's own secrets (vault key, agent signing key, session secret, pinned
fingerprints, audit chain head) live in one file encrypted with DPAPI for the signed-in
Windows user (``DpapiSecretStore``). That is the protection Windows Credential Manager uses
too, but without its 2.5 KB limit per entry, which an RSA-3072 private key exceeds.
Tests use ``MemorySecretStore`` so they never touch the real store.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import keyring

if TYPE_CHECKING:
    from filevow.config import Settings

VAULT_KEY = "vault_key"
AGENT_PRIVATE_KEY = "agent_private_key"
BASELINE_FINGERPRINT = "baseline_key_fingerprint"
AUDIT_CHAIN_HEAD = "audit_chain_head"
JWT_SECRET = "jwt_secret"  # noqa: S105 - the name of the secret, not its value


class SecretNotFound(Exception):
    pass


class SecretStore(Protocol):
    def get(self, name: str) -> str: ...
    def set(self, name: str, value: str) -> None: ...
    def exists(self, name: str) -> bool: ...


class KeyringSecretStore:
    def __init__(self, service: str) -> None:
        self._service = service

    def get(self, name: str) -> str:
        value = keyring.get_password(self._service, name)
        if value is None:
            raise SecretNotFound(name)
        return value

    def set(self, name: str, value: str) -> None:
        keyring.set_password(self._service, name, value)

    def exists(self, name: str) -> bool:
        return keyring.get_password(self._service, name) is not None


class DpapiSecretStore:
    """All secrets in one file, encrypted with Windows DPAPI for the current user.

    Only the same Windows account on the same computer can decrypt it. Values that an
    older version saved in Windows Credential Manager are moved into the file the first
    time they are read.
    """

    _ENTROPY = b"FileVow secret store v1"
    _UI_FORBIDDEN = 0x01  # CRYPTPROTECT_UI_FORBIDDEN: never show a prompt

    def __init__(self, path: Path, legacy_service: str | None = None) -> None:
        self._path = path
        self._legacy_service = legacy_service

    def _load(self) -> dict[str, str]:
        if not self._path.is_file():
            return {}
        import win32crypt  # pywin32; Windows only

        _, plaintext = win32crypt.CryptUnprotectData(
            self._path.read_bytes(), self._ENTROPY, None, None, self._UI_FORBIDDEN
        )
        data: dict[str, str] = json.loads(plaintext.decode("utf-8"))
        return data

    def _save(self, values: dict[str, str]) -> None:
        import win32crypt

        blob = win32crypt.CryptProtectData(
            json.dumps(values).encode("utf-8"),
            "FileVow secrets",
            self._ENTROPY,
            None,
            None,
            self._UI_FORBIDDEN,
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(".tmp")
        temporary.write_bytes(blob)
        os.replace(temporary, self._path)

    def _legacy(self, name: str) -> str | None:
        if not self._legacy_service:
            return None
        try:
            return keyring.get_password(self._legacy_service, name)
        except Exception:  # no keyring backend, or the entry is unreadable
            return None

    def get(self, name: str) -> str:
        values = self._load()
        if name in values:
            return values[name]
        legacy = self._legacy(name)
        if legacy is None:
            raise SecretNotFound(name)
        values[name] = legacy
        self._save(values)
        return legacy

    def set(self, name: str, value: str) -> None:
        values = self._load()
        values[name] = value
        self._save(values)

    def exists(self, name: str) -> bool:
        try:
            self.get(name)
        except SecretNotFound:
            return False
        return True


class MemorySecretStore:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get(self, name: str) -> str:
        try:
            return self._values[name]
        except KeyError:
            raise SecretNotFound(name) from None

    def set(self, name: str, value: str) -> None:
        self._values[name] = value

    def exists(self, name: str) -> bool:
        return name in self._values


class FileSecretStore:
    """Secrets in a JSON file readable only by the service account.

    For development and for servers without an OS keyring (for example Linux
    containers, where the file should live on an encrypted volume). Prefer
    ``KeyringSecretStore`` on Windows.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def _load(self) -> dict[str, str]:
        if not self._path.is_file():
            return {}
        data: dict[str, str] = json.loads(self._path.read_text(encoding="utf-8"))
        return data

    def get(self, name: str) -> str:
        try:
            return self._load()[name]
        except KeyError:
            raise SecretNotFound(name) from None

    def set(self, name: str, value: str) -> None:
        values = self._load()
        values[name] = value
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(".tmp")
        temporary.write_text(json.dumps(values, indent=2), encoding="utf-8")
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, self._path)

    def exists(self, name: str) -> bool:
        return name in self._load()


def create_secret_store(settings: Settings) -> SecretStore:
    if settings.key_storage == "file":
        return FileSecretStore(settings.home / "secrets" / "secrets.json")
    if settings.key_storage == "dpapi":
        return DpapiSecretStore(
            settings.home / "secrets" / "secrets.dpapi", legacy_service=settings.keyring_service
        )
    return KeyringSecretStore(settings.keyring_service)
