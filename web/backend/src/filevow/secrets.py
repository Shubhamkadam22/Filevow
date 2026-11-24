"""Secret storage.

In production secrets live in Windows Credential Manager (protected by DPAPI) via
``keyring``. Tests use ``MemorySecretStore`` so they never touch the real store.
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
    return KeyringSecretStore(settings.keyring_service)
