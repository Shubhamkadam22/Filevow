"""The Windows DPAPI secret store: large values, persistence, encryption, migration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from filevow.crypto import keys
from filevow.secrets import DpapiSecretStore, SecretNotFound

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")


def test_holds_an_rsa_3072_private_key(tmp_path: Path, rsa_key: keys.PrivateKey) -> None:
    # Windows Credential Manager refuses values this big ("The stub received bad data").
    pem = keys.private_key_to_pem(rsa_key, passphrase=None).decode("ascii")
    assert len(pem.encode("utf-16-le")) > 2560

    store = DpapiSecretStore(tmp_path / "secrets.dpapi")
    store.set("agent_private_key", pem)

    assert DpapiSecretStore(tmp_path / "secrets.dpapi").get("agent_private_key") == pem


def test_file_is_encrypted_and_keeps_every_value(tmp_path: Path) -> None:
    path = tmp_path / "secrets.dpapi"
    store = DpapiSecretStore(path)
    store.set("vault_key", "a" * 64)
    store.set("jwt_secret", "very-secret-session-value")

    raw = path.read_bytes()
    assert b"very-secret-session-value" not in raw
    assert store.get("vault_key") == "a" * 64
    assert store.exists("jwt_secret")
    assert not store.exists("missing")
    with pytest.raises(SecretNotFound):
        store.get("missing")


def test_values_from_credential_manager_are_moved_into_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = {("FileVow", "vault_key"): "b" * 64}
    monkeypatch.setattr("keyring.get_password", lambda service, name: legacy.get((service, name)))
    store = DpapiSecretStore(tmp_path / "secrets.dpapi", legacy_service="FileVow")

    assert store.get("vault_key") == "b" * 64
    legacy.clear()  # now only the file has it
    assert DpapiSecretStore(tmp_path / "secrets.dpapi").get("vault_key") == "b" * 64
