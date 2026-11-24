from __future__ import annotations

import os
from pathlib import Path

import pytest

from filevow.core.hashing import sha256_bytes
from filevow.core.paths import is_within, normalize_path
from filevow.core.walker import iter_files
from filevow.crypto import aead
from filevow.vault import MirrorVault, VaultIntegrityError


@pytest.fixture
def vault(tmp_path: Path) -> MirrorVault:
    return MirrorVault(tmp_path / "vault", aead.generate_key())


def test_store_and_load_round_trip(vault: MirrorVault) -> None:
    stored = vault.store(b"<h1>Hello</h1>")
    assert stored.created and stored.sha256 == sha256_bytes(b"<h1>Hello</h1>")
    assert vault.load(stored.sha256) == b"<h1>Hello</h1>"
    assert b"Hello" not in vault.object_path(stored.sha256).read_bytes()  # encrypted at rest


def test_identical_content_is_stored_once(vault: MirrorVault) -> None:
    first, second = vault.store(b"same"), vault.store(b"same")
    assert first.sha256 == second.sha256 and not second.created


def test_flipped_byte_in_vault_object_is_detected(vault: MirrorVault) -> None:
    stored = vault.store(b"approved content")
    path = vault.object_path(stored.sha256)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(VaultIntegrityError):
        vault.load(stored.sha256)


def test_swapped_vault_objects_are_detected(vault: MirrorVault) -> None:
    old, current = vault.store(b"old version"), vault.store(b"current version")
    vault.object_path(current.sha256).write_bytes(vault.object_path(old.sha256).read_bytes())
    with pytest.raises(VaultIntegrityError):
        vault.load(current.sha256)


def test_expected_hash_mismatch_is_refused(vault: MirrorVault) -> None:
    with pytest.raises(VaultIntegrityError):
        vault.store(b"content", expected_sha256="0" * 64)


def test_walker_applies_include_and_exclude(site: Path) -> None:
    names = sorted(p.name for p in iter_files(site, exclude=["*.log"]))
    assert names == ["about.html", "app.js", "index.html"]
    assert sorted(p.name for p in iter_files(site, include=["*.html"])) == ["about.html", "index.html"]
    assert sorted(p.name for p in iter_files(site, recursive=False, exclude=["*.log"])) == [
        "about.html",
        "index.html",
    ]


def test_walker_never_follows_links(site: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    try:
        os.symlink(outside, site / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra privileges on this system")
    assert "link.txt" not in {p.name for p in iter_files(site)}


def test_path_normalisation(tmp_path: Path) -> None:
    root = tmp_path / "Site"
    assert normalize_path(root / "a" / ".." / "Index.HTML") == normalize_path(root / "Index.HTML")
    assert is_within(root / "a" / "b.txt", root)
    assert not is_within(root / ".." / "elsewhere.txt", root)
