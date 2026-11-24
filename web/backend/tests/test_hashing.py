from __future__ import annotations

import os
from pathlib import Path

import pytest

from filevow.core import hashing
from filevow.core.hashing import FileChangedDuringRead, hash_file_stable, sha256_bytes, sha256_file

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_known_test_vectors() -> None:
    assert sha256_bytes(b"") == EMPTY_SHA256
    assert sha256_bytes(b"abc") == ABC_SHA256


def test_chunked_file_hash_matches_whole_hash(tmp_path: Path) -> None:
    data = os.urandom(300_000)  # several chunks, with a partial last chunk
    target = tmp_path / "big.bin"
    target.write_bytes(data)
    assert sha256_file(target, chunk_size=64 * 1024) == sha256_bytes(data)
    assert hash_file_stable(target).sha256 == sha256_bytes(data)


def test_one_byte_change_gives_a_different_hash(tmp_path: Path) -> None:
    target = tmp_path / "config.txt"
    target.write_text("port = 8080")
    before = sha256_file(target)
    target.write_text("port = 8081")
    assert sha256_file(target) != before


def test_file_changing_during_read_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "busy.txt"
    target.write_text("content")
    real_fstat = os.fstat
    calls = {"n": 0}

    class FakeStat:
        def __init__(self, base: os.stat_result, bump: int) -> None:
            self.st_size, self.st_mtime_ns, self.st_ino = base.st_size + bump, base.st_mtime_ns, base.st_ino

    def changing_fstat(fd: int) -> FakeStat:
        calls["n"] += 1
        return FakeStat(real_fstat(fd), bump=calls["n"])  # size differs before and after every read

    monkeypatch.setattr(hashing.os, "fstat", changing_fstat)
    with pytest.raises(FileChangedDuringRead):
        hash_file_stable(target, attempts=3)
