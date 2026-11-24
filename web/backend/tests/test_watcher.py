"""Real-time watcher: protected paths added or removed while running, single files."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from filevow.agent.watcher import FileWatcher
from filevow.core.paths import normalize_path


class Collector:
    def __init__(self) -> None:
        self.paths: set[str] = set()
        self.event = threading.Event()

    def __call__(self, paths: set[str]) -> None:
        self.paths |= paths
        self.event.set()

    def wait_for(self, path: Path, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if normalize_path(path) in self.paths:
                return True
            self.event.wait(0.2)
            self.event.clear()
        return False


def test_folder_added_while_running_is_watched(tmp_path: Path) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    collector = Collector()
    watcher = FileWatcher(collector, quiet_seconds=0.3)
    watcher.start([])
    try:
        assert watcher.watched == set()
        watcher.sync([str(folder)])
        target = folder / "notes.txt"
        target.write_text("changed", encoding="utf-8")
        assert collector.wait_for(target)
    finally:
        watcher.stop()


def test_single_file_is_watched_but_not_its_neighbours(tmp_path: Path) -> None:
    protected = tmp_path / "contract.txt"
    neighbour = tmp_path / "scratch.txt"
    protected.write_text("v1", encoding="utf-8")
    collector = Collector()
    watcher = FileWatcher(collector, quiet_seconds=0.3)
    watcher.start([str(protected)])
    try:
        assert watcher.watched == {(str(tmp_path), False)}
        neighbour.write_text("noise", encoding="utf-8")
        protected.write_text("v2", encoding="utf-8")
        assert collector.wait_for(protected)
        assert normalize_path(neighbour) not in collector.paths
    finally:
        watcher.stop()


def test_removed_paths_stop_being_watched(tmp_path: Path) -> None:
    folder = tmp_path / "site"
    folder.mkdir()
    watcher = FileWatcher(lambda paths: None, quiet_seconds=0.3)
    watcher.start([str(folder)])
    try:
        assert watcher.watched == {(str(folder), True)}
        watcher.sync([])
        assert watcher.watched == set()
    finally:
        watcher.stop()


def test_internal_folders_are_ignored(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    collector = Collector()
    watcher = FileWatcher(collector, ignored_roots=[str(vault)], quiet_seconds=0.3)
    watcher.start([str(tmp_path)])
    try:
        (vault / "blob.bin").write_bytes(b"x")
        visible = tmp_path / "page.html"
        visible.write_text("<h1>hi</h1>", encoding="utf-8")
        assert collector.wait_for(visible)
        assert normalize_path(vault / "blob.bin") not in collector.paths
    finally:
        watcher.stop()
