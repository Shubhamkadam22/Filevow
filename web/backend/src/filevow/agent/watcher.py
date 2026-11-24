"""Real-time detection: file-system events, debounced into small verification runs."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import ObservedWatch

from filevow.core.paths import is_within, normalize_path

log = logging.getLogger(__name__)


class Debouncer:
    """Collects paths and hands them over once no new event arrived for ``quiet_seconds``.

    Saving a file in most editors produces several events (temp file, write, rename);
    debouncing turns them into one check.
    """

    def __init__(self, callback: Callable[[set[str]], None], quiet_seconds: float = 2.0) -> None:
        self._callback = callback
        self._quiet = quiet_seconds
        self._pending: dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="filevow-debouncer", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def touch(self, path: str) -> None:
        with self._lock:
            self._pending[path] = time.monotonic()

    def flush_ready(self, now: float | None = None) -> set[str]:
        now = time.monotonic() if now is None else now
        with self._lock:
            ready = {p for p, seen in self._pending.items() if now - seen >= self._quiet}
            for path in ready:
                del self._pending[path]
        return ready

    def _loop(self) -> None:
        while not self._stop.wait(0.5):
            ready = self.flush_ready()
            if ready:
                try:
                    self._callback(ready)
                except Exception:  # keep watching even if one check fails
                    log.exception("real-time verification failed")


class _Handler(FileSystemEventHandler):
    """Forwards events for protected locations to the debouncer, ignoring everything else."""

    def __init__(self, debouncer: Debouncer, ignored_roots: Iterable[str]) -> None:
        self._debouncer = debouncer
        self._ignored = [normalize_path(r) for r in ignored_roots]
        self._folders: list[str] = []
        self._files: set[str] = set()

    def set_targets(self, folders: Iterable[str], files: Iterable[str]) -> None:
        self._folders = [normalize_path(f) for f in folders]
        self._files = {normalize_path(f) for f in files}

    def wanted(self, path: str) -> bool:
        if any(is_within(path, root) for root in self._ignored):
            return False
        return path in self._files or any(is_within(path, folder) for folder in self._folders)

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        for raw in (event.src_path, getattr(event, "dest_path", "")):
            if not raw:
                continue
            path = normalize_path(raw if isinstance(raw, str) else raw.decode())
            if self.wanted(path):
                self._debouncer.touch(path)


class FileWatcher:
    """Watches protected folders (recursively) and single protected files.

    ``sync`` can be called at any time with the current list of protected paths: new
    ones start being watched and removed or paused ones stop, without a restart.
    """

    def __init__(
        self,
        on_changes: Callable[[set[str]], None],
        *,
        ignored_roots: Iterable[str] = (),
        quiet_seconds: float = 2.0,
    ) -> None:
        self._debouncer = Debouncer(on_changes, quiet_seconds)
        self._handler = _Handler(self._debouncer, ignored_roots)
        self._observer = Observer()
        self._watches: dict[tuple[str, bool], ObservedWatch] = {}
        self._lock = threading.Lock()

    def start(self, roots: Iterable[str] = ()) -> None:
        self._debouncer.start()
        self._observer.start()
        self.sync(roots)

    def sync(self, roots: Iterable[str]) -> None:
        folders = [r for r in roots if os.path.isdir(r)]
        files = [r for r in roots if os.path.isfile(r)]
        # A single file is watched through its folder, without subfolders.
        wanted = {(folder, True) for folder in folders} | {(os.path.dirname(f), False) for f in files}
        with self._lock:
            self._handler.set_targets(folders, files)
            for key in set(self._watches) - wanted:
                self._observer.unschedule(self._watches.pop(key))
            for directory, recursive in wanted - set(self._watches):
                try:
                    self._watches[(directory, recursive)] = self._observer.schedule(
                        self._handler, directory, recursive=recursive
                    )
                except OSError as exc:  # removed or unreadable since it was protected
                    log.warning("cannot watch %s: %s", directory, exc)
            count = len(self._watches)
        log.debug("watching %d location(s) in real time", count)

    @property
    def watched(self) -> set[tuple[str, bool]]:
        return set(self._watches)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        self._debouncer.stop()
