"""Enumerate the files under a monitored path."""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from fnmatch import fnmatch
from pathlib import Path


def matches_any(relative_path: str, patterns: Sequence[str]) -> bool:
    """A pattern matches either the file name (``*.log``) or the relative path (``cache/*``)."""
    name = relative_path.rsplit("/", 1)[-1]
    return any(fnmatch(name, p) or fnmatch(relative_path, p) for p in patterns)


def iter_files(
    root: str | os.PathLike[str],
    *,
    recursive: bool = True,
    include: Sequence[str] = (),
    exclude: Sequence[str] = (),
    follow_symlinks: bool = False,
) -> Iterator[Path]:
    """Yield every regular file under ``root`` that passes the include/exclude filters.

    Links and junctions are skipped unless ``follow_symlinks`` is set, so a monitored
    folder can never be used to make FileVow read files outside it.
    """
    root_path = Path(root)
    if root_path.is_file():
        yield root_path
        return

    stack = [root_path]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except (PermissionError, FileNotFoundError):
            continue
        for entry in entries:
            if not follow_symlinks and (entry.is_symlink() or _is_junction(entry)):
                continue
            relative = Path(entry.path).relative_to(root_path).as_posix()
            if entry.is_dir(follow_symlinks=follow_symlinks):
                if recursive and not matches_any(relative, exclude):
                    stack.append(Path(entry.path))
                continue
            if exclude and matches_any(relative, exclude):
                continue
            if include and not matches_any(relative, include):
                continue
            yield Path(entry.path)


def _is_junction(entry: os.DirEntry[str]) -> bool:
    is_junction = getattr(entry, "is_junction", None)  # Python 3.12+
    return bool(is_junction and is_junction())
