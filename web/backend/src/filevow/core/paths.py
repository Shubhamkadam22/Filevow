"""Path normalisation.

Every path stored in the database or inside a signed record goes through
``normalize_path`` so the same file always produces the same bytes, whatever
spelling the user typed (``C:\\Site\\Index.html`` vs ``c:/site/index.html``).
"""

from __future__ import annotations

import os
from pathlib import Path


def normalize_path(path: str | os.PathLike[str]) -> str:
    """Absolute, case-folded on Windows, forward slashes. Never follows symlinks."""
    absolute = os.path.abspath(os.fspath(path))
    return os.path.normcase(absolute).replace("\\", "/")


def is_within(child: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    """True when ``child`` is ``root`` itself or lies underneath it (no ``..`` escapes)."""
    child_norm = normalize_path(child)
    root_norm = normalize_path(root).rstrip("/")
    return child_norm == root_norm or child_norm.startswith(root_norm + "/")


def to_native(normalized: str) -> Path:
    """Turn a normalised path back into a path the OS accepts."""
    return Path(normalized)
