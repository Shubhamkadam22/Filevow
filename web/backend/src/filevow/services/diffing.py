"""Line diffs between the approved copy and the current (evidence) copy of a text file."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Literal

MAX_DIFF_BYTES = 512 * 1024

Kind = Literal["same", "add", "del", "mod"]


@dataclass(frozen=True)
class DiffLine:
    kind: Kind
    old_number: int | None
    new_number: int | None
    old_text: str | None
    new_text: str | None


@dataclass(frozen=True)
class TextDiff:
    lines: list[DiffLine]
    added: int
    removed: int


def as_text(data: bytes | None) -> list[str] | None:
    """Split into lines, or ``None`` for binary or oversized content."""
    if data is None:
        return []
    if len(data) > MAX_DIFF_BYTES or b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        try:
            return data.decode("cp1252").splitlines()
        except UnicodeDecodeError:
            return None


def text_diff(old: bytes | None, new: bytes | None) -> TextDiff | None:
    old_lines, new_lines = as_text(old), as_text(new)
    if old_lines is None or new_lines is None:
        return None
    lines: list[DiffLine] = []
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            lines += [
                DiffLine("same", a0 + i + 1, b0 + i + 1, old_lines[a0 + i], new_lines[b0 + i])
                for i in range(a1 - a0)
            ]
            continue
        paired = min(a1 - a0, b1 - b0) if tag == "replace" else 0
        for i in range(paired):
            lines.append(DiffLine("mod", a0 + i + 1, b0 + i + 1, old_lines[a0 + i], new_lines[b0 + i]))
        for i in range(a0 + paired, a1):
            lines.append(DiffLine("del", i + 1, None, old_lines[i], None))
        for i in range(b0 + paired, b1):
            lines.append(DiffLine("add", None, i + 1, None, new_lines[i]))
    added = sum(1 for line in lines if line.kind in ("add", "mod"))
    removed = sum(1 for line in lines if line.kind in ("del", "mod"))
    return TextDiff(lines, added, removed)
