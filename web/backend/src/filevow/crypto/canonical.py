"""Canonical serialisation.

A signature covers exact bytes. Two dictionaries with the same content must always
serialise identically, otherwise a genuine signature would fail to verify.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def format_timestamp(moment: datetime) -> str:
    """ISO 8601, UTC, second precision, ``Z`` suffix: ``2026-11-23T10:15:00Z``."""
    if moment.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
