"""Workspace isolation: every user only ever sees and touches their own data.

Rows that belong to someone else are reported as "not found" rather than "forbidden",
so the API never confirms that another workspace's file or change exists.
"""

from __future__ import annotations

from typing import Any, TypeVar

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement
from sqlalchemy.orm import InstrumentedAttribute, Session

from filevow.db.models import ChangeEvent, FileBaseline, MonitoredPath, NotificationChannel, User

T = TypeVar("T", ChangeEvent, MonitoredPath, NotificationChannel)


def mine(column: InstrumentedAttribute[Any], user: User) -> ColumnElement[bool]:
    """SQL filter: rows owned by this user."""
    return column == user.id


def owned(session: Session, model: type[T], row_id: int, user: User, label: str) -> T:
    row = session.get(model, row_id)
    if row is None or row.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{label} not found")
    return row


def owned_baseline(session: Session, baseline_id: int, user: User) -> FileBaseline:
    baseline = session.get(FileBaseline, baseline_id)
    if baseline is None or baseline.monitored_path.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return baseline
