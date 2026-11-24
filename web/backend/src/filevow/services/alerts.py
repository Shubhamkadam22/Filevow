"""Alerts: one per change event, plus system alerts (monitoring gaps, tampering of FileVow itself)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.db.base import utcnow
from filevow.db.enums import AlertStatus, Severity
from filevow.db.models import Alert, ChangeEvent

ESCALATE_AFTER = {Severity.CRITICAL: timedelta(minutes=15), Severity.HIGH: timedelta(minutes=60)}
SYSTEM_ALERT_COOLDOWN = timedelta(hours=1)

TITLES = {
    "RECORD_TAMPERED": "Integrity record tampered",
    "ROLLBACK_DETECTED": "Rollback to an older version detected",
    "KEY_UNTRUSTED": "Record signed by an untrusted key",
    "FILE_MODIFIED": "File modified",
    "FILE_MODIFIED_NO_CLEAN_COPY": "File modified and no clean copy",
    "FILE_DELETED": "File deleted",
    "MIRROR_CORRUPTED": "Mirror copy damaged",
    "TYPE_CHANGED": "File replaced by a link or folder",
    "PERMISSION_CHANGED": "Permissions changed",
    "OWNER_CHANGED": "Owner changed",
    "UNKNOWN_FILE_CREATED": "Unknown file created",
    "UNREADABLE": "File could not be read",
}


def _next_escalation(severity: Severity, now: datetime) -> datetime | None:
    delay = ESCALATE_AFTER.get(severity)
    return now + delay if delay else None


def _short(sha: str | None) -> str:
    return f"{sha[:8]}…{sha[-4:]}" if sha else "—"


def alert_for_change(session: Session, event: ChangeEvent) -> Alert | None:
    """Create the alert for a new change. Repeat detections never create a second alert."""
    if session.scalar(select(Alert.id).where(Alert.change_event_id == event.id)) is not None:
        return None
    now = utcnow()
    title = f"{TITLES.get(event.event_type, event.event_type)}: {Path(event.file_path).name}"
    message = (
        f"{event.file_path}\n"
        f"Expected SHA-256 {_short(event.expected_sha256)} · observed {_short(event.observed_sha256)}\n"
        f"Size {event.expected_size if event.expected_size is not None else '—'} → "
        f"{event.observed_size if event.observed_size is not None else '—'} bytes"
    )  # never include file contents or secrets in alerts
    alert = Alert(
        change_event_id=event.id,
        owner_id=event.owner_id,
        alert_type=event.event_type,
        severity=event.severity,
        title=title,
        message=message,
        next_escalation_at=_next_escalation(event.severity, now),
    )
    session.add(alert)
    session.flush()
    return alert


def system_alert(
    session: Session, alert_type: str, severity: Severity, title: str, message: str
) -> Alert | None:
    """Raise an alert about FileVow itself, at most once per hour per type while unresolved."""
    now = utcnow()
    recent = session.scalar(
        select(Alert.id).where(
            Alert.alert_type == alert_type,
            Alert.change_event_id.is_(None),
            Alert.status != AlertStatus.RESOLVED,
            Alert.created_at >= now - SYSTEM_ALERT_COOLDOWN,
        )
    )
    if recent is not None:
        return None
    alert = Alert(
        alert_type=alert_type,
        severity=severity,
        title=title,
        message=message,
        next_escalation_at=_next_escalation(severity, now),
    )
    session.add(alert)
    session.flush()
    return alert


def acknowledge(session: Session, alert_id: int, user_id: int | None) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None:
        raise LookupError(f"alert #{alert_id} does not exist")
    if alert.status is AlertStatus.NEW:
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user_id
        alert.acknowledged_at = utcnow()
        alert.next_escalation_at = None
    return alert


def resolve_for_changes(session: Session, change_ids: Iterable[int]) -> None:
    ids = list(change_ids)
    if not ids:
        return
    for alert in session.scalars(select(Alert).where(Alert.change_event_id.in_(ids))):
        alert.status = AlertStatus.RESOLVED
        alert.next_escalation_at = None


def escalate_due(session: Session, now: datetime | None = None) -> list[Alert]:
    """Raise the escalation level of unacknowledged alerts whose deadline passed."""
    now = now or utcnow()
    due = session.scalars(
        select(Alert).where(Alert.status == AlertStatus.NEW, Alert.next_escalation_at <= now)
    ).all()
    for alert in due:
        alert.escalation_level += 1
        alert.next_escalation_at = _next_escalation(alert.severity, now)
    return list(due)
