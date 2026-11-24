from __future__ import annotations

import shutil
from datetime import timedelta
from typing import Any, ClassVar

import pytest
from sqlalchemy import select, text

from filevow.agent.watcher import Debouncer
from filevow.core.paths import normalize_path
from filevow.db.base import utcnow
from filevow.db.enums import AlertStatus, ChannelType, RunStatus, RunType, Severity
from filevow.db.models import (
    AgentHeartbeat,
    Alert,
    AuditCheckpoint,
    AuditEntry,
    NotificationChannel,
    NotificationLog,
    VerificationRun,
)
from filevow.secrets import AUDIT_CHAIN_HEAD, VAULT_KEY
from filevow.services import audit
from filevow.services.monitor import MonitoringService
from filevow.services.notifications import Notification, NotificationDispatcher, encrypt_config
from tests.conftest import Protected


class RecordingChannel:
    sent: ClassVar[list[tuple[str, Notification]]] = []
    fail: ClassVar[bool] = False

    def __init__(self, name: str) -> None:
        self.name = name

    def send(self, notification: Notification) -> None:
        if RecordingChannel.fail:
            raise ConnectionError("mail server down")
        RecordingChannel.sent.append((self.name, notification))


@pytest.fixture(autouse=True)
def _reset_channel() -> None:
    RecordingChannel.sent = []
    RecordingChannel.fail = False


def _recording_dispatcher(session: Any, vault_key: bytes) -> NotificationDispatcher:
    return NotificationDispatcher(
        session, vault_key, channel_factory=lambda row, _key: RecordingChannel(row.name)
    )


def _monitor(protected: Protected) -> MonitoringService:
    return MonitoringService(protected.ctx, dispatcher_factory=_recording_dispatcher, agent_id="test-agent")


def _add_channel(protected: Protected, name: str, min_severity: Severity, escalation: bool = False) -> None:
    vault_key = bytes.fromhex(protected.ctx.secrets.get(VAULT_KEY))
    with protected.ctx.session() as session:
        session.add(
            NotificationChannel(
                name=name,
                type=ChannelType.WEBHOOK,
                config_enc=encrypt_config(vault_key, {"url": "https://example.invalid/hook"}),
                min_severity=min_severity,
                is_escalation_contact=escalation,
            )
        )


def _system_alert_types(protected: Protected) -> set[str]:
    with protected.ctx.session() as session:
        return {a.alert_type for a in session.scalars(select(Alert).where(Alert.change_event_id.is_(None)))}


def test_a_change_raises_exactly_one_alert(protected: Protected) -> None:
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    monitor = _monitor(protected)
    first = monitor.verify(RunType.MANUAL)
    second = monitor.verify(RunType.MANUAL)
    assert len(first.alert_ids) == 1 and second.alert_ids == []
    with protected.ctx.session() as session:
        alert = session.scalars(select(Alert)).one()
        assert alert.title == "File modified: index.html" and alert.severity is Severity.HIGH
        assert "changed" not in alert.message  # alerts never carry file contents


def test_every_run_signs_a_checkpoint_and_remembers_the_head(protected: Protected) -> None:
    _monitor(protected).verify(RunType.MANUAL)
    with protected.ctx.session() as session:
        checkpoint = session.scalars(select(AuditCheckpoint)).one()
        assert audit.verify_checkpoints(session) == []
    assert (
        protected.ctx.secrets.get(AUDIT_CHAIN_HEAD) == f"{checkpoint.last_entry_id}:{checkpoint.entry_hash}"
    )


def test_forged_checkpoint_is_reported(protected: Protected) -> None:
    _monitor(protected).verify(RunType.MANUAL)
    with protected.ctx.session() as session:
        session.scalars(select(AuditCheckpoint)).one().entry_hash = "f" * 64
    _monitor(protected).verify(RunType.MANUAL)
    assert "AUDIT_CHECKPOINT_INVALID" in _system_alert_types(protected)


def test_edited_audit_entry_raises_a_critical_alert(protected: Protected) -> None:
    _monitor(protected).verify(RunType.MANUAL)
    with protected.ctx.session() as session:
        session.scalars(select(AuditEntry).order_by(AuditEntry.id)).first().details = {"forged": True}
    _monitor(protected).verify(RunType.MANUAL)
    assert "AUDIT_CHAIN_BROKEN" in _system_alert_types(protected)


def test_restoring_an_old_database_copy_is_detected(protected: Protected) -> None:
    ctx = protected.ctx
    db_file = ctx.settings.data_dir / "filevow.db"
    _monitor(protected).verify(RunType.MANUAL)

    with ctx.engine.connect() as connection:
        connection.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))
    ctx.engine.dispose()
    backup = db_file.with_suffix(".old")
    shutil.copy(db_file, backup)

    _monitor(protected).verify(RunType.MANUAL)  # the chain moves on; the new head is remembered

    ctx.engine.dispose()
    for leftover in (db_file.with_name("filevow.db-wal"), db_file.with_name("filevow.db-shm")):
        leftover.unlink(missing_ok=True)
    shutil.copy(backup, db_file)  # attacker puts back yesterday's database

    result = _monitor(protected).verify(RunType.MANUAL)
    assert any("restored from an older copy" in p for p in result.system_problems)
    assert "DATABASE_ROLLBACK_DETECTED" in _system_alert_types(protected)


def test_monitoring_gap_is_reported_once(protected: Protected) -> None:
    with protected.ctx.session() as session:
        session.add(
            VerificationRun(
                run_type=RunType.SCHEDULED,
                status=RunStatus.COMPLETED,
                started_at=utcnow() - timedelta(hours=2),
                finished_at=utcnow() - timedelta(hours=2),
            )
        )
    monitor = _monitor(protected)
    alert = monitor.check_monitoring_gap()
    assert alert is not None and "120 minutes" in alert.message
    assert monitor.check_monitoring_gap() is None  # cooldown: no duplicate alert


def test_heartbeat_detects_changed_program_files(protected: Protected) -> None:
    monitor = _monitor(protected)
    monitor.heartbeat()
    with protected.ctx.session() as session:
        session.get(AgentHeartbeat, "test-agent").code_sha256 = "0" * 64
    monitor.heartbeat()
    assert "AGENT_CODE_CHANGED" in _system_alert_types(protected)


def test_notifications_respect_channel_severity(protected: Protected) -> None:
    _add_channel(protected, "security-team", Severity.HIGH)
    _add_channel(protected, "critical-only", Severity.CRITICAL)
    (protected.site / "index.html").write_text("changed", encoding="utf-8")  # HIGH
    _monitor(protected).verify(RunType.MANUAL)
    assert [name for name, _ in RecordingChannel.sent] == ["security-team"]
    assert RecordingChannel.sent[0][1].subject == "[HIGH] File modified: index.html"


def test_many_alerts_are_grouped_into_one_message(protected: Protected) -> None:
    _add_channel(protected, "ops", Severity.LOW)
    for number in range(25):
        (protected.site / f"dropped-{number}.php").write_text("<?php echo 1; ?>", encoding="utf-8")
    _monitor(protected).verify(RunType.MANUAL)
    assert len(RecordingChannel.sent) == 1
    assert RecordingChannel.sent[0][1].subject.endswith("25 integrity alerts")


def test_failed_delivery_is_logged_and_retried(protected: Protected) -> None:
    _add_channel(protected, "ops", Severity.LOW)
    RecordingChannel.fail = True
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    monitor = _monitor(protected)
    monitor.verify(RunType.MANUAL)
    with protected.ctx.session() as session:
        log_entry = session.scalars(select(NotificationLog)).one()
        assert log_entry.status == "failed" and "mail server down" in (log_entry.error or "")
        log_entry.sent_at = utcnow() - timedelta(minutes=2)  # backoff elapsed

    RecordingChannel.fail = False
    assert monitor.retry_notifications() == 1
    with protected.ctx.session() as session:
        attempts = [
            (e.attempt, e.status)
            for e in session.scalars(select(NotificationLog).order_by(NotificationLog.id))
        ]
    assert attempts == [(1, "failed"), (2, "sent")]


def test_unacknowledged_alerts_escalate(protected: Protected) -> None:
    _add_channel(protected, "manager", Severity.HIGH, escalation=True)
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    monitor = _monitor(protected)
    monitor.verify(RunType.MANUAL)
    with protected.ctx.session() as session:
        session.scalars(select(Alert)).one().next_escalation_at = utcnow() - timedelta(seconds=1)
    RecordingChannel.sent = []
    assert monitor.escalate() == 1
    with protected.ctx.session() as session:
        alert = session.scalars(select(Alert)).one()
        assert alert.escalation_level == 1 and alert.status is AlertStatus.NEW
    assert [name for name, _ in RecordingChannel.sent] == ["manager"]


def test_real_time_run_checks_only_the_reported_paths(protected: Protected) -> None:
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    (protected.site / "about.html").write_text("also changed", encoding="utf-8")
    (protected.site / "new.js").write_text("x", encoding="utf-8")
    only = {normalize_path(protected.site / "index.html"), normalize_path(protected.site / "new.js")}
    result = _monitor(protected).verify(RunType.REALTIME, only_paths=only)
    assert sorted(i.outcome.value for i in result.summary.issues) == ["FILE_MODIFIED", "UNKNOWN_FILE_CREATED"]
    assert result.summary.files_checked == 2


def test_debouncer_waits_for_quiet() -> None:
    debouncer = Debouncer(callback=lambda paths: None, quiet_seconds=2.0)
    debouncer.touch("c:/site/a.html")
    assert debouncer.flush_ready() == set()
    import time

    later = time.monotonic() + 2.5
    assert debouncer.flush_ready(now=later) == {"c:/site/a.html"}
    assert debouncer.flush_ready(now=later) == set()
