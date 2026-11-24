"""The background agent: scheduled verification, real-time watching, heartbeat, escalation."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from filevow.agent.watcher import FileWatcher
from filevow.db.enums import RunType
from filevow.db.models import MonitoredPath
from filevow.services import cloud
from filevow.services.context import AppContext
from filevow.services.monitor import MonitoringService

log = logging.getLogger(__name__)

WATCH_REFRESH_SECONDS = 10


class AgentRuntime:
    def __init__(self, ctx: AppContext, *, realtime: bool = True) -> None:
        self._ctx = ctx
        self._monitor = MonitoringService(ctx)
        self._realtime = realtime
        self._scheduler = BackgroundScheduler(timezone=UTC)
        self._watcher: FileWatcher | None = None
        self._run_lock = threading.Lock()  # scheduled and real-time runs never overlap

    @property
    def monitor(self) -> MonitoringService:
        return self._monitor

    def start(self) -> None:
        settings = self._ctx.settings
        self._monitor.check_monitoring_gap()
        self._monitor.heartbeat()

        self._scheduler.add_job(
            self._scheduled_run,
            "interval",
            minutes=settings.verification_interval_minutes,
            id="verify",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=300,
            next_run_time=datetime.now(UTC),  # run immediately at start-up
        )
        self._scheduler.add_job(
            self._monitor.heartbeat, "interval", seconds=60, id="heartbeat", max_instances=1
        )
        self._scheduler.add_job(
            self._monitor.escalate, "interval", seconds=60, id="escalate", max_instances=1
        )
        self._scheduler.add_job(
            self._monitor.retry_notifications, "interval", seconds=60, id="retry", max_instances=1
        )
        if self._ctx.settings.cloud_enabled:
            # Once-a-day "in use" count for cloud accounts (see services/cloud.py).
            self._scheduler.add_job(
                self.report_activity,
                "interval",
                hours=1,
                id="usage",
                max_instances=1,
                next_run_time=datetime.now(UTC) + timedelta(minutes=2),
            )
        self._scheduler.start()

        if self._realtime:
            self._start_watcher()
        log.info("FileVow agent %s started", self._monitor.agent_id)

    def stop(self) -> None:
        if self._watcher:
            self._watcher.stop()
        self._scheduler.shutdown(wait=False)

    def run_now(self, run_type: RunType = RunType.MANUAL, workspace: int | None = None) -> None:
        with self._run_lock:
            self._monitor.verify(run_type, workspace=workspace)

    def _scheduled_run(self) -> None:
        with self._run_lock:
            self._monitor.verify(RunType.SCHEDULED)

    def _realtime_run(self, paths: set[str]) -> None:
        with self._run_lock:
            result = self._monitor.verify(RunType.REALTIME, only_paths=paths)
        if result.summary.issues:
            log.info("real-time check found %d issue(s)", result.summary.issue_count)

    def report_activity(self) -> None:
        client = self._ctx.cloud()
        if client is None:
            return
        with self._ctx.session() as session:
            reported = cloud.report_daily_activity(session, client, self._ctx.vault_key())
        if reported:
            log.info("reported today's use for %d account(s)", reported)

    def _protected_roots(self) -> list[str]:
        with self._ctx.session() as session:
            return list(session.scalars(select(MonitoredPath.path).where(MonitoredPath.enabled.is_(True))))

    def _start_watcher(self) -> None:
        settings = self._ctx.settings
        self._watcher = FileWatcher(
            self._realtime_run,
            ignored_roots=[str(d) for d in settings.internal_dirs],
        )
        self._watcher.start(self._protected_roots())
        log.info("watching %d location(s) in real time", len(self._watcher.watched))
        # Folders added, paused or removed in the dashboard are picked up within seconds.
        self._scheduler.add_job(
            self.refresh_watcher,
            "interval",
            seconds=WATCH_REFRESH_SECONDS,
            id="watch-refresh",
            max_instances=1,
        )

    def refresh_watcher(self) -> None:
        if self._watcher is not None:
            self._watcher.sync(self._protected_roots())
