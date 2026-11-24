"""High-level monitoring: one call per verification run, heartbeat and gap checks.

Used by the background agent, the CLI and the API so they all behave identically.
"""

from __future__ import annotations

import hashlib
import logging
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

import filevow
from filevow.crypto import keys
from filevow.db.base import utcnow
from filevow.db.enums import RunStatus, RunType, Severity
from filevow.db.models import AgentHeartbeat, Alert, ChangeEvent, MonitoredPath, SigningKey, VerificationRun
from filevow.secrets import VAULT_KEY
from filevow.services import alerts, audit, trust
from filevow.services.context import AppContext
from filevow.services.notifications import NotificationDispatcher
from filevow.services.verification import RunSummary, Verifier

log = logging.getLogger(__name__)


@dataclass
class MonitorResult:
    summaries: list[RunSummary]
    alert_ids: list[int] = field(default_factory=list)
    system_problems: list[str] = field(default_factory=list)

    @property
    def summary(self) -> RunSummary:
        """All workspaces of this cycle combined (one signed run is stored per workspace)."""
        if len(self.summaries) == 1:
            return self.summaries[0]
        return RunSummary(
            run_id=max((s.run_id for s in self.summaries), default=0),
            files_checked=sum(s.files_checked for s in self.summaries),
            ok_count=sum(s.ok_count for s in self.summaries),
            issues=[issue for s in self.summaries for issue in s.issues],
            duration_ms=sum(s.duration_ms for s in self.summaries),
            signed=all(s.signed for s in self.summaries),
            new_change_ids=[cid for s in self.summaries for cid in s.new_change_ids],
        )


def agent_code_fingerprint() -> str:
    """SHA-256 over FileVow's own source files, reported with every heartbeat."""
    package_root = Path(filevow.__file__).parent
    digest = hashlib.sha256()
    for source in sorted(package_root.rglob("*.py")):
        digest.update(source.relative_to(package_root).as_posix().encode())
        digest.update(source.read_bytes())
    return digest.hexdigest()


class MonitoringService:
    def __init__(
        self,
        ctx: AppContext,
        dispatcher_factory: Callable[..., NotificationDispatcher] = NotificationDispatcher,
        agent_id: str | None = None,
    ) -> None:
        self._ctx = ctx
        self._dispatcher_factory = dispatcher_factory
        self.agent_id = agent_id or socket.gethostname()

    # ------------------------------------------------------------------ verification

    def verify(
        self,
        run_type: RunType = RunType.SCHEDULED,
        *,
        only_paths: set[str] | None = None,
        deep: bool = False,
        workspace: int | Literal["all"] | None = "all",
    ) -> MonitorResult:
        """Verify every workspace (default) or just one; each gets its own signed run."""
        ctx = self._ctx
        agent_key = ctx.agent_private_key()
        with ctx.session() as session:
            problems = self._self_checks(session)
            raised = [
                alerts.system_alert(session, kind, Severity.CRITICAL, title, detail)
                for kind, title, detail in problems
            ]
            trusted = trust.load_trusted_baseline_keys(session, ctx.secrets)
            owners = self._workspaces(session) if workspace == "all" else [workspace]

            summaries: list[RunSummary] = []
            for owner_id in owners:
                verifier = Verifier(
                    session,
                    ctx.settings,
                    ctx.vault(),
                    trusted,
                    agent_key,
                    deep_mirror_check=deep,
                    owner_id=owner_id,
                )
                summary = verifier.run(run_type, only_paths)
                summaries.append(summary)
                for change_id in summary.new_change_ids:
                    event = session.get(ChangeEvent, change_id)
                    if event is not None:
                        raised.append(alerts.alert_for_change(session, event))

            agent_row = self._agent_key_row(session, agent_key)
            checkpoint = audit.create_checkpoint(session, agent_key, agent_row, summaries[-1].run_id)
            alert_ids = [a.id for a in raised if a is not None]

        if checkpoint is not None:
            audit.remember_chain_head(ctx.secrets, checkpoint)  # only after the commit succeeded
        self._notify(alert_ids)
        return MonitorResult(summaries, alert_ids, [detail for _, _, detail in problems])

    @staticmethod
    def _workspaces(session: Session) -> list[int | None]:
        owners = sorted(
            set(session.scalars(select(MonitoredPath.owner_id).where(MonitoredPath.enabled.is_(True)))),
            key=lambda owner: -1 if owner is None else owner,
        )
        return owners or [None]

    def _self_checks(self, session: Session) -> list[tuple[str, str, str]]:
        """Is FileVow's own evidence intact? Database copy, audit chain and checkpoints."""
        problems: list[tuple[str, str, str]] = []
        rollback = audit.detect_database_rollback(session, self._ctx.secrets)
        if rollback:
            problems.append(("DATABASE_ROLLBACK_DETECTED", "Database rollback detected", rollback))
        chain = audit.verify_chain(session)
        if not chain.intact:
            problems.append(
                ("AUDIT_CHAIN_BROKEN", "Audit log tampered", f"entry {chain.first_broken_id}: {chain.reason}")
            )
        for problem in audit.verify_checkpoints(session):
            problems.append(("AUDIT_CHECKPOINT_INVALID", "Audit checkpoint invalid", problem))
        return problems

    @staticmethod
    def _agent_key_row(session: Session, agent_key: keys.PrivateKey) -> SigningKey:
        fingerprint = keys.fingerprint(agent_key.public_key())
        row = session.scalar(select(SigningKey).where(SigningKey.fingerprint == fingerprint))
        if row is None:
            raise RuntimeError("the agent key is not registered; run `filevow init`")
        return row

    # ------------------------------------------------------------------ gaps, heartbeat, escalation

    def check_monitoring_gap(self, now: datetime | None = None) -> Alert | None:
        """Raise an alert when no run completed within the allowed window (agent was stopped)."""
        now = now or utcnow()
        allowed = timedelta(minutes=self._ctx.settings.monitoring_gap_minutes)
        with self._ctx.session() as session:
            last = session.scalar(
                select(VerificationRun.finished_at)
                .where(VerificationRun.status == RunStatus.COMPLETED)
                .order_by(VerificationRun.finished_at.desc())
                .limit(1)
            )
            if last is None or now - last <= allowed:
                return None
            minutes = int((now - last).total_seconds() // 60)
            alert = alerts.system_alert(
                session,
                "MONITORING_GAP",
                Severity.HIGH,
                "Monitoring gap",
                f"No verification ran for {minutes} minutes (last completed run {last:%Y-%m-%d %H:%M} UTC). "
                "Files may have been changed and put back while FileVow was not running.",
            )
            alert_id = alert.id if alert else None
        if alert_id:
            self._notify([alert_id])
        return alert

    def heartbeat(self) -> None:
        code = agent_code_fingerprint()
        changed_alert: int | None = None
        with self._ctx.session() as session:
            row = session.get(AgentHeartbeat, self.agent_id)
            if row is None:
                row = AgentHeartbeat(agent_id=self.agent_id)
                session.add(row)
            elif row.code_sha256 and row.code_sha256 != code:
                alert = alerts.system_alert(
                    session,
                    "AGENT_CODE_CHANGED",
                    Severity.CRITICAL,
                    "FileVow program files changed",
                    f"The agent's code fingerprint changed from {row.code_sha256[:12]}… to {code[:12]}…",
                )
                changed_alert = alert.id if alert else None
            row.last_seen_at = utcnow()
            row.code_sha256 = code
            row.agent_version = filevow.__version__
            row.status = "running"
        if changed_alert:
            self._notify([changed_alert])

    def escalate(self) -> int:
        with self._ctx.session() as session:
            due = alerts.escalate_due(session)
            ids = [a.id for a in due]
        if ids:
            self._notify(ids, escalation=True)
        return len(ids)

    def retry_notifications(self) -> int:
        with self._ctx.session() as session:
            return self._dispatcher(session).retry_failed()

    # ------------------------------------------------------------------ notifications

    def _dispatcher(self, session: Session) -> NotificationDispatcher:
        return self._dispatcher_factory(session, bytes.fromhex(self._ctx.secrets.get(VAULT_KEY)))

    def _notify(self, alert_ids: list[int], *, escalation: bool = False) -> None:
        if not alert_ids:
            return
        try:
            with self._ctx.session() as session:
                rows = session.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all()
                self._dispatcher(session).dispatch(rows, escalation=escalation)
        except Exception:  # a broken mail server must never stop monitoring
            log.exception("sending notifications failed")
