"""Alerts, verification runs and the audit log."""

from __future__ import annotations

import csv
import io
import threading

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import ColumnElement, Select, or_, select
from sqlalchemy.orm import Session

from filevow.api.deps import get_ctx, get_session, require
from filevow.api.presenters import run_out, username
from filevow.api.schemas import AlertOut, AuditOut, ChainOut, RunDetailOut, RunIssueOut, RunOut
from filevow.crypto import keys, signing
from filevow.db.enums import AlertStatus, KeyPurpose, Outcome, Role, RunType
from filevow.db.models import Alert, AuditEntry, SigningKey, User, VerificationResult, VerificationRun
from filevow.services import alerts, audit
from filevow.services.context import AppContext
from filevow.services.monitor import MonitoringService

router = APIRouter(tags=["activity"])
viewer = require(Role.VIEWER)
analyst = require(Role.ANALYST)

AUDIT_GROUPS = {
    "change": ("CHANGE_", "FILE_QUARANTINED", "BASELINE_CREATED"),
    "auth": (
        "LOGIN_",
        "ACCOUNT_LOCKED",
        "MFA_",
        "PASSWORD_",
        "SESSIONS_",
        "REFRESH_TOKEN_",
        "USER_REGISTERED",
    ),
    "admin": ("PATH_", "USER_", "KEY_", "CHANNEL_"),
    "system": ("VERIFICATION_RUN",),
}


# --------------------------------------------------------------------------- alerts


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    state: str = Query(default="open", pattern="^(open|all)$"),
    limit: int = Query(default=100, le=500),
    user: User = Depends(viewer),
    session: Session = Depends(get_session),
) -> list[Alert]:
    query = select(Alert).where(_visible_alerts(user)).order_by(Alert.id.desc()).limit(limit)
    if state == "open":
        query = query.where(Alert.status != AlertStatus.RESOLVED)
    return list(session.scalars(query))


@router.post("/alerts/{alert_id}/ack", response_model=AlertOut)
def acknowledge_alert(
    alert_id: int, user: User = Depends(analyst), session: Session = Depends(get_session)
) -> Alert:
    alert = session.get(Alert, alert_id)
    if alert is None or not (
        alert.owner_id == user.id or (alert.owner_id is None and user.role is Role.ADMIN)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alerts.acknowledge(session, alert_id, user.id)


def _visible_alerts(user: User) -> ColumnElement[bool]:
    if user.role is Role.ADMIN:
        return or_(Alert.owner_id == user.id, Alert.owner_id.is_(None))
    return Alert.owner_id == user.id


# --------------------------------------------------------------------------- runs

_manual_run_lock = threading.Lock()


def _run_in_background(app_state: object, ctx: AppContext, owner_id: int) -> None:
    agent = getattr(app_state, "agent", None)
    if agent is not None:
        agent.run_now(RunType.MANUAL, workspace=owner_id)
        return
    if _manual_run_lock.acquire(blocking=False):
        try:
            MonitoringService(ctx).verify(RunType.MANUAL, workspace=owner_id)
        finally:
            _manual_run_lock.release()


@router.get("/runs", response_model=list[RunOut])
def list_runs(
    limit: int = Query(default=50, le=500),
    user: User = Depends(viewer),
    session: Session = Depends(get_session),
) -> list[RunOut]:
    query = select(VerificationRun).where(VerificationRun.owner_id == user.id)
    return [run_out(r) for r in session.scalars(query.order_by(VerificationRun.id.desc()).limit(limit))]


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
def start_run(
    request: Request,
    tasks: BackgroundTasks,
    user: User = Depends(analyst),
    ctx: AppContext = Depends(get_ctx),
) -> dict[str, str]:
    tasks.add_task(_run_in_background, request.app.state, ctx, user.id)
    return {"status": "started"}


@router.get("/runs/{run_id}", response_model=RunDetailOut)
def get_run(
    run_id: int, user: User = Depends(viewer), session: Session = Depends(get_session)
) -> RunDetailOut:
    run = session.get(VerificationRun, run_id)
    if run is None or run.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
    issues = session.scalars(
        select(VerificationResult).where(
            VerificationResult.run_id == run.id, VerificationResult.outcome != Outcome.OK
        )
    )
    return RunDetailOut(
        **run_out(run).model_dump(),
        issues=[RunIssueOut(file_path=r.file_path, outcome=r.outcome) for r in issues],
        signature_valid=_report_signature_valid(session, run),
        results_sha256=run.results_sha256,
    )


def _report_signature_valid(session: Session, run: VerificationRun) -> bool | None:
    if run.agent_signature is None or run.report_json is None:
        return None
    for row in session.scalars(select(SigningKey).where(SigningKey.purpose == KeyPurpose.AGENT)):
        if signing.verify_payload(
            keys.load_public_key(row.public_key_pem), run.report_json, run.agent_signature
        ):
            return True
    return False


# --------------------------------------------------------------------------- audit


def _audit_query(group: str | None, user: User) -> Select[AuditEntry]:
    query = select(AuditEntry).where(AuditEntry.owner_id == user.id).order_by(AuditEntry.id.desc())
    if group in AUDIT_GROUPS:
        prefixes = AUDIT_GROUPS[group]
        query = query.where(or_(*[AuditEntry.action.startswith(p) for p in prefixes]))
    return query


def _audit_out(session: Session, entry: AuditEntry) -> AuditOut:
    return AuditOut(
        id=entry.id,
        created_at=entry.created_at,
        action=entry.action,
        actor=username(session, entry.actor_user_id) or "System",
        target_type=entry.target_type,
        target_id=entry.target_id,
        details=entry.details,
        ip_address=entry.ip_address,
        entry_hash=entry.entry_hash,
    )


@router.get("/audit", response_model=list[AuditOut])
def list_audit(
    group: str | None = Query(default=None, pattern="^(change|auth|admin|system)$"),
    limit: int = Query(default=100, le=1000),
    user: User = Depends(viewer),
    session: Session = Depends(get_session),
) -> list[AuditOut]:
    return [_audit_out(session, e) for e in session.scalars(_audit_query(group, user).limit(limit))]


@router.get("/audit/verify", response_model=ChainOut)
def verify_audit(_: User = Depends(viewer), session: Session = Depends(get_session)) -> ChainOut:
    report = audit.verify_chain(session)
    return ChainOut(
        intact=report.intact,
        entries_checked=report.entries_checked,
        first_broken_id=report.first_broken_id,
        reason=report.reason,
        checkpoint_problems=audit.verify_checkpoints(session),
    )


@router.get("/audit/export.csv")
def export_audit(user: User = Depends(viewer), session: Session = Depends(get_session)) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["id", "time_utc", "action", "actor", "target_type", "target_id", "details", "ip", "entry_hash"]
    )
    for entry in session.scalars(
        select(AuditEntry).where(AuditEntry.owner_id == user.id).order_by(AuditEntry.id)
    ):
        writer.writerow(
            [
                entry.id,
                entry.created_at.isoformat(),
                entry.action,
                username(session, entry.actor_user_id) or "System",
                entry.target_type or "",
                entry.target_id or "",
                entry.details or "",
                entry.ip_address or "",
                entry.entry_hash,
            ]
        )
    audit.record_event(session, "AUDIT_EXPORTED", actor_user_id=user.id, owner_id=user.id)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="filevow-audit-log.csv"'},
    )
