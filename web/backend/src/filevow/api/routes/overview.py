"""Dashboard summary, monitored folders and protected files, all scoped to the user's workspace."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from filevow.api.deps import StepUp, confirm_step_up, get_ctx, get_session, rate_limit, require
from filevow.api.presenters import file_detail, file_out, open_change_ids, run_out, username
from filevow.api.schemas import (
    ActivityOut,
    BaselineIn,
    BaselineOut,
    DashboardOut,
    FileDetailOut,
    FileOut,
    LayerSummary,
    PathCreateIn,
    PathOut,
    PathUpdateIn,
    RunPoint,
)
from filevow.api.workspace import mine, owned, owned_baseline
from filevow.crypto import keys
from filevow.db.base import utcnow
from filevow.db.enums import OPEN_REVIEW_STATUSES, AlertStatus, BaselineStatus, Outcome, Role
from filevow.db.models import (
    AgentHeartbeat,
    Alert,
    AuditEntry,
    ChangeEvent,
    FileBaseline,
    MonitoredPath,
    SigningKey,
    User,
    VerificationRun,
)
from filevow.services import audit, trust
from filevow.services.baseline import BaselineBuilder, MonitoredPathError, add_monitored_path
from filevow.services.context import AppContext

router = APIRouter(tags=["overview"])
viewer = require(Role.VIEWER)
owner = require(Role.USER)  # full control of one's own workspace

CONTENT_ISSUES = {
    Outcome.FILE_MODIFIED,
    Outcome.FILE_MODIFIED_NO_CLEAN_COPY,
    Outcome.FILE_DELETED,
    Outcome.TYPE_CHANGED,
}
SIGNATURE_ISSUES = {Outcome.RECORD_TAMPERED, Outcome.ROLLBACK_DETECTED, Outcome.KEY_UNTRUSTED}
MIRROR_ISSUES = {Outcome.MIRROR_CORRUPTED, Outcome.FILE_MODIFIED_NO_CLEAN_COPY}


def _my_files(user: User) -> Select[FileBaseline]:
    return (
        select(FileBaseline)
        .join(MonitoredPath)
        .where(mine(MonitoredPath.owner_id, user), FileBaseline.status != BaselineStatus.DELETED)
    )


# --------------------------------------------------------------------------- dashboard


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(
    user: User = Depends(viewer), session: Session = Depends(get_session), ctx: AppContext = Depends(get_ctx)
) -> DashboardOut:
    now = utcnow()
    protected = session.scalar(select(func.count()).select_from(_my_files(user).subquery())) or 0
    open_events = session.scalars(
        select(ChangeEvent).where(
            mine(ChangeEvent.owner_id, user), ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES)
        )
    ).all()
    by_severity: dict[str, int] = {}
    for event in open_events:
        by_severity[str(event.severity)] = by_severity.get(str(event.severity), 0) + 1

    def failing(kinds: set[Outcome]) -> int:
        return len({e.file_path for e in open_events if e.event_type in kinds and e.file_baseline_id})

    my_runs = select(VerificationRun).where(mine(VerificationRun.owner_id, user))
    last_run = session.scalar(my_runs.order_by(VerificationRun.id.desc()).limit(1))
    runs = session.scalars(
        my_runs.where(VerificationRun.started_at >= now - timedelta(hours=24)).order_by(VerificationRun.id)
    ).all()
    heartbeat = session.scalar(select(AgentHeartbeat).order_by(AgentHeartbeat.last_seen_at.desc()).limit(1))
    entries = session.scalars(
        select(AuditEntry).where(mine(AuditEntry.owner_id, user)).order_by(AuditEntry.id.desc()).limit(8)
    ).all()
    key = trust.active_signing_key(session, user.id)
    open_alerts = (
        session.scalar(
            select(func.count(Alert.id)).where(mine(Alert.owner_id, user), Alert.status == AlertStatus.NEW)
        )
        or 0
    )
    interval = timedelta(minutes=ctx.settings.verification_interval_minutes)
    folders = session.scalar(select(func.count(MonitoredPath.id)).where(mine(MonitoredPath.owner_id, user)))

    return DashboardOut(
        protected_files=protected,
        monitored_paths=folders or 0,
        open_changes=len(open_events),
        open_by_severity=by_severity,
        layers=LayerSummary(
            content_ok=protected - failing(CONTENT_ISSUES),
            signatures_ok=protected - failing(SIGNATURE_ISSUES),
            mirror_ok=protected - failing(MIRROR_ISSUES),
            total=protected,
        ),
        last_run=run_out(last_run) if last_run else None,
        next_run_at=(last_run.started_at + interval) if last_run else None,
        agent_last_seen=heartbeat.last_seen_at if heartbeat else None,
        agent_online=bool(heartbeat and now - heartbeat.last_seen_at < timedelta(minutes=5)),
        audit_intact=audit.verify_chain(session).intact,
        key_id=key.key_id if key else None,
        runs_24h=[
            RunPoint(id=r.id, started_at=r.started_at, issue_count=r.issue_count, duration_ms=r.duration_ms)
            for r in runs
        ],
        activity=[
            ActivityOut(
                created_at=e.created_at,
                action=e.action,
                actor=username(session, e.actor_user_id) or "System",
                summary=_activity_summary(e),
            )
            for e in entries
        ],
        open_alerts=open_alerts,
    )


def _activity_summary(entry: AuditEntry) -> str:
    details = entry.details or {}
    for key in ("file", "path", "username"):
        if key in details:
            return Path(str(details[key])).name if key == "file" else str(details[key])
    if entry.action == "VERIFICATION_RUN":
        return f"{details.get('files', 0)} files · {details.get('issues', 0)} issues"
    return entry.ip_address or ""


# --------------------------------------------------------------------------- monitored folders


def _path_out(session: Session, monitored: MonitoredPath) -> PathOut:
    count = (
        session.scalar(
            select(func.count(FileBaseline.id)).where(
                FileBaseline.monitored_path_id == monitored.id, FileBaseline.status != BaselineStatus.DELETED
            )
        )
        or 0
    )
    return PathOut(
        id=monitored.id,
        path=monitored.path,
        is_directory=monitored.is_directory,
        recursive=monitored.recursive,
        include_patterns=monitored.include_patterns,
        exclude_patterns=monitored.exclude_patterns,
        severity=monitored.severity,
        enabled=monitored.enabled,
        mirror_enabled=monitored.mirror_enabled,
        protected_files=count,
        created_at=monitored.created_at,
    )


@router.get("/paths", response_model=list[PathOut])
def list_paths(user: User = Depends(viewer), session: Session = Depends(get_session)) -> list[PathOut]:
    rows = session.scalars(
        select(MonitoredPath).where(mine(MonitoredPath.owner_id, user)).order_by(MonitoredPath.id)
    )
    return [_path_out(session, m) for m in rows]


@router.post(
    "/paths", response_model=PathOut, status_code=201, dependencies=[Depends(rate_limit("step-up", 30))]
)
def create_path(
    body: PathCreateIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> PathOut:
    confirm_step_up(session, ctx, user, body)
    try:
        monitored = add_monitored_path(
            session,
            ctx.settings,
            body.path,
            recursive=body.recursive,
            include=body.include,
            exclude=body.exclude,
            severity=body.severity,
            actor_user_id=user.id,
            owner_id=user.id,
        )
    except MonitoredPathError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _path_out(session, monitored)


@router.patch("/paths/{path_id}", response_model=PathOut, dependencies=[Depends(rate_limit("step-up", 30))])
def update_path(
    path_id: int,
    body: PathUpdateIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> PathOut:
    confirm_step_up(session, ctx, user, body)
    monitored = owned(session, MonitoredPath, path_id, user, "Folder")
    changes = body.model_dump(exclude_unset=True, exclude={"password", "totp_code"})
    if "include" in changes:
        monitored.include_patterns = changes.pop("include")
    if "exclude" in changes:
        monitored.exclude_patterns = changes.pop("exclude")
    for field, value in changes.items():
        setattr(monitored, field, value)
    audit.record_event(
        session,
        "PATH_UPDATED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="monitored_path",
        target_id=monitored.id,
        details={
            "path": monitored.path,
            **{
                k: str(v)
                for k, v in body.model_dump(exclude_unset=True, exclude={"password", "totp_code"}).items()
            },
        },
    )
    return _path_out(session, monitored)


@router.post(
    "/paths/{path_id}/baseline", response_model=BaselineOut, dependencies=[Depends(rate_limit("step-up", 30))]
)
def baseline_path(
    path_id: int,
    body: BaselineIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> BaselineOut:
    confirm_step_up(session, ctx, user, body)
    monitored = owned(session, MonitoredPath, path_id, user, "Folder")
    private_key, signing_key = unlock_signing_key(session, ctx, user, body.key_passphrase)
    builder = BaselineBuilder(session, ctx.settings, ctx.vault(), private_key, signing_key, user.id)
    return BaselineOut(**builder.protect(monitored).__dict__)


def unlock_signing_key(
    session: Session, ctx: AppContext, user: User, passphrase: str
) -> tuple[keys.PrivateKey, SigningKey]:
    """Unlock this user's workspace signing key; it can only sign their own files."""
    try:
        return trust.unlock_user_signing_key(session, ctx.settings, ctx.secrets, user.id, passphrase)
    except trust.SigningKeyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except trust.UntrustedKeyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


# --------------------------------------------------------------------------- files


@router.get("/files", response_model=list[FileOut])
def list_files(
    q: str | None = Query(default=None, max_length=200),
    state: str | None = Query(default=None, pattern="^(ok|review|deleted)$"),
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(viewer),
    session: Session = Depends(get_session),
) -> list[FileOut]:
    query = (
        select(FileBaseline)
        .join(MonitoredPath)
        .where(mine(MonitoredPath.owner_id, user))
        .order_by(FileBaseline.file_path)
    )
    if q:
        query = query.where(FileBaseline.file_path.contains(q.lower().replace("\\", "/")))
    if state == "ok":
        query = query.where(FileBaseline.status == BaselineStatus.ACTIVE)
    elif state == "review":
        query = query.where(FileBaseline.status == BaselineStatus.PENDING_REVIEW)
    elif state == "deleted":
        query = query.where(FileBaseline.status == BaselineStatus.DELETED)
    else:
        query = query.where(FileBaseline.status != BaselineStatus.DELETED)
    open_ids = open_change_ids(session)
    return [file_out(b, open_ids.get(b.id)) for b in session.scalars(query.limit(limit).offset(offset))]


@router.get("/files/{file_id}", response_model=FileDetailOut)
def get_file(
    file_id: int, user: User = Depends(viewer), session: Session = Depends(get_session)
) -> FileDetailOut:
    baseline = owned_baseline(session, file_id, user)
    return file_detail(session, baseline, open_change_ids(session).get(baseline.id))


__all__ = ["StepUp", "router", "unlock_signing_key"]
