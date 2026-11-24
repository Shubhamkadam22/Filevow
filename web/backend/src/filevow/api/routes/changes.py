"""The review queue and the decisions taken on it."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.api.deps import confirm_step_up, get_ctx, get_session, rate_limit, require
from filevow.api.presenters import change_detail, change_out
from filevow.api.routes.overview import unlock_signing_key
from filevow.api.schemas import (
    AcceptIn,
    BulkIn,
    BulkOut,
    ChangeDetailOut,
    ChangeOut,
    DecisionOut,
    ReasonIn,
    RestoreIn,
)
from filevow.api.workspace import mine, owned
from filevow.db.enums import OPEN_REVIEW_STATUSES, Role, Severity
from filevow.db.models import ChangeEvent, User
from filevow.services import alerts, trust
from filevow.services.context import AppContext
from filevow.services.review import ConflictError, ReviewError, ReviewResult, ReviewService

router = APIRouter(prefix="/changes", tags=["changes"])
viewer = require(Role.VIEWER)
analyst = require(Role.ANALYST)
owner = require(Role.USER)


def _service(session: Session, ctx: AppContext) -> ReviewService:
    return ReviewService(
        session, ctx.settings, ctx.vault(), trust.load_trusted_baseline_keys(session, ctx.secrets)
    )


def _decide(session: Session, action: Callable[[], ReviewResult]) -> DecisionOut:
    try:
        result = action()
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, {"code": "conflict", "message": str(exc)}) from exc
    except ReviewError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    _resolve_alerts(session, result.file_path)
    return DecisionOut(
        change_id=result.change_id,
        action=result.action,
        message=result.message,
        new_version=result.new_version,
    )


def _resolve_alerts(session: Session, file_path: str) -> None:
    closed = session.scalars(
        select(ChangeEvent.id).where(
            ChangeEvent.file_path == file_path, ChangeEvent.review_status.not_in(OPEN_REVIEW_STATUSES)
        )
    ).all()
    alerts.resolve_for_changes(session, closed)


@router.get("", response_model=list[ChangeOut])
def list_changes(
    state: str = Query(default="open", pattern="^(open|closed|all)$"),
    severity: Severity | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=200, le=1000),
    user: User = Depends(viewer),
    session: Session = Depends(get_session),
) -> list[ChangeOut]:
    query = (
        select(ChangeEvent).where(mine(ChangeEvent.owner_id, user)).order_by(ChangeEvent.detected_at.desc())
    )
    if state == "open":
        query = query.where(ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES))
    elif state == "closed":
        query = query.where(ChangeEvent.review_status.not_in(OPEN_REVIEW_STATUSES))
    if severity:
        query = query.where(ChangeEvent.severity == severity)
    if q:
        query = query.where(ChangeEvent.file_path.contains(q.lower().replace("\\", "/")))
    return [change_out(session, e) for e in session.scalars(query.limit(limit))]


@router.get("/{change_id}", response_model=ChangeDetailOut)
def get_change(
    change_id: int,
    user: User = Depends(viewer),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> ChangeDetailOut:
    return change_detail(session, ctx.vault(), owned(session, ChangeEvent, change_id, user, "Change"))


@router.post(
    "/{change_id}/accept", response_model=DecisionOut, dependencies=[Depends(rate_limit("step-up", 30))]
)
def accept(
    change_id: int,
    body: AcceptIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> DecisionOut:
    owned(session, ChangeEvent, change_id, user, "Change")
    confirm_step_up(session, ctx, user, body)
    private_key, signing_key = unlock_signing_key(session, ctx, user, body.key_passphrase)
    service = _service(session, ctx)
    return _decide(
        session,
        lambda: service.accept(
            change_id,
            actor_user_id=user.id,
            reason=body.reason,
            private_key=private_key,
            signing_key=signing_key,
            expected_sha256=body.expected_sha256,
        ),
    )


@router.post(
    "/{change_id}/restore", response_model=DecisionOut, dependencies=[Depends(rate_limit("step-up", 30))]
)
def restore(
    change_id: int,
    body: RestoreIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> DecisionOut:
    owned(session, ChangeEvent, change_id, user, "Change")
    confirm_step_up(session, ctx, user, body)
    service = _service(session, ctx)
    return _decide(session, lambda: service.restore(change_id, actor_user_id=user.id, reason=body.reason))


@router.post(
    "/{change_id}/quarantine", response_model=DecisionOut, dependencies=[Depends(rate_limit("step-up", 30))]
)
def quarantine(
    change_id: int,
    body: RestoreIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> DecisionOut:
    owned(session, ChangeEvent, change_id, user, "Change")
    confirm_step_up(session, ctx, user, body)
    service = _service(session, ctx)
    return _decide(session, lambda: service.quarantine(change_id, actor_user_id=user.id, reason=body.reason))


@router.post("/{change_id}/reject", response_model=DecisionOut)
def reject(
    change_id: int,
    body: ReasonIn,
    user: User = Depends(analyst),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> DecisionOut:
    owned(session, ChangeEvent, change_id, user, "Change")
    service = _service(session, ctx)
    return _decide(session, lambda: service.reject(change_id, actor_user_id=user.id, reason=body.reason))


@router.post("/{change_id}/escalate", response_model=DecisionOut)
def escalate(
    change_id: int,
    body: ReasonIn,
    user: User = Depends(analyst),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> DecisionOut:
    owned(session, ChangeEvent, change_id, user, "Change")
    service = _service(session, ctx)
    return _decide(session, lambda: service.escalate(change_id, actor_user_id=user.id, reason=body.reason))


@router.post("/bulk", response_model=BulkOut, dependencies=[Depends(rate_limit("step-up", 30))])
def bulk(
    body: BulkIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> BulkOut:
    """One confirmation for many files; each file still gets its own signed version."""
    confirm_step_up(session, ctx, user, body)
    service = _service(session, ctx)
    signing = None
    if body.action == "accept":
        if not body.key_passphrase:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "The signing-key passphrase is required to accept"
            )
        signing = unlock_signing_key(session, ctx, user, body.key_passphrase)

    results: list[DecisionOut] = []
    skipped: dict[int, str] = {}
    for change_id in body.ids:
        event = session.get(ChangeEvent, change_id)
        if event is None or event.owner_id != user.id:
            skipped[change_id] = "change not found"
            continue
        try:
            with session.begin_nested():  # one failing file does not undo the others
                if signing is not None:
                    result = service.accept(
                        change_id,
                        actor_user_id=user.id,
                        reason=body.reason,
                        private_key=signing[0],
                        signing_key=signing[1],
                    )
                else:
                    result = service.restore(change_id, actor_user_id=user.id, reason=body.reason)
        except ReviewError as exc:
            skipped[change_id] = str(exc)
            continue
        _resolve_alerts(session, result.file_path)
        results.append(
            DecisionOut(
                change_id=result.change_id,
                action=result.action,
                message=result.message,
                new_version=result.new_version,
            )
        )
    return BulkOut(results=results, skipped=skipped)
