"""Live updates over WebSocket.

The server pushes a small state snapshot whenever something changes (new run, new
change, new alert). Polling the database keeps this correct even when the agent runs
in a different process from the API.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import func, select

from filevow.api.deps import ACCESS_COOKIE
from filevow.db.enums import OPEN_REVIEW_STATUSES
from filevow.db.models import AgentHeartbeat, Alert, AuditEntry, ChangeEvent, User, VerificationRun
from filevow.services import tokens, users
from filevow.services.context import AppContext

router = APIRouter()
POLL_SECONDS = 3.0


def _snapshot(ctx: AppContext) -> dict[str, Any]:
    with ctx.session() as session:
        heartbeat = session.scalar(select(func.max(AgentHeartbeat.last_seen_at)))
        return {
            "last_run_id": session.scalar(select(func.max(VerificationRun.id))),
            "open_changes": session.scalar(
                select(func.count(ChangeEvent.id)).where(ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES))
            ),
            "last_alert_id": session.scalar(select(func.max(Alert.id))),
            "last_audit_id": session.scalar(select(func.max(AuditEntry.id))),
            "agent_last_seen": heartbeat.isoformat() if heartbeat else None,
        }


def _same_origin(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    if origin is None:
        return True  # non-browser clients
    return urlparse(origin).netloc == websocket.headers.get("host")


@router.websocket("/api/v1/events")
async def events(websocket: WebSocket) -> None:
    ctx: AppContext = websocket.app.state.ctx
    token = websocket.cookies.get(ACCESS_COOKIE)
    if not token or not _same_origin(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        claims = tokens.decode_access_token(token, ctx.jwt_secret())
    except users.AuthError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    with ctx.session() as session:
        user = session.get(User, claims.user_id)
        if user is None or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await websocket.accept()
    previous: dict[str, Any] | None = None
    try:
        while True:
            current = await asyncio.to_thread(_snapshot, ctx)
            if current != previous:
                await websocket.send_json({"type": "state", **current})
                previous = current
            await asyncio.sleep(POLL_SECONDS)
    except WebSocketDisconnect:
        return
