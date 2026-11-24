"""Administration: users, signing keys, notification channels and system information."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

import filevow
from filevow.api.deps import confirm_step_up, get_ctx, get_session, rate_limit, require
from filevow.api.schemas import (
    ChannelIn,
    ChannelOut,
    KeyOut,
    SystemInfoOut,
    UserCreateIn,
    UserOut,
    UserUpdateIn,
)
from filevow.api.workspace import owned
from filevow.db.enums import ChannelType, KeyPurpose, Role
from filevow.db.models import NotificationChannel, SigningKey, User
from filevow.services import audit, tokens, trust, users
from filevow.services.context import AppContext
from filevow.services.notifications import Notification, build_channel, decrypt_config, encrypt_config

router = APIRouter(tags=["admin"])
viewer = require(Role.VIEWER)
admin = require(Role.ADMIN)
owner = require(Role.USER)


# --------------------------------------------------------------------------- users


@router.get("/users", response_model=list[UserOut])
def list_users(_: User = Depends(admin), session: Session = Depends(get_session)) -> list[User]:
    return list(session.scalars(select(User).order_by(User.username)))


@router.post(
    "/users", response_model=UserOut, status_code=201, dependencies=[Depends(rate_limit("step-up", 30))]
)
def create_user(
    body: UserCreateIn,
    user: User = Depends(admin),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> User:
    confirm_step_up(session, ctx, user, body)
    try:
        return users.create_user(session, body.username, body.new_password, body.role, actor_user_id=user.id)
    except users.UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.patch("/users/{user_id}", response_model=UserOut, dependencies=[Depends(rate_limit("step-up", 30))])
def update_user(
    user_id: int,
    body: UserUpdateIn,
    user: User = Depends(admin),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> User:
    confirm_step_up(session, ctx, user, body)
    target = session.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if target.id == user.id and (body.role not in (None, Role.ADMIN) or body.is_active is False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You can't remove your own administrator access")
    if body.role is not None:
        target.role = body.role
    if body.is_active is not None:
        target.is_active = body.is_active
        if not body.is_active:
            tokens.revoke_all(session, target.id)
    audit.record_event(
        session,
        "USER_UPDATED",
        actor_user_id=user.id,
        owner_id=target.id,
        target_type="user",
        target_id=target.id,
        details={"username": target.username, "role": str(target.role), "active": target.is_active},
    )
    return target


# --------------------------------------------------------------------------- keys and system


@router.get("/keys", response_model=list[KeyOut])
def list_keys(
    user: User = Depends(viewer), session: Session = Depends(get_session), ctx: AppContext = Depends(get_ctx)
) -> list[KeyOut]:
    pinned = trust.pinned_fingerprints(ctx.secrets)
    rows = session.scalars(
        select(SigningKey)
        .where(or_(SigningKey.owner_id == user.id, SigningKey.purpose == KeyPurpose.AGENT))
        .order_by(SigningKey.id)
    )
    return [KeyOut.model_validate(r).model_copy(update={"pinned": r.fingerprint in pinned}) for r in rows]


@router.get("/system", response_model=SystemInfoOut)
def system_info(
    user: User = Depends(viewer), session: Session = Depends(get_session), ctx: AppContext = Depends(get_ctx)
) -> SystemInfoOut:
    url = ctx.settings.resolved_database_url
    return SystemInfoOut(
        version=filevow.__version__,
        verification_interval_minutes=ctx.settings.verification_interval_minutes,
        monitoring_gap_minutes=ctx.settings.monitoring_gap_minutes,
        signing_key_configured=trust.active_signing_key(session, user.id) is not None,
        database=url.split(":", 1)[0],
    )


# --------------------------------------------------------------------------- notification channels


def _channel_target(row: NotificationChannel, vault_key: bytes) -> str:
    config = decrypt_config(vault_key, row.config_enc)
    if row.type is ChannelType.EMAIL:
        return ", ".join(config.get("recipients", []))
    if row.type is ChannelType.DESKTOP:
        return "this computer"
    return urlparse(str(config.get("url", ""))).netloc  # host only; the URL itself can be a secret


def _channel_out(row: NotificationChannel, vault_key: bytes) -> ChannelOut:
    return ChannelOut(
        id=row.id,
        name=row.name,
        type=row.type,
        min_severity=row.min_severity,
        is_escalation_contact=row.is_escalation_contact,
        enabled=row.enabled,
        target=_channel_target(row, vault_key),
    )


def _validate_config(kind: ChannelType, config: dict[str, object]) -> None:
    if kind is ChannelType.EMAIL:
        missing = {"host", "sender", "recipients"} - config.keys()
        if missing:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"Missing e-mail settings: {', '.join(sorted(missing))}"
            )
    elif kind is not ChannelType.DESKTOP and not str(config.get("url", "")).startswith("https://"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Webhook URLs must start with https://")


@router.get("/channels", response_model=list[ChannelOut])
def list_channels(
    user: User = Depends(owner), session: Session = Depends(get_session), ctx: AppContext = Depends(get_ctx)
) -> list[ChannelOut]:
    key = ctx.vault_key()
    return [
        _channel_out(r, key)
        for r in session.scalars(
            select(NotificationChannel)
            .where(NotificationChannel.owner_id == user.id)
            .order_by(NotificationChannel.id)
        )
    ]


@router.post(
    "/channels", response_model=ChannelOut, status_code=201, dependencies=[Depends(rate_limit("step-up", 30))]
)
def create_channel(
    body: ChannelIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> ChannelOut:
    confirm_step_up(session, ctx, user, body)
    _validate_config(body.type, body.config)
    row = NotificationChannel(
        owner_id=user.id,
        name=body.name,
        type=body.type,
        config_enc=encrypt_config(ctx.vault_key(), body.config),
        min_severity=body.min_severity,
        is_escalation_contact=body.is_escalation_contact,
        enabled=body.enabled,
    )
    session.add(row)
    session.flush()
    audit.record_event(
        session,
        "CHANNEL_ADDED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="channel",
        target_id=row.id,
        details={"name": row.name, "type": str(row.type)},
    )
    return _channel_out(row, ctx.vault_key())


@router.delete("/channels/{channel_id}", status_code=204)
def delete_channel(
    channel_id: int, user: User = Depends(owner), session: Session = Depends(get_session)
) -> None:
    row = owned(session, NotificationChannel, channel_id, user, "Channel")
    row.enabled = False  # keep it for the notification log; just stop using it
    audit.record_event(
        session,
        "CHANNEL_DISABLED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="channel",
        target_id=row.id,
    )


@router.post("/channels/{channel_id}/test")
def test_channel(
    channel_id: int,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> dict[str, str]:
    row = owned(session, NotificationChannel, channel_id, user, "Channel")
    try:
        build_channel(row, ctx.vault_key()).send(
            Notification("FileVow test notification", "If you can read this, alerts will reach you.", "low")
        )
    except Exception as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, f"Sending failed: {type(exc).__name__}: {exc}"
        ) from exc
    return {"status": "sent"}
