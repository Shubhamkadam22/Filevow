from __future__ import annotations

import io
import secrets

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.api.deps import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    client_ip,
    confirm_step_up,
    current_user,
    get_ctx,
    get_session,
    rate_limit,
)
from filevow.api.schemas import (
    AuthOptionsOut,
    LoginIn,
    MfaConfirmIn,
    MfaSetupOut,
    PasswordChangeIn,
    RegisterIn,
    UserOut,
)
from filevow.db.models import User
from filevow.services import audit, tokens, users
from filevow.services.context import AppContext

router = APIRouter(prefix="/auth", tags=["auth"])


def start_session(
    request: Request, response: Response, session: Session, ctx: AppContext, user: User
) -> None:
    """Issue access and refresh tokens for a user who just proved who they are."""
    refresh = tokens.issue_refresh_token(session, user, client_ip(request), request.headers.get("User-Agent"))
    _set_session_cookies(response, ctx, user, tokens.issue_access_token(user, ctx.jwt_secret()), refresh)


def _set_session_cookies(response: Response, ctx: AppContext, user: User, access: str, refresh: str) -> None:
    secure = ctx.settings.cookie_secure
    response.set_cookie(
        ACCESS_COOKIE,
        access,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api",
        max_age=int(tokens.ACCESS_TOKEN_TTL.total_seconds()),
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api/v1/auth",
        max_age=int(tokens.refresh_ttl(user).total_seconds()),
    )
    # Readable by our own JavaScript so it can echo it in the X-CSRF-Token header.
    response.set_cookie(
        CSRF_COOKIE, secrets.token_urlsafe(24), httponly=False, secure=secure, samesite="strict", path="/"
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/api")
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")


@router.post("/login", response_model=UserOut, dependencies=[Depends(rate_limit("login", 5))])
def login(
    body: LoginIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> User:
    ip = client_ip(request)
    try:
        user = users.authenticate(
            session, body.username, body.password, body.totp_code, ctx.vault_key(), ip_address=ip
        )
    except users.MfaRequired as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, {"code": "mfa_required", "message": str(exc)}
        ) from exc
    except users.AccountLocked as exc:
        raise HTTPException(status.HTTP_423_LOCKED, str(exc)) from exc
    except users.AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    start_session(request, response, session, ctx, user)
    return user


@router.get("/options", response_model=AuthOptionsOut)
def options(session: Session = Depends(get_session), ctx: AppContext = Depends(get_ctx)) -> AuthOptionsOut:
    """Public: lets the sign-in page offer "Create account" only when it is allowed."""
    settings = ctx.settings
    has_accounts = session.scalar(select(User.id).limit(1)) is not None
    cloud = settings.cloud_enabled
    return AuthOptionsOut(
        allow_registration=not cloud and (settings.allow_registration or not has_accounts),
        has_accounts=has_accounts,
        cloud=cloud,
        google=cloud and settings.cloud_google,
        email=cloud and settings.cloud_email,
    )


@router.post(
    "/register", response_model=UserOut, status_code=201, dependencies=[Depends(rate_limit("register", 5))]
)
def register(
    body: RegisterIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> User:
    """Create a personal account and sign straight in. The first account becomes the administrator."""
    if ctx.settings.cloud_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Create your account with Google or an e-mail code")
    ip = client_ip(request)
    try:
        user = users.register(
            session, body.username, body.password, allowed=ctx.settings.allow_registration, ip_address=ip
        )
    except users.UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    start_session(request, response, session, ctx, user)
    return user


@router.post("/refresh", response_model=UserOut, dependencies=[Depends(rate_limit("refresh", 30))])
def refresh(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> User:
    raw = request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue")
    try:
        user, new_refresh = tokens.rotate_refresh_token(
            session, raw, client_ip(request), request.headers.get("User-Agent")
        )
    except users.AuthError as exc:
        _clear_session_cookies(response)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    _set_session_cookies(response, ctx, user, tokens.issue_access_token(user, ctx.jwt_secret()), new_refresh)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, session: Session = Depends(get_session)) -> None:
    raw = request.cookies.get(REFRESH_COOKIE)
    if raw:
        tokens.revoke_refresh_token(session, raw)
    _clear_session_cookies(response)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> User:
    return user


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(user: User = Depends(current_user), ctx: AppContext = Depends(get_ctx)) -> MfaSetupOut:
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-step verification is already on")
    enrollment = users.begin_mfa_enrollment(user, ctx.vault_key())
    buffer = io.BytesIO()
    qrcode.make(enrollment.provisioning_uri, image_factory=qrcode.image.svg.SvgPathImage).save(buffer)
    return MfaSetupOut(
        secret=enrollment.secret,
        provisioning_uri=enrollment.provisioning_uri,
        qr_svg=buffer.getvalue().decode(),
    )


@router.post("/mfa/confirm", response_model=list[str])
def mfa_confirm(
    body: MfaConfirmIn,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> list[str]:
    try:
        return users.confirm_mfa(session, user, body.code, ctx.vault_key())
    except users.AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post(
    "/password", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(rate_limit("step-up", 30))]
)
def change_password(
    body: PasswordChangeIn,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> None:
    if user.is_cloud:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "You sign in with Google or an e-mail code, so there's no password to change",
        )
    confirm_step_up(session, ctx, user, body)
    try:
        users.change_password(session, user, body.new_password)
    except users.UserError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    tokens.revoke_all(session, user.id)
    audit.record_event(
        session, "SESSIONS_REVOKED", actor_user_id=user.id, target_type="user", target_id=user.id
    )
