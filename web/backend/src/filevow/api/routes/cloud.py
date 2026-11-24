"""Cloud sign-in routes: one-time e-mail codes (by e-mail or username) and, optionally, Google."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from filevow.api.deps import (
    StepUp,
    client_ip,
    confirm_step_up,
    current_user,
    get_ctx,
    get_session,
    rate_limit,
)
from filevow.api.routes.auth import _clear_session_cookies, start_session
from filevow.api.schemas import (
    CloudPreferencesIn,
    EmailCodeStartIn,
    EmailCodeStartOut,
    EmailCodeVerifyIn,
    UserOut,
)
from filevow.db.models import User
from filevow.services import cloud, tokens, users
from filevow.services.context import AppContext

router = APIRouter(prefix="/auth/cloud", tags=["auth"])

PKCE_COOKIE = "fv_pkce"
PKCE_COOKIE_PATH = "/api/v1/auth/cloud"
PKCE_LIFETIME_SECONDS = 600


def _cloud(ctx: AppContext = Depends(get_ctx)) -> cloud.SupabaseAuth:
    client = ctx.cloud()
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cloud sign-in is not set up on this installation")
    return client


def _callback_url(request: Request) -> str:
    # Same host the window uses (127.0.0.1 or localhost), so the PKCE cookie comes back.
    return f"{request.base_url}api/v1/auth/cloud/callback"


def _back_to_sign_in(message: str) -> RedirectResponse:
    response = RedirectResponse("/?" + urlencode({"signin_error": message}), status.HTTP_303_SEE_OTHER)
    response.delete_cookie(PKCE_COOKIE, path=PKCE_COOKIE_PATH)
    return response


def _after_sign_in(
    request: Request,
    response: Response,
    session: Session,
    ctx: AppContext,
    client: cloud.SupabaseAuth,
    signed_in: cloud.CloudSession,
    username: str | None = None,
) -> User:
    user = cloud.link_account(
        session, signed_in, ctx.vault_key(), ip_address=client_ip(request), username=username
    )
    if user.usage_reporting:
        try:  # signing in counts as using the app today; never block sign-in on it
            cloud.record_activity(client, signed_in.access_token)
            user.cloud_reported_on = user.last_login_at.date() if user.last_login_at else None
        except cloud.CloudError:
            pass
    start_session(request, response, session, ctx, user)
    return user


def _google_enabled(ctx: AppContext = Depends(get_ctx)) -> None:
    if not ctx.settings.cloud_google:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Google sign-in is turned off")


@router.get("/google", dependencies=[Depends(_google_enabled), Depends(rate_limit("cloud-google", 10))])
def google_start(request: Request, client: cloud.SupabaseAuth = Depends(_cloud)) -> RedirectResponse:
    """Send the window to Google (via Supabase); the verifier stays in an HttpOnly cookie."""
    pkce = cloud.new_pkce_pair()
    response = RedirectResponse(
        client.google_authorize_url(_callback_url(request), pkce.challenge), status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        PKCE_COOKIE,
        pkce.verifier,
        max_age=PKCE_LIFETIME_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",  # must survive the top-level redirect back from Supabase
        path=PKCE_COOKIE_PATH,
    )
    return response


@router.get("/callback", dependencies=[Depends(_google_enabled)])
def google_callback(
    request: Request,
    code: str | None = None,
    error_description: str | None = None,
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
    client: cloud.SupabaseAuth = Depends(_cloud),
) -> RedirectResponse:
    if error_description or not code:
        return _back_to_sign_in(error_description or "Google sign-in was cancelled")
    verifier = request.cookies.get(PKCE_COOKIE)
    if not verifier:
        return _back_to_sign_in("The sign-in took too long. Try again.")
    response = RedirectResponse("/", status.HTTP_303_SEE_OTHER)
    try:
        signed_in = client.exchange_code(code, verifier)
        _after_sign_in(request, response, session, ctx, client, signed_in)
    except (cloud.CloudError, users.AuthError) as exc:
        session.rollback()
        return _back_to_sign_in(str(exc))
    response.delete_cookie(PKCE_COOKIE, path=PKCE_COOKIE_PATH)
    return response


@router.post(
    "/email/start", response_model=EmailCodeStartOut, dependencies=[Depends(rate_limit("cloud-email", 5))]
)
def email_start(
    body: EmailCodeStartIn,
    session: Session = Depends(get_session),
    client: cloud.SupabaseAuth = Depends(_cloud),
) -> EmailCodeStartOut:
    """E-mail a sign-in code. ``login`` is an e-mail address or a username on this computer."""
    try:
        target = cloud.resolve_login(session, body.login)
        client.send_email_code(target.email)
    except cloud.CloudError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    new_account = target.account is None
    return EmailCodeStartOut(
        email_hint=cloud.mask_email(target.email),
        new_account=new_account,
        suggested_username=cloud.suggest_username(session, target.email) if new_account else None,
    )


@router.post("/email/verify", response_model=UserOut, dependencies=[Depends(rate_limit("cloud-verify", 10))])
def email_verify(
    body: EmailCodeVerifyIn,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
    client: cloud.SupabaseAuth = Depends(_cloud),
) -> User:
    try:
        target = cloud.resolve_login(session, body.login)
        # Check a new username first, so a taken name doesn't use up the code.
        username = (
            cloud.check_new_username(session, body.username)
            if target.account is None and body.username
            else None
        )
        signed_in = client.verify_email_code(target.email, body.code)
        return _after_sign_in(request, response, session, ctx, client, signed_in, username)
    except cloud.CloudError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except users.AuthError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc


@router.post("/preferences", response_model=UserOut)
def preferences(
    body: CloudPreferencesIn, user: User = Depends(current_user), session: Session = Depends(get_session)
) -> User:
    """Turn the once-a-day "in use" report on or off for this account."""
    user.usage_reporting = body.usage_reporting
    session.flush()
    return user


@router.post("/delete-account", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    body: StepUp,
    request: Request,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
    client: cloud.SupabaseAuth = Depends(_cloud),
) -> None:
    """Delete the cloud account and its usage data, then sign out. Local files are untouched."""
    if not user.is_cloud:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This account isn't a cloud account")
    confirm_step_up(session, ctx, user, body)
    try:
        cloud.delete_cloud_account(session, client, user, ctx.vault_key())
    except cloud.CloudError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    tokens.revoke_all(session, user.id)
    _clear_session_cookies(response)
