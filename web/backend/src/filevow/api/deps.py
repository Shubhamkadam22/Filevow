"""FastAPI dependencies: context, database session, authentication, roles, CSRF, rate limits."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterator

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from filevow.api.security import RateLimiter
from filevow.db.enums import Role
from filevow.db.models import User
from filevow.services import tokens, users
from filevow.services.context import AppContext

ACCESS_COOKIE = "fv_access"
REFRESH_COOKIE = "fv_refresh"
CSRF_COOKIE = "fv_csrf"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.USER: 2, Role.ADMIN: 3}


class StepUp(BaseModel):
    """Fresh proof of identity required for sensitive actions."""

    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, max_length=12)


def get_ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


def get_session(ctx: AppContext = Depends(get_ctx)) -> Iterator[Session]:
    with ctx.session() as session:
        yield session


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_rate_limiter(request: Request) -> RateLimiter:
    limiter: RateLimiter = request.app.state.rate_limiter
    return limiter


def rate_limit(bucket: str, limit: int, window_seconds: float = 60) -> Callable[..., None]:
    def check(request: Request, limiter: RateLimiter = Depends(get_rate_limiter)) -> None:
        if not limiter.allow(client_ip(request), bucket, limit, window_seconds):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts; wait a minute and try again"
            )

    return check


def current_user(
    request: Request, session: Session = Depends(get_session), ctx: AppContext = Depends(get_ctx)
) -> User:
    header = request.headers.get("Authorization", "")
    bearer = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else None
    token = bearer or request.cookies.get(ACCESS_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue")
    try:
        claims = tokens.decode_access_token(token, ctx.jwt_secret())
    except users.AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    if bearer is None and request.method in UNSAFE_METHODS:
        # Cookie sessions must prove the request came from our own page (double-submit token).
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        header_token = request.headers.get(CSRF_HEADER, "")
        if not cookie_token or not secrets.compare_digest(cookie_token, header_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")

    user = session.get(User, claims.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue")
    return user


def require(minimum: Role) -> Callable[..., User]:
    def check(user: User = Depends(current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have permission to do that")
        return user

    return check


def confirm_step_up(session: Session, ctx: AppContext, user: User, proof: StepUp) -> None:
    try:
        users.verify_step_up(session, user, proof.password, proof.totp_code, ctx.vault_key())
    except users.AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
