"""Session tokens: short-lived JWT access tokens and rotating refresh tokens."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import jwt
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from filevow.db.base import utcnow
from filevow.db.models import RefreshToken, User
from filevow.services import audit
from filevow.services.users import AuthError

ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(hours=8)
ALGORITHM = "HS256"


@dataclass(frozen=True)
class AccessClaims:
    user_id: int
    role: str
    expires_at: int


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def issue_access_token(user: User, secret: str) -> str:
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "role": str(user.role),
        "typ": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + ACCESS_TOKEN_TTL).timestamp()),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, secret: str) -> AccessClaims:
    try:
        claims = jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub", "typ"]})
    except jwt.PyJWTError as exc:
        raise AuthError("Your session expired; sign in again") from exc
    if claims.get("typ") != "access":
        raise AuthError("Wrong token type")
    return AccessClaims(int(claims["sub"]), str(claims.get("role")), int(claims["exp"]))


def issue_refresh_token(session: Session, user: User, ip: str | None, user_agent: str | None) -> str:
    raw = secrets.token_urlsafe(32)
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash(raw),
            expires_at=utcnow() + REFRESH_TOKEN_TTL,
            ip_address=ip,
            user_agent=(user_agent or "")[:255],
        )
    )
    session.flush()
    return raw


def rotate_refresh_token(
    session: Session, raw: str, ip: str | None, user_agent: str | None
) -> tuple[User, str]:
    """Exchange a refresh token for a new one. Reusing an old token signals theft:
    every session of that user is revoked."""
    stored = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash(raw)))
    if stored is None:
        raise AuthError("Sign in again")
    user = session.get(User, stored.user_id)
    if user is None or not user.is_active:
        raise AuthError("Sign in again")
    if stored.revoked_at is not None:
        revoke_all(session, user.id)
        audit.record_event(
            session, "REFRESH_TOKEN_REUSED", target_type="user", target_id=user.id, ip_address=ip
        )
        session.commit()
        raise AuthError("This session was ended for your safety; sign in again")
    if stored.expires_at <= utcnow():
        raise AuthError("Your session expired; sign in again")

    new_raw = issue_refresh_token(session, user, ip, user_agent)
    stored.revoked_at = utcnow()
    stored.replaced_by_id = session.scalar(
        select(RefreshToken.id).where(RefreshToken.token_hash == _hash(new_raw))
    )
    return user, new_raw


def revoke_refresh_token(session: Session, raw: str) -> None:
    stored = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == _hash(raw)))
    if stored is not None and stored.revoked_at is None:
        stored.revoked_at = utcnow()


def revoke_all(session: Session, user_id: int) -> None:
    session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
