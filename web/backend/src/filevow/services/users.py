"""User accounts: Argon2id passwords, lockout, TOTP two-step verification, recovery codes."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.crypto import aead
from filevow.db.base import utcnow
from filevow.db.enums import Role
from filevow.db.models import User
from filevow.services import audit

MIN_PASSWORD_LENGTH = 12
LOCKOUT_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
TOTP_STEP_SECONDS = 30
RECOVERY_CODE_COUNT = 8
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{3,64}$")
COMMON_PASSWORDS = frozenset(
    {"password1234", "123456789012", "qwertyuiop12", "administrator", "letmein12345", "welcome12345"}
)

_hasher = PasswordHasher()  # Argon2id, 64 MB memory, 3 passes, 4 lanes
_DUMMY_HASH = _hasher.hash("timing-equaliser-password")


class AuthError(Exception):
    """Generic failure. The message never reveals whether the username exists."""

    def __init__(self, message: str = "Invalid username, password or code") -> None:
        super().__init__(message)


class AccountLocked(AuthError):
    def __init__(self, until: datetime) -> None:
        super().__init__(f"Account locked until {until:%H:%M} UTC after too many failed attempts")
        self.until = until


class MfaRequired(AuthError):
    def __init__(self) -> None:
        super().__init__("Enter the 6-digit code from your authenticator app")


class UserError(ValueError):
    pass


@dataclass(frozen=True)
class MfaEnrollment:
    secret: str
    provisioning_uri: str


# --------------------------------------------------------------------------- accounts


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise UserError(f"Use at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in COMMON_PASSWORDS:
        raise UserError("This password is too common")


def create_user(
    session: Session, username: str, password: str, role: Role, *, actor_user_id: int | None = None
) -> User:
    if not USERNAME_PATTERN.match(username):
        raise UserError("Usernames use 3 to 64 letters, digits, dots, dashes or underscores")
    if session.scalar(select(User.id).where(User.username == username)) is not None:
        raise UserError("That username is already taken")
    validate_password(password)
    user = User(username=username, password_hash=_hasher.hash(password), role=role)
    session.add(user)
    session.flush()
    audit.record_event(
        session,
        "USER_CREATED",
        actor_user_id=actor_user_id,
        owner_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"username": username, "role": str(role)},
    )
    return user


def change_password(session: Session, user: User, new_password: str) -> None:
    validate_password(new_password)
    user.password_hash = _hasher.hash(new_password)
    audit.record_event(
        session,
        "PASSWORD_CHANGED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="user",
        target_id=user.id,
    )


def _password_matches(user: User, password: str) -> bool:
    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _hasher.hash(password)
    return True


def authenticate(
    session: Session,
    username: str,
    password: str,
    totp_code: str | None,
    vault_key: bytes,
    *,
    ip_address: str | None = None,
    now: datetime | None = None,
) -> User:
    now = now or utcnow()
    user = session.scalar(select(User).where(User.username == username))
    if user is None or not user.is_active:
        _hasher.verify(_DUMMY_HASH, "timing-equaliser-password")  # same cost as a real check
        raise AuthError()
    if user.locked_until and user.locked_until > now:
        raise AccountLocked(user.locked_until)

    if not _password_matches(user, password):
        _register_failure(session, user, now, ip_address)
        raise AuthError()
    if user.mfa_enabled:
        if not totp_code:
            raise MfaRequired()
        if not (verify_totp(user, totp_code, vault_key, now) or use_recovery_code(user, totp_code)):
            _register_failure(session, user, now, ip_address)
            raise AuthError()

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    audit.record_event(
        session, "LOGIN_SUCCESS", actor_user_id=user.id, owner_id=user.id, ip_address=ip_address
    )
    return user


def verify_step_up(
    session: Session, user: User, password: str, totp_code: str | None, vault_key: bytes
) -> None:
    """Re-check identity right before a sensitive action, even with a valid session."""
    now = utcnow()
    if not _password_matches(user, password):
        _register_failure(session, user, now, None)
        raise AuthError("Password is not correct")
    if user.mfa_enabled and not (totp_code and verify_totp(user, totp_code, vault_key, now)):
        _register_failure(session, user, now, None)
        raise AuthError("Authenticator code is not correct")


def record_failed_step_up(session: Session, user: User) -> None:
    """Count a wrong confirmation (password, passphrase or code) like a failed sign-in."""
    _register_failure(session, user, utcnow(), None)


def unusable_password_hash() -> str:
    """For accounts that sign in through the cloud: a hash no password can match."""
    return _hasher.hash(secrets.token_urlsafe(32))


def _register_failure(session: Session, user: User, now: datetime, ip_address: str | None) -> None:
    user.failed_attempts += 1
    audit.record_event(
        session,
        "LOGIN_FAILED",
        owner_id=user.id,
        target_type="user",
        target_id=user.id,
        ip_address=ip_address,
    )
    if user.failed_attempts >= LOCKOUT_ATTEMPTS:
        user.locked_until = now + LOCKOUT_DURATION
        user.failed_attempts = 0
        audit.record_event(
            session,
            "ACCOUNT_LOCKED",
            owner_id=user.id,
            target_type="user",
            target_id=user.id,
            ip_address=ip_address,
        )
    session.commit()  # failures must be remembered even though the request itself fails


def register(
    session: Session, username: str, password: str, *, allowed: bool, ip_address: str | None
) -> User:
    """Self-service sign-up. The first account on a fresh installation becomes the administrator."""
    first_account = session.scalar(select(User.id).limit(1)) is None
    if not allowed and not first_account:
        raise UserError("New accounts are turned off. Ask the administrator to create one for you.")
    user = create_user(session, username, password, Role.ADMIN if first_account else Role.USER)
    user.last_login_at = utcnow()
    audit.record_event(
        session,
        "USER_REGISTERED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="user",
        target_id=user.id,
        ip_address=ip_address,
        details={"username": username, "role": str(user.role)},
    )
    return user


# --------------------------------------------------------------------------- TOTP


def _totp_aad(user: User) -> bytes:
    return f"filevow:totp:{user.id}".encode()


def begin_mfa_enrollment(user: User, vault_key: bytes, issuer: str = "FileVow") -> MfaEnrollment:
    secret = pyotp.random_base32()
    user.mfa_secret_enc = aead.seal(secret.encode(), vault_key, _totp_aad(user))
    user.mfa_enabled = False
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=issuer)
    return MfaEnrollment(secret=secret, provisioning_uri=uri)


def confirm_mfa(session: Session, user: User, code: str, vault_key: bytes) -> list[str]:
    """Turn on two-step verification once the user proves the app works. Returns recovery codes."""
    if user.mfa_secret_enc is None or not verify_totp(user, code, vault_key, utcnow(), require_enabled=False):
        raise AuthError("That code is not correct; check the time on your phone and try again")
    user.mfa_enabled = True
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(RECOVERY_CODE_COUNT)]
    user.recovery_codes = [_hasher.hash(c) for c in codes]
    audit.record_event(
        session, "MFA_ENABLED", actor_user_id=user.id, owner_id=user.id, target_type="user", target_id=user.id
    )
    return codes


def verify_totp(
    user: User, code: str, vault_key: bytes, now: datetime, *, require_enabled: bool = True
) -> bool:
    """Accept the current 30-second step or one either side, and never the same step twice."""
    if user.mfa_secret_enc is None or (require_enabled and not user.mfa_enabled):
        return False
    code = code.strip().replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return False
    secret = aead.unseal(user.mfa_secret_enc, vault_key, _totp_aad(user)).decode()
    totp = pyotp.TOTP(secret)
    current_step = int(now.timestamp() if now else time.time()) // TOTP_STEP_SECONDS
    for step in (current_step - 1, current_step, current_step + 1):
        if user.last_totp_step is not None and step <= user.last_totp_step:
            continue
        if secrets.compare_digest(totp.at(step * TOTP_STEP_SECONDS), code):
            user.last_totp_step = step
            return True
    return False


def use_recovery_code(user: User, code: str) -> bool:
    for index, hashed in enumerate(user.recovery_codes or []):
        try:
            _hasher.verify(hashed, code.strip().lower())
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            continue
        remaining = list(user.recovery_codes or [])
        remaining.pop(index)
        user.recovery_codes = remaining
        return True
    return False
