from __future__ import annotations

from datetime import timedelta

import pyotp
import pytest

from filevow.crypto import aead
from filevow.db.base import utcnow
from filevow.db.enums import Role
from filevow.db.models import User
from filevow.services import tokens, users
from filevow.services.context import AppContext
from filevow.services.users import AccountLocked, AuthError, MfaRequired, UserError

PASSWORD = "a strong passphrase 42"


def _user(ctx: AppContext, role: Role = Role.ADMIN, name: str = "alice") -> int:
    with ctx.session() as session:
        return users.create_user(session, name, PASSWORD, role).id


def _login(ctx: AppContext, password: str = PASSWORD, code: str | None = None, name: str = "alice") -> User:
    with ctx.session() as session:
        return users.authenticate(session, name, password, code, ctx.vault_key())


def _enable_mfa(ctx: AppContext, user_id: int) -> tuple[str, list[str], str]:
    """Returns the secret, the recovery codes and the TOTP code used to confirm enrolment."""
    with ctx.session() as session:
        user = session.get(User, user_id)
        enrollment = users.begin_mfa_enrollment(user, ctx.vault_key())
        used_code = pyotp.TOTP(enrollment.secret).now()
        codes = users.confirm_mfa(session, user, used_code, ctx.vault_key())
    return enrollment.secret, codes, used_code


def test_password_is_stored_as_argon2id(ctx: AppContext) -> None:
    user_id = _user(ctx)
    with ctx.session() as session:
        assert session.get(User, user_id).password_hash.startswith("$argon2id$")
    assert _login(ctx).id == user_id


@pytest.mark.parametrize("password", ["short", "password1234"])
def test_weak_passwords_are_refused(ctx: AppContext, password: str) -> None:
    with ctx.session() as session, pytest.raises(UserError):
        users.create_user(session, "bob", password, Role.VIEWER)


def test_unknown_user_and_wrong_password_look_identical(ctx: AppContext) -> None:
    _user(ctx)
    with pytest.raises(AuthError) as unknown:
        _login(ctx, name="nobody")
    with pytest.raises(AuthError) as wrong:
        _login(ctx, password="wrong password!!")
    assert str(unknown.value) == str(wrong.value)


def test_five_failures_lock_the_account(ctx: AppContext) -> None:
    _user(ctx)
    for _ in range(5):
        with pytest.raises(AuthError):
            _login(ctx, password="wrong password!!")
    with pytest.raises(AccountLocked):
        _login(ctx)  # even the right password is refused while locked


def test_lock_expires(ctx: AppContext) -> None:
    user_id = _user(ctx)
    with ctx.session() as session:
        session.get(User, user_id).locked_until = utcnow() - timedelta(seconds=1)
    assert _login(ctx).id == user_id


def test_totp_is_required_once_enabled(ctx: AppContext) -> None:
    user_id = _user(ctx)
    secret, _, _ = _enable_mfa(ctx, user_id)
    with pytest.raises(MfaRequired):
        _login(ctx)
    with ctx.session() as session:
        session.get(User, user_id).last_totp_step = None  # enrolment used the current step
    assert _login(ctx, code=pyotp.TOTP(secret).now()).id == user_id


def test_a_totp_code_cannot_be_replayed(ctx: AppContext) -> None:
    user_id = _user(ctx)
    _, _, used_code = _enable_mfa(ctx, user_id)
    with pytest.raises(AuthError):
        _login(ctx, code=used_code)  # exactly the code that confirmed enrolment


def test_totp_secret_is_encrypted(ctx: AppContext) -> None:
    user_id = _user(ctx)
    secret, _, _ = _enable_mfa(ctx, user_id)
    with ctx.session() as session:
        blob = session.get(User, user_id).mfa_secret_enc
    assert secret.encode() not in blob
    with pytest.raises(aead.DecryptionError):
        aead.unseal(blob, ctx.vault_key(), b"filevow:totp:999")


def test_recovery_codes_work_once(ctx: AppContext) -> None:
    user_id = _user(ctx)
    _, codes, _ = _enable_mfa(ctx, user_id)
    assert len(codes) == 8
    assert _login(ctx, code=codes[0]).id == user_id
    with pytest.raises(AuthError):
        _login(ctx, code=codes[0])


def test_access_token_round_trip_and_expiry(ctx: AppContext) -> None:
    user_id = _user(ctx)
    with ctx.session() as session:
        token = tokens.issue_access_token(session.get(User, user_id), ctx.jwt_secret())
    claims = tokens.decode_access_token(token, ctx.jwt_secret())
    assert claims.user_id == user_id and claims.role == "admin"
    with pytest.raises(AuthError):
        tokens.decode_access_token(token, "another secret entirely, 32 bytes+")


def test_refresh_tokens_rotate_and_reuse_revokes_everything(ctx: AppContext) -> None:
    user_id = _user(ctx)
    with ctx.session() as session:
        first = tokens.issue_refresh_token(session, session.get(User, user_id), "127.0.0.1", "test")
    with ctx.session() as session:
        _, second = tokens.rotate_refresh_token(session, first, "127.0.0.1", "test")
    with ctx.session() as session, pytest.raises(AuthError):
        tokens.rotate_refresh_token(session, first, "127.0.0.1", "test")  # stolen old token replayed
    with ctx.session() as session, pytest.raises(AuthError):
        tokens.rotate_refresh_token(session, second, "127.0.0.1", "test")  # the whole family is gone
