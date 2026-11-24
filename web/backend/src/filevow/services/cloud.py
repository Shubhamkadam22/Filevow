"""Cloud sign-in with Supabase, plus the once-a-day "in use" count.

What goes to Supabase: the account's e-mail address (verified by Google or by a one-time
code), its sign-in times, and at most one row per day with the app version and Windows
version, which is how the publisher counts active users. File names, paths, contents,
keys and history never leave the computer.

Sign-in methods:

* Google: OAuth 2.0 authorisation code flow with PKCE. The app window goes to Supabase's
  ``/authorize`` endpoint, Google verifies the person, Supabase redirects back to the
  local callback with a one-time code, and the local server exchanges it together with
  the PKCE verifier it kept in an HttpOnly cookie.
* E-mail code: Supabase e-mails a 6-digit code, the user types it in, the local server
  checks it with Supabase.

Either way the local server then links the Supabase account to a local FileVow account
(creating it on first sign-in) and issues its own session cookies, exactly as for a
password sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import platform
import re
import secrets
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.config import Settings
from filevow.crypto import aead
from filevow.db.base import utcnow
from filevow.db.enums import Role
from filevow.db.models import User
from filevow.secrets import SecretStore
from filevow.services import audit, trust, users

log = logging.getLogger(__name__)

# Signing in again is required for sensitive actions after this long if the account has no
# signing key yet (once it has one, its passphrase confirms those actions instead).
FRESH_SIGN_IN = timedelta(minutes=30)
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$")


class CloudError(Exception):
    """A sign-in step failed; the message is safe to show to the user."""


@dataclass(frozen=True)
class CloudSession:
    user_id: str
    email: str
    access_token: str
    refresh_token: str


@dataclass(frozen=True)
class PkcePair:
    verifier: str
    challenge: str


def new_pkce_pair() -> PkcePair:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PkcePair(verifier, challenge)


def normalize_email(email: str) -> str:
    cleaned = email.strip().lower()
    if not EMAIL_PATTERN.match(cleaned):
        raise CloudError("Enter a valid e-mail address")
    return cleaned


class SupabaseAuth:
    """The few Supabase Auth (GoTrue) and RPC endpoints FileVow uses."""

    def __init__(
        self, url: str, anon_key: str, *, transport: httpx.BaseTransport | None = None, timeout: float = 15
    ) -> None:
        self.url = url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.url,
            headers={"apikey": anon_key, "Content-Type": "application/json"},
            timeout=timeout,
            transport=transport,
        )

    # ------------------------------------------------------------------ sign-in

    def send_email_code(self, email: str) -> None:
        self._post("/auth/v1/otp", {"email": email, "create_user": True})

    def verify_email_code(self, email: str, code: str) -> CloudSession:
        code = code.strip().replace(" ", "")
        if not code.isdigit() or not 6 <= len(code) <= 10:
            raise CloudError("Enter the code from the e-mail")
        return self._session(self._post("/auth/v1/verify", {"type": "email", "email": email, "token": code}))

    def google_authorize_url(self, redirect_to: str, code_challenge: str) -> str:
        query = urlencode(
            {
                "provider": "google",
                "redirect_to": redirect_to,
                "code_challenge": code_challenge,
                "code_challenge_method": "s256",
            }
        )
        return f"{self.url}/auth/v1/authorize?{query}"

    def exchange_code(self, auth_code: str, code_verifier: str) -> CloudSession:
        body = {"auth_code": auth_code, "code_verifier": code_verifier}
        return self._session(self._post("/auth/v1/token?grant_type=pkce", body))

    def refresh(self, refresh_token: str) -> CloudSession:
        body = {"refresh_token": refresh_token}
        return self._session(self._post("/auth/v1/token?grant_type=refresh_token", body))

    # ------------------------------------------------------------------ data

    def rpc(self, name: str, access_token: str, payload: dict[str, Any] | None = None) -> None:
        self._post(f"/rest/v1/rpc/{name}", payload or {}, token=access_token)

    # ------------------------------------------------------------------ helpers

    def _post(self, path: str, body: dict[str, Any], *, token: str | None = None) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {token}"} if token else None
        try:
            response = self._client.post(path, json=body, headers=headers)
        except httpx.HTTPError as exc:
            log.warning("Supabase request to %s failed: %s", path.split("?")[0], exc)
            raise CloudError("Can't reach the sign-in service. Check your internet connection.") from exc
        if response.status_code >= 400:
            raise CloudError(_friendly_error(path, response))
        if not response.content:
            return {}
        data = response.json()
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _session(data: dict[str, Any]) -> CloudSession:
        user = data.get("user") or {}
        try:
            return CloudSession(
                user_id=str(user["id"]),
                email=str(user.get("email") or "").lower(),
                access_token=str(data["access_token"]),
                refresh_token=str(data["refresh_token"]),
            )
        except KeyError as exc:
            raise CloudError("The sign-in service sent an unexpected answer. Try again.") from exc


def _friendly_error(path: str, response: httpx.Response) -> str:
    if response.status_code == 429:
        return "Too many attempts. Wait a minute, then try again."
    if "/verify" in path or "grant_type=pkce" in path:
        return "That code is wrong or has expired. Request a new one."
    if "grant_type=refresh_token" in path:
        return "Your cloud session ended. Sign in again."
    try:
        detail = response.json()
        message = detail.get("msg") or detail.get("error_description") or detail.get("message")
    except ValueError:
        message = None
    log.warning("Supabase %s answered %s: %s", path.split("?")[0], response.status_code, message)
    return str(message) if message else "The sign-in service had a problem. Try again in a moment."


# --------------------------------------------------------------------------- local accounts


def _refresh_aad(user: User) -> bytes:
    return f"filevow:cloud-refresh:{user.id}".encode()


def store_refresh_token(user: User, refresh_token: str, vault_key: bytes) -> None:
    user.cloud_refresh_enc = aead.seal(refresh_token.encode(), vault_key, _refresh_aad(user))


def load_refresh_token(user: User, vault_key: bytes) -> str | None:
    if user.cloud_refresh_enc is None:
        return None
    return aead.unseal(user.cloud_refresh_enc, vault_key, _refresh_aad(user)).decode()


def _unique_username(session: Session, email: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9._-]", "", email.split("@")[0])[:40] or "user"
    if len(base) < 3:
        base = f"{base}user"
    candidate, number = base, 1
    while session.scalar(select(User.id).where(User.username == candidate)) is not None:
        number += 1
        candidate = f"{base}{number}"
    return candidate


def link_account(session: Session, cloud: CloudSession, vault_key: bytes, *, ip_address: str | None) -> User:
    """Find or create the local account for a Supabase account and record the sign-in."""
    if not cloud.email:
        raise CloudError("Your account has no e-mail address; sign in another way.")
    user = session.scalar(select(User).where(User.cloud_id == cloud.user_id))
    if user is None:
        first_account = session.scalar(select(User.id).limit(1)) is None
        user = User(
            username=_unique_username(session, cloud.email),
            password_hash=users.unusable_password_hash(),
            role=Role.ADMIN if first_account else Role.USER,
            cloud_id=cloud.user_id,
            email=cloud.email,
        )
        session.add(user)
        session.flush()
        audit.record_event(
            session,
            "USER_REGISTERED",
            actor_user_id=user.id,
            owner_id=user.id,
            target_type="user",
            target_id=user.id,
            ip_address=ip_address,
            details={"username": user.username, "role": str(user.role), "method": "cloud"},
        )
    if not user.is_active:
        raise users.AuthError("This account is turned off. Ask the administrator.")
    user.email = cloud.email
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    store_refresh_token(user, cloud.refresh_token, vault_key)
    audit.record_event(
        session,
        "LOGIN_SUCCESS",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="user",
        target_id=user.id,
        ip_address=ip_address,
        details={"method": "cloud"},
    )
    return user


def verify_step_up(
    session: Session,
    settings: Settings,
    secrets_store: SecretStore,
    vault_key: bytes,
    user: User,
    passphrase: str,
    totp_code: str | None,
) -> None:
    """Confirm a sensitive action for an account that has no FileVow password.

    The signing-key passphrase is the proof: only the person who chose it can unlock the
    key, and checking it works offline. Before a key exists, a recent sign-in counts.
    """
    now = utcnow()
    if trust.active_signing_key(session, user.id) is not None:
        try:
            trust.unlock_user_signing_key(session, settings, secrets_store, user.id, passphrase)
        except trust.SigningKeyError as exc:
            users.record_failed_step_up(session, user)
            raise users.AuthError("Signing-key passphrase is not correct") from exc
    elif user.last_login_at is None or now - user.last_login_at > FRESH_SIGN_IN:
        raise users.AuthError("For your safety, sign out and sign in again to confirm this change")
    if user.mfa_enabled and not (totp_code and users.verify_totp(user, totp_code, vault_key, now)):
        users.record_failed_step_up(session, user)
        raise users.AuthError("Authenticator code is not correct")


# --------------------------------------------------------------------------- usage count


def app_version() -> str:
    import filevow

    return filevow.__version__


def os_name() -> str:
    return f"{platform.system()} {platform.release()}".strip()[:64]


def record_activity(cloud: SupabaseAuth, access_token: str) -> None:
    cloud.rpc("record_activity", access_token, {"app_version": app_version(), "os_name": os_name()})


def report_daily_activity(
    session: Session, cloud: SupabaseAuth, vault_key: bytes, today: date | None = None
) -> int:
    """Tell Supabase each signed-in account used FileVow today (once per day). Returns the count."""
    today = today or utcnow().date()
    accounts = session.scalars(
        select(User).where(
            User.cloud_refresh_enc.is_not(None),
            User.usage_reporting.is_(True),
            User.is_active.is_(True),
        )
    ).all()
    reported = 0
    for user in accounts:
        if user.cloud_reported_on == today:
            continue
        refresh_token = load_refresh_token(user, vault_key)
        if refresh_token is None:
            continue
        try:
            fresh = cloud.refresh(refresh_token)
        except CloudError as exc:
            log.info("daily usage report skipped for account %s: %s", user.id, exc)
            continue
        # Refresh tokens are single-use: keep the new one before doing anything else.
        store_refresh_token(user, fresh.refresh_token, vault_key)
        session.commit()
        try:
            record_activity(cloud, fresh.access_token)
        except CloudError as exc:
            log.info("daily usage report failed for account %s: %s", user.id, exc)
            continue
        user.cloud_reported_on = today
        session.commit()
        reported += 1
    return reported


def delete_cloud_account(session: Session, cloud: SupabaseAuth, user: User, vault_key: bytes) -> None:
    """Delete the Supabase account (and its usage rows) and turn the local account off."""
    refresh_token = load_refresh_token(user, vault_key)
    if refresh_token is None:
        raise CloudError("Sign in again first, then delete the account.")
    fresh = cloud.refresh(refresh_token)
    store_refresh_token(user, fresh.refresh_token, vault_key)
    cloud.rpc("delete_my_account", fresh.access_token)
    user.cloud_refresh_enc = None
    user.is_active = False
    audit.record_event(
        session,
        "USER_DELETED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="user",
        target_id=user.id,
        details={"method": "cloud", "email": user.email},
    )
