"""Cloud sign-in (Supabase): e-mail codes, Google with PKCE, step-up, usage count, deletion.

Supabase is replaced by an in-process fake behind httpx.MockTransport, so these tests
check FileVow's side of every exchange without any network access.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from filevow.api.app import create_app
from filevow.db.base import utcnow
from filevow.db.models import User
from filevow.services import cloud
from filevow.services.context import AppContext

API = "/api/v1"
SUPABASE = "https://example-project.supabase.co"
GOOD_CODE = "123456"
KEY_PASSPHRASE = "my signing key passphrase"


class FakeSupabase:
    """Just enough of Supabase Auth + PostgREST RPC to exercise FileVow."""

    def __init__(self) -> None:
        self.ids: dict[str, str] = {}
        self.codes_sent: list[str] = []
        self.challenge: str | None = None
        self.google_email = "gmail.user@gmail.com"
        self.live_refresh: dict[str, str] = {}  # refresh token -> email
        self.activity: list[tuple[str, dict[str, object]]] = []
        self.deleted: list[str] = []
        self.counter = 0

    def _session(self, email: str) -> httpx.Response:
        self.counter += 1
        user_id = self.ids.setdefault(email, str(uuid.uuid4()))
        refresh = f"refresh-{self.counter}"
        self.live_refresh[refresh] = email
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{email}-{self.counter}",
                "refresh_token": refresh,
                "user": {"id": user_id, "email": email},
            },
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["apikey"] == "anon-test-key"
        body = json.loads(request.content or b"{}")
        path, query = request.url.path, parse_qs(request.url.query.decode())
        if path == "/auth/v1/otp":
            self.codes_sent.append(body["email"])
            return httpx.Response(200, json={})
        if path == "/auth/v1/verify":
            if body["token"] != GOOD_CODE:
                return httpx.Response(403, json={"msg": "Token has expired or is invalid"})
            return self._session(body["email"])
        if path == "/auth/v1/token" and query["grant_type"] == ["pkce"]:
            digest = hashlib.sha256(body["code_verifier"].encode()).digest()
            if (
                body["auth_code"] != "google-code"
                or base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != self.challenge
            ):
                return httpx.Response(400, json={"msg": "invalid flow state"})
            return self._session(self.google_email)
        if path == "/auth/v1/token" and query["grant_type"] == ["refresh_token"]:
            email = self.live_refresh.pop(body["refresh_token"], None)  # single use, like Supabase
            if email is None:
                return httpx.Response(400, json={"msg": "Invalid Refresh Token"})
            return self._session(email)
        if path.startswith("/rest/v1/rpc/"):
            token = request.headers.get("Authorization", "")
            assert token.startswith("Bearer access-"), token
            name = path.rsplit("/", 1)[1]
            if name == "record_activity":
                self.activity.append((token, body))
            elif name == "delete_my_account":
                self.deleted.append(token)
            return httpx.Response(204)
        return httpx.Response(404, json={"msg": f"unexpected {path}"})


@pytest.fixture
def fake() -> FakeSupabase:
    return FakeSupabase()


@pytest.fixture
def app(ctx: AppContext, fake: FakeSupabase) -> Iterator[TestClient]:
    ctx.settings.cookie_secure = False
    ctx.settings.supabase_url = SUPABASE
    ctx.settings.supabase_anon_key = "anon-test-key"
    ctx.cloud_transport = httpx.MockTransport(fake.handler)
    with TestClient(create_app(ctx)) as client:
        yield client


def email_sign_in(client: TestClient, email: str) -> dict[str, object]:
    assert client.post(f"{API}/auth/cloud/email/start", json={"email": email}).status_code == 204
    response = client.post(f"{API}/auth/cloud/email/verify", json={"email": email, "code": GOOD_CODE})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = client.cookies.get("fv_csrf", "")
    return response.json()  # type: ignore[no-any-return]


def test_options_offer_cloud_sign_in_and_block_password_sign_up(app: TestClient) -> None:
    options = app.get(f"{API}/auth/options").json()
    assert options == {
        "allow_registration": False,
        "has_accounts": False,
        "cloud": True,
        "google": True,
        "email": True,
    }

    response = app.post(
        f"{API}/auth/register", json={"username": "someone", "password": "long enough password"}
    )
    assert response.status_code == 403


def test_email_code_creates_the_account_and_signs_in(app: TestClient, fake: FakeSupabase) -> None:
    user = email_sign_in(app, "Priya.Sharma@Example.com ")

    assert fake.codes_sent == ["priya.sharma@example.com"]
    assert user["email"] == "priya.sharma@example.com"
    assert user["username"] == "priya.sharma"
    assert user["is_cloud"] is True
    assert user["role"] == "admin"  # first account on this computer
    assert app.get(f"{API}/auth/me").json()["id"] == user["id"]
    assert len(fake.activity) == 1  # signing in counts as today's use

    # Signing in again finds the same account instead of creating a new one.
    again = email_sign_in(TestClient(app.app), "priya.sharma@example.com")
    assert again["id"] == user["id"]


def test_second_person_gets_their_own_regular_account(app: TestClient) -> None:
    email_sign_in(app, "first@example.com")
    second = email_sign_in(TestClient(app.app), "second@example.com")
    assert second["role"] == "user"


def test_wrong_code_is_refused_with_a_clear_message(app: TestClient) -> None:
    app.post(f"{API}/auth/cloud/email/start", json={"email": "a@example.com"})
    response = app.post(f"{API}/auth/cloud/email/verify", json={"email": "a@example.com", "code": "000000"})
    assert response.status_code == 400
    assert "wrong or has expired" in response.json()["detail"]


def test_invalid_email_is_refused_before_calling_supabase(app: TestClient, fake: FakeSupabase) -> None:
    response = app.post(f"{API}/auth/cloud/email/start", json={"email": "not-an-email"})
    assert response.status_code == 400
    assert fake.codes_sent == []


def test_google_sign_in_with_pkce(app: TestClient, fake: FakeSupabase) -> None:
    start = app.get(f"{API}/auth/cloud/google", follow_redirects=False)
    assert start.status_code == 303
    target = urlparse(start.headers["location"])
    params = parse_qs(target.query)
    assert f"{target.scheme}://{target.netloc}{target.path}" == f"{SUPABASE}/auth/v1/authorize"
    assert params["provider"] == ["google"]
    assert params["code_challenge_method"] == ["s256"]
    assert params["redirect_to"] == ["http://testserver/api/v1/auth/cloud/callback"]
    fake.challenge = params["code_challenge"][0]

    done = app.get(f"{API}/auth/cloud/callback?code=google-code", follow_redirects=False)
    assert done.status_code == 303
    assert done.headers["location"] == "/"
    me = app.get(f"{API}/auth/me").json()
    assert me["email"] == "gmail.user@gmail.com"
    assert me["is_cloud"] is True


def test_google_callback_without_the_pkce_cookie_is_refused(app: TestClient, fake: FakeSupabase) -> None:
    response = TestClient(app.app).get(f"{API}/auth/cloud/callback?code=google-code", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/?signin_error=")


def test_cancelled_google_sign_in_returns_to_the_sign_in_page(app: TestClient) -> None:
    response = app.get(
        f"{API}/auth/cloud/callback?error=access_denied&error_description=Cancelled", follow_redirects=False
    )
    assert response.headers["location"] == "/?signin_error=Cancelled"


def test_cloud_sessions_last_thirty_days(app: TestClient) -> None:
    app.post(f"{API}/auth/cloud/email/start", json={"email": "keep@example.com"})
    response = app.post(
        f"{API}/auth/cloud/email/verify", json={"email": "keep@example.com", "code": GOOD_CODE}
    )
    refresh_cookie = next(h for h in response.headers.get_list("set-cookie") if h.startswith("fv_refresh="))
    assert f"Max-Age={30 * 24 * 3600}" in refresh_cookie


def test_signing_key_passphrase_confirms_sensitive_actions(app: TestClient, tmp_path: Path) -> None:
    email_sign_in(app, "owner@example.com")
    # No key yet: a fresh sign-in is enough to create one (there is no password to ask for).
    key = app.post(f"{API}/workspace/signing-key", json={"key_passphrase": KEY_PASSPHRASE})
    assert key.status_code == 201, key.text

    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("hello", encoding="utf-8")
    wrong = app.post(f"{API}/paths", json={"password": "not my passphrase", "path": str(folder)})
    assert wrong.status_code == 401
    assert "passphrase is not correct" in wrong.json()["detail"]

    right = app.post(f"{API}/paths", json={"password": KEY_PASSPHRASE, "path": str(folder)})
    assert right.status_code == 201, right.text
    baseline = app.post(
        f"{API}/paths/{right.json()['id']}/baseline",
        json={"password": KEY_PASSPHRASE, "key_passphrase": KEY_PASSPHRASE},
    )
    assert baseline.status_code == 200, baseline.text


def test_stale_sign_in_without_a_key_must_sign_in_again(app: TestClient, ctx: AppContext) -> None:
    user = email_sign_in(app, "late@example.com")
    with ctx.session() as session:
        account = session.get(User, user["id"])
        assert account is not None
        account.last_login_at = utcnow() - timedelta(hours=2)
    response = app.post(f"{API}/workspace/signing-key", json={"key_passphrase": KEY_PASSPHRASE})
    assert response.status_code == 401
    assert "sign in again" in response.json()["detail"]


def test_cloud_accounts_have_no_password_to_change(app: TestClient) -> None:
    email_sign_in(app, "nopass@example.com")
    response = app.post(
        f"{API}/auth/password", json={"password": "x", "new_password": "a brand new password"}
    )
    assert response.status_code == 400


def test_password_sign_in_never_works_for_a_cloud_account(app: TestClient) -> None:
    user = email_sign_in(app, "cloudonly@example.com")
    response = TestClient(app.app).post(
        f"{API}/auth/login", json={"username": user["username"], "password": "anything at all here"}
    )
    assert response.status_code == 401


def test_daily_usage_report_runs_once_per_day(app: TestClient, ctx: AppContext, fake: FakeSupabase) -> None:
    email_sign_in(app, "daily@example.com")
    client = ctx.cloud()
    assert client is not None
    tomorrow = date.today() + timedelta(days=1)
    with ctx.session() as session:
        assert cloud.report_daily_activity(session, client, ctx.vault_key(), today=tomorrow) == 1
        assert cloud.report_daily_activity(session, client, ctx.vault_key(), today=tomorrow) == 0
    assert len(fake.activity) == 2  # sign-in + tomorrow
    assert fake.activity[-1][1]["app_version"]
    # The rotated refresh token was kept, so the next day still works.
    with ctx.session() as session:
        assert (
            cloud.report_daily_activity(session, client, ctx.vault_key(), today=tomorrow + timedelta(days=1))
            == 1
        )


def test_usage_reporting_can_be_turned_off(app: TestClient, ctx: AppContext, fake: FakeSupabase) -> None:
    email_sign_in(app, "private@example.com")
    response = app.post(f"{API}/auth/cloud/preferences", json={"usage_reporting": False})
    assert response.json()["usage_reporting"] is False
    client = ctx.cloud()
    assert client is not None
    with ctx.session() as session:
        assert (
            cloud.report_daily_activity(
                session, client, ctx.vault_key(), today=date.today() + timedelta(days=3)
            )
            == 0
        )


def test_delete_account_removes_the_cloud_account_and_signs_out(
    app: TestClient, ctx: AppContext, fake: FakeSupabase
) -> None:
    user = email_sign_in(app, "leaving@example.com")
    response = app.post(f"{API}/auth/cloud/delete-account", json={})  # fresh sign-in, no key yet
    assert response.status_code == 204, response.text
    assert len(fake.deleted) == 1
    assert app.get(f"{API}/auth/me").status_code == 401
    with ctx.session() as session:
        account = session.scalar(select(User).where(User.id == user["id"]))
        assert account is not None and account.is_active is False


def test_without_supabase_settings_cloud_routes_are_off(ctx: AppContext) -> None:
    ctx.settings.cookie_secure = False
    with TestClient(create_app(ctx)) as client:
        assert client.get(f"{API}/auth/options").json()["cloud"] is False
        assert (
            client.post(f"{API}/auth/cloud/email/start", json={"email": "a@example.com"}).status_code == 404
        )
