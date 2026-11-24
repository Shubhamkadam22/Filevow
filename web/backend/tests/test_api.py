from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from filevow.api.app import create_app
from filevow.db.enums import KeyPurpose, Role
from filevow.db.models import MonitoredPath, SigningKey
from filevow.services import users
from tests.conftest import PASSPHRASE, Protected

API = "/api/v1"
ADMIN_PASSWORD = "admin passphrase 2026"
STEP_UP = {"password": ADMIN_PASSWORD}


@pytest.fixture
def client(protected: Protected, key_file: Path) -> Iterator[TestClient]:
    ctx = protected.ctx
    ctx.settings.baseline_key_path = key_file
    ctx.settings.cookie_secure = False  # the test client speaks plain http
    with ctx.session() as session:
        admin = users.create_user(session, "admin", ADMIN_PASSWORD, Role.ADMIN)
        users.create_user(session, "analyst", "analyst passphrase 1", Role.ANALYST)
        users.create_user(session, "viewer", "viewer passphrase 12", Role.VIEWER)
        # The demo site and its signing key live in the admin's workspace.
        session.execute(update(MonitoredPath).values(owner_id=admin.id))
        session.execute(
            update(SigningKey)
            .where(SigningKey.purpose == KeyPurpose.BASELINE)
            .values(owner_id=admin.id, key_file=str(key_file))
        )
    with TestClient(create_app(ctx)) as test_client:
        yield test_client


def login(
    client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD, code: str | None = None
):  # type: ignore[no-untyped-def]
    response = client.post(
        f"{API}/auth/login", json={"username": username, "password": password, "totp_code": code}
    )
    if response.status_code == 200:
        client.headers["X-CSRF-Token"] = client.cookies.get("fv_csrf", "")
    return response


def change_id_for(client: TestClient, name: str) -> int:
    changes = client.get(f"{API}/changes").json()
    return next(c["id"] for c in changes if c["name"] == name)


def run_now(client: TestClient) -> None:
    assert client.post(f"{API}/runs").status_code == 202  # background task runs before the call returns


# --------------------------------------------------------------------------- authentication


def test_login_sets_secure_cookie_session(client: TestClient) -> None:
    response = login(client)
    assert response.status_code == 200 and response.json()["role"] == "admin"
    assert (
        "HttpOnly" in response.headers.get("set-cookie", "")
        or "httponly" in response.headers.get("set-cookie", "").lower()
    )
    assert client.get(f"{API}/auth/me").json()["username"] == "admin"


def test_wrong_password_and_rate_limit(client: TestClient) -> None:
    for _ in range(5):
        assert login(client, password="not the password").status_code == 401
    assert login(client).status_code == 429  # sixth attempt inside a minute


def test_requests_without_a_session_are_refused(client: TestClient) -> None:
    assert client.get(f"{API}/dashboard").status_code == 401


def test_cookie_sessions_need_the_csrf_header(client: TestClient) -> None:
    login(client, "analyst", "analyst passphrase 1")
    del client.headers["X-CSRF-Token"]
    assert client.post(f"{API}/runs").status_code == 403


def test_refresh_and_logout(client: TestClient) -> None:
    login(client)
    assert client.post(f"{API}/auth/refresh").status_code == 200
    client.headers["X-CSRF-Token"] = client.cookies.get("fv_csrf", "")
    assert client.post(f"{API}/auth/logout").status_code == 204
    assert client.get(f"{API}/auth/me").status_code == 401


def test_mfa_enrolment_and_login(client: TestClient) -> None:
    login(client)
    setup = client.post(f"{API}/auth/mfa/setup").json()
    assert setup["qr_svg"].startswith("<?xml") or "<svg" in setup["qr_svg"]
    codes = client.post(f"{API}/auth/mfa/confirm", json={"code": pyotp.TOTP(setup["secret"]).now()}).json()
    assert len(codes) == 8

    client.cookies.clear()
    response = login(client)
    assert response.status_code == 401 and response.json()["detail"]["code"] == "mfa_required"
    assert login(client, code=codes[0]).status_code == 200  # recovery code


def test_security_headers(client: TestClient) -> None:
    response = client.get(f"{API}/health")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


# --------------------------------------------------------------------------- roles


def test_roles_limit_what_can_be_decided(client: TestClient, protected: Protected) -> None:
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    login(client)
    run_now(client)
    change_id = change_id_for(client, "index.html")
    body = {**STEP_UP, "reason": "release", "key_passphrase": PASSPHRASE.decode()}

    login(client, "analyst", "analyst passphrase 1")
    assert client.post(f"{API}/changes/{change_id}/accept", json=body).status_code == 403

    login(client, "viewer", "viewer passphrase 12")
    assert client.post(f"{API}/changes/{change_id}/reject", json={"reason": "fp"}).status_code == 403
    assert client.get(f"{API}/changes/{change_id}").status_code == 404  # someone else's workspace


# --------------------------------------------------------------------------- the review flow


def test_detect_review_and_accept_over_http(client: TestClient, protected: Protected) -> None:
    (protected.site / "index.html").write_text("<h1>Hello, visitor</h1>\n", encoding="utf-8")
    login(client)
    run_now(client)

    dashboard = client.get(f"{API}/dashboard").json()
    assert dashboard["open_changes"] == 1 and dashboard["layers"]["content_ok"] == 2

    change_id = change_id_for(client, "index.html")
    detail = client.get(f"{API}/changes/{change_id}").json()
    assert detail["event_type"] == "FILE_MODIFIED" and detail["layers"]["signature"] is True
    assert detail["diff"]["lines"][0] == {
        "kind": "mod",
        "old_number": 1,
        "new_number": 1,
        "old_text": "<h1>Hello</h1>",
        "new_text": "<h1>Hello, visitor</h1>",
    }

    wrong = {**STEP_UP, "reason": "release 2", "key_passphrase": "wrong passphrase"}
    assert client.post(f"{API}/changes/{change_id}/accept", json=wrong).status_code == 400
    bad_step_up = {"password": "nope", "reason": "release 2", "key_passphrase": PASSPHRASE.decode()}
    assert client.post(f"{API}/changes/{change_id}/accept", json=bad_step_up).status_code == 401

    body = {
        **STEP_UP,
        "reason": "release 2",
        "key_passphrase": PASSPHRASE.decode(),
        "expected_sha256": detail["observed_sha256"],
    }
    decision = client.post(f"{API}/changes/{change_id}/accept", json=body)
    assert decision.status_code == 200 and decision.json()["new_version"] == 2

    assert client.get(f"{API}/changes").json() == []
    assert all(a["status"] == "resolved" for a in client.get(f"{API}/alerts?state=all").json())
    run_now(client)
    assert client.get(f"{API}/changes").json() == []


def test_restore_and_bulk_restore(client: TestClient, protected: Protected) -> None:
    originals = {name: (protected.site / name).read_bytes() for name in ("index.html", "about.html")}
    for name in originals:
        (protected.site / name).write_text("defaced", encoding="utf-8")
    login(client)
    run_now(client)

    first = change_id_for(client, "index.html")
    assert (
        client.post(f"{API}/changes/{first}/restore", json={**STEP_UP, "reason": "defacement"}).status_code
        == 200
    )

    second = change_id_for(client, "about.html")
    bulk = client.post(
        f"{API}/changes/bulk",
        json={**STEP_UP, "action": "restore", "ids": [second, 9999], "reason": "defacement"},
    )
    assert bulk.status_code == 200
    assert [r["change_id"] for r in bulk.json()["results"]] == [second]
    assert "9999" in bulk.json()["skipped"]
    for name, content in originals.items():
        assert (protected.site / name).read_bytes() == content


def test_paths_files_runs_and_audit(client: TestClient, protected: Protected, tmp_path: Path) -> None:
    login(client)
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "settings.ini").write_text("[app]\nport=80\n", encoding="utf-8")

    created = client.post(f"{API}/paths", json={**STEP_UP, "path": str(extra), "severity": "critical"})
    assert created.status_code == 201
    baseline = client.post(
        f"{API}/paths/{created.json()['id']}/baseline",
        json={**STEP_UP, "key_passphrase": PASSPHRASE.decode()},
    )
    assert baseline.json()["created"] == 1

    files = client.get(f"{API}/files").json()
    assert len(files) == 4
    detail = client.get(f"{API}/files/{files[0]['id']}").json()
    assert detail["versions"][0]["version"] == 1

    run_now(client)
    run = client.get(f"{API}/runs").json()[0]
    assert run["signed"] is True
    assert client.get(f"{API}/runs/{run['id']}").json()["signature_valid"] is True

    chain = client.get(f"{API}/audit/verify").json()
    assert chain["intact"] is True and chain["checkpoint_problems"] == []
    export = client.get(f"{API}/audit/export.csv")
    assert export.status_code == 200 and "PATH_ADDED" in export.text


def test_admin_user_and_channel_management(client: TestClient) -> None:
    login(client)
    created = client.post(
        f"{API}/users",
        json={**STEP_UP, "username": "carol", "new_password": "carol passphrase 9", "role": "analyst"},
    )
    assert created.status_code == 201
    insecure = {**STEP_UP, "name": "chat", "type": "webhook", "config": {"url": "http://example.com/hook"}}
    assert client.post(f"{API}/channels", json=insecure).status_code == 400
    secure = {**insecure, "config": {"url": "https://hooks.example.com/abc/secret-token"}}
    channel = client.post(f"{API}/channels", json=secure).json()
    assert channel["target"] == "hooks.example.com"  # the secret path is never shown
    me = client.get(f"{API}/auth/me").json()
    demote_self = client.patch(f"{API}/users/{me['id']}", json={**STEP_UP, "role": "viewer"})
    assert demote_self.status_code == 400


def test_live_events_websocket(client: TestClient) -> None:
    login(client)
    with client.websocket_connect("/api/v1/events") as socket:
        message = socket.receive_json()
    assert message["type"] == "state" and "open_changes" in message


def test_keys_and_system_info(client: TestClient) -> None:
    login(client)
    keys_list = client.get(f"{API}/keys").json()
    purposes = {k["purpose"]: k for k in keys_list}
    assert purposes["baseline"]["pinned"] is True and purposes["agent"]["pinned"] is False
    info = client.get(f"{API}/system").json()
    assert info["signing_key_configured"] is True and info["database"] == "sqlite"
