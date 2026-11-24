"""Personal workspaces: sign-up, per-user signing keys, folder browsing and isolation."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from filevow.api.app import create_app
from filevow.crypto import keys, signing
from filevow.db.enums import KeyPurpose, RunType
from filevow.services import trust
from filevow.services.baseline import BaselineBuilder, add_monitored_path
from filevow.services.context import AppContext
from filevow.services.monitor import MonitoringService
from filevow.services.records import record_for

API = "/api/v1"
ALICE = ("alice", "alice passphrase 2026")
BOB = ("bob", "bob passphrase 2026!")
KEY_PASSPHRASE = "my signing key passphrase"


@pytest.fixture
def app(ctx: AppContext) -> Iterator[TestClient]:
    ctx.settings.cookie_secure = False
    with TestClient(create_app(ctx)) as client:
        yield client


def new_client(app: TestClient) -> TestClient:
    """A separate browser: its own cookie jar against the same server."""
    return TestClient(app.app)


def sign_up(client: TestClient, username: str, password: str) -> dict[str, object]:
    response = client.post(f"{API}/auth/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    client.headers["X-CSRF-Token"] = client.cookies.get("fv_csrf", "")
    return response.json()  # type: ignore[no-any-return]


def make_site(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "notes.txt").write_text("my private notes\n", encoding="utf-8")
    (root / "budget.csv").write_text("month,amount\njan,100\n", encoding="utf-8")
    return root


def set_up_workspace(client: TestClient, password: str, folder: Path) -> int:
    step_up = {"password": password}
    key = client.post(f"{API}/workspace/signing-key", json={**step_up, "key_passphrase": KEY_PASSPHRASE})
    assert key.status_code == 201, key.text
    path = client.post(f"{API}/paths", json={**step_up, "path": str(folder)})
    assert path.status_code == 201, path.text
    baseline = client.post(
        f"{API}/paths/{path.json()['id']}/baseline", json={**step_up, "key_passphrase": KEY_PASSPHRASE}
    )
    assert baseline.json()["created"] == 2
    return int(path.json()["id"])


def test_first_account_is_admin_and_later_ones_are_users(app: TestClient) -> None:
    assert app.get(f"{API}/auth/options").json() == {
        "allow_registration": True,
        "has_accounts": False,
        "cloud": False,
        "google": False,
        "email": False,
    }
    assert sign_up(app, *ALICE)["role"] == "admin"
    assert sign_up(new_client(app), *BOB)["role"] == "user"


def test_registration_can_be_turned_off(app: TestClient, ctx: AppContext) -> None:
    ctx.settings.allow_registration = False
    assert sign_up(app, *ALICE)["role"] == "admin"  # the very first account is always allowed
    refused = new_client(app).post(f"{API}/auth/register", json={"username": BOB[0], "password": BOB[1]})
    assert refused.status_code == 400 and "turned off" in refused.text


def test_new_user_gets_a_guided_empty_workspace(app: TestClient) -> None:
    sign_up(app, *ALICE)
    status = app.get(f"{API}/workspace").json()
    assert status["has_signing_key"] is False and status["folders"] == 0 and status["protected_files"] == 0


def test_personal_flow_from_sign_up_to_accepting_a_change(app: TestClient, tmp_path: Path) -> None:
    sign_up(app, *ALICE)
    folder = make_site(tmp_path / "alice-docs")
    set_up_workspace(app, ALICE[1], folder)
    assert app.get(f"{API}/workspace").json() | {"key_id": None} == {
        "has_signing_key": True,
        "key_id": None,
        "folders": 1,
        "protected_files": 2,
        "unprotected_folders": 0,
        "mfa_enabled": False,
        "channels": 0,
        "open_changes": 0,
    }

    (folder / "budget.csv").write_text("month,amount\njan,999\n", encoding="utf-8")
    assert app.post(f"{API}/runs").status_code == 202
    change = next(c for c in app.get(f"{API}/changes").json() if c["name"] == "budget.csv")

    wrong = {"password": ALICE[1], "reason": "my edit", "key_passphrase": "not my passphrase"}
    assert app.post(f"{API}/changes/{change['id']}/accept", json=wrong).status_code == 400
    right = {**wrong, "key_passphrase": KEY_PASSPHRASE}
    accepted = app.post(f"{API}/changes/{change['id']}/accept", json=right)
    assert accepted.status_code == 200 and accepted.json()["new_version"] == 2

    backup = app.get(f"{API}/workspace/signing-key/backup")
    assert backup.status_code == 200 and b"ENCRYPTED PRIVATE KEY" in backup.content


def test_workspaces_are_invisible_to_each_other(app: TestClient, tmp_path: Path) -> None:
    alice, bob = app, new_client(app)
    sign_up(alice, *ALICE)
    sign_up(bob, *BOB)
    bob_folder = make_site(tmp_path / "bob-docs")
    bob_path = set_up_workspace(bob, BOB[1], bob_folder)
    (bob_folder / "notes.txt").write_text("changed by bob", encoding="utf-8")
    assert bob.post(f"{API}/runs").status_code == 202
    bob_change = bob.get(f"{API}/changes").json()[0]["id"]
    bob_file = bob.get(f"{API}/files").json()[0]["id"]

    # Alice (even as administrator) sees nothing of Bob's workspace…
    assert alice.get(f"{API}/paths").json() == []
    assert alice.get(f"{API}/files").json() == []
    assert alice.get(f"{API}/changes").json() == []
    assert alice.get(f"{API}/runs").json() == []
    assert all(e["action"] != "CHANGE_DETECTED" for e in alice.get(f"{API}/audit").json())
    assert alice.get(f"{API}/dashboard").json()["protected_files"] == 0
    # …and cannot touch it.
    assert alice.get(f"{API}/changes/{bob_change}").status_code == 404
    assert alice.get(f"{API}/files/{bob_file}").status_code == 404
    assert (
        alice.post(
            f"{API}/changes/{bob_change}/restore", json={"password": ALICE[1], "reason": "nosy"}
        ).status_code
        == 404
    )
    assert (
        alice.patch(f"{API}/paths/{bob_path}", json={"password": ALICE[1], "enabled": False}).status_code
        == 404
    )
    # The same folder cannot be claimed by a second workspace.
    taken = alice.post(f"{API}/paths", json={"password": ALICE[1], "path": str(bob_folder)})
    assert taken.status_code == 400 and "another workspace" in taken.text


def test_a_key_from_another_workspace_is_not_trusted(ctx: AppContext, tmp_path: Path) -> None:
    from filevow.db.enums import Role
    from filevow.services import users

    folder = make_site(tmp_path / "bob-docs")
    with ctx.session() as session:
        alice = users.create_user(session, "alice", ALICE[1], Role.ADMIN)
        bob = users.create_user(session, "bob", BOB[1], Role.USER)
        trust.create_user_signing_key(session, ctx.settings, ctx.secrets, alice, KEY_PASSPHRASE)
        monitored = add_monitored_path(session, ctx.settings, folder, owner_id=bob.id)
        # Alice signs Bob's files with her own key: a record that must never be trusted.
        alice_key, alice_row = trust.unlock_user_signing_key(
            session, ctx.settings, ctx.secrets, alice.id, KEY_PASSPHRASE
        )
        BaselineBuilder(session, ctx.settings, ctx.vault(), alice_key, alice_row).protect(monitored)
    result = MonitoringService(ctx).verify(RunType.MANUAL)
    assert {i.outcome.value for i in result.summary.issues} == {"KEY_UNTRUSTED"}


def test_folder_browser_lists_folders_and_hides_filevow_data(
    app: TestClient, ctx: AppContext, tmp_path: Path
) -> None:
    sign_up(app, *ALICE)
    make_site(tmp_path / "docs")
    listing = app.get(f"{API}/fs/list", params={"path": str(tmp_path)}).json()
    names = {e["name"]: e["kind"] for e in listing["entries"]}
    assert names["docs"] == "folder"
    home = app.get(f"{API}/fs/list", params={"path": str(ctx.settings.home)}).json()
    assert {e["name"] for e in home["entries"]}.isdisjoint({"data", "vault", "logs", "keys", "secrets"})
    inside = app.get(f"{API}/fs/list", params={"path": str(tmp_path / "docs")}).json()
    assert {e["name"] for e in inside["entries"]} == {"budget.csv", "notes.txt"}
    assert inside["parent"] == str(tmp_path)
    drives = app.get(f"{API}/fs/list").json()
    assert drives["path"] is None and all(e["kind"] == "drive" for e in drives["entries"])
    assert app.get(f"{API}/fs/places").status_code == 200


def test_record_signed_by_own_key_is_trusted(ctx: AppContext, tmp_path: Path) -> None:
    from filevow.db.enums import Role
    from filevow.services import users

    folder = make_site(tmp_path / "docs")
    with ctx.session() as session:
        alice = users.create_user(session, "alice", ALICE[1], Role.ADMIN)
        trust.create_user_signing_key(session, ctx.settings, ctx.secrets, alice, KEY_PASSPHRASE)
        monitored = add_monitored_path(session, ctx.settings, folder, owner_id=alice.id)
        private_key, row = trust.unlock_user_signing_key(
            session, ctx.settings, ctx.secrets, alice.id, KEY_PASSPHRASE
        )
        BaselineBuilder(session, ctx.settings, ctx.vault(), private_key, row).protect(monitored)
        baseline = monitored.baselines[0]
        assert signing.verify_payload(private_key.public_key(), record_for(baseline), baseline.rsa_signature)
        assert row.purpose is KeyPurpose.BASELINE and Path(row.key_file or "").is_file()
        assert keys.fingerprint(private_key.public_key()) in trust.pinned_fingerprints(ctx.secrets)
    assert MonitoringService(ctx).verify(RunType.MANUAL).summary.issues == []
