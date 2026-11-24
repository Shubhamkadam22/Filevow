from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest
from sqlalchemy import select

from filevow.core.hashing import sha256_file
from filevow.core.paths import normalize_path
from filevow.db.enums import BaselineStatus, ReviewStatus
from filevow.db.models import AuditEntry, ChangeEvent, FileBaseline
from filevow.services import trust
from filevow.services.review import ConflictError, ReviewError, ReviewService
from tests.conftest import PASSPHRASE, Protected, outcomes, run_verification

ADMIN = None  # user accounts arrive with the API; the CLI acts as "system"


def _change_for(protected: Protected, name: str) -> int:
    with protected.ctx.session() as session:
        for event in session.scalars(select(ChangeEvent)):
            if Path(event.file_path).name == name and event.review_status == ReviewStatus.PENDING_REVIEW:
                return event.id
    raise AssertionError(f"no open change for {name}")


def _service(session, protected: Protected) -> ReviewService:  # type: ignore[no-untyped-def]
    ctx = protected.ctx
    return ReviewService(
        session, ctx.settings, ctx.vault(), trust.load_trusted_baseline_keys(session, ctx.secrets)
    )


def _accept(protected: Protected, change_id: int, key_file: Path, expected: str | None = None):  # type: ignore[no-untyped-def]
    with protected.ctx.session() as session:
        private_key, signing_key = trust.unlock_baseline_key(
            session, protected.ctx.secrets, key_file, PASSPHRASE
        )
        return _service(session, protected).accept(
            change_id,
            actor_user_id=ADMIN,
            reason="planned release",
            private_key=private_key,
            signing_key=signing_key,
            expected_sha256=expected,
        )


def test_accept_creates_a_new_signed_version(protected: Protected, key_file: Path) -> None:
    target = protected.site / "index.html"
    target.write_text("<h1>Release 2</h1>", encoding="utf-8")
    run_verification(protected.ctx)

    result = _accept(protected, _change_for(protected, "index.html"), key_file)
    assert result.new_version == 2
    assert outcomes(run_verification(protected.ctx)) == {}
    with protected.ctx.session() as session:
        baseline = session.scalar(
            select(FileBaseline).where(FileBaseline.file_path == normalize_path(target))
        )
        assert baseline.current_version == 2 and baseline.sha256 == sha256_file(target)
        assert [v.version for v in baseline.versions] == [1, 2]
        assert session.scalar(select(AuditEntry).where(AuditEntry.action == "CHANGE_ACCEPTED")) is not None


def test_accept_refuses_content_the_reviewer_did_not_see(protected: Protected, key_file: Path) -> None:
    target = protected.site / "index.html"
    target.write_text("version the reviewer saw", encoding="utf-8")
    run_verification(protected.ctx)
    change_id = _change_for(protected, "index.html")
    target.write_text("swapped after review", encoding="utf-8")
    with pytest.raises(ConflictError):
        _accept(protected, change_id, key_file)


def test_accept_unknown_file_starts_protecting_it(protected: Protected, key_file: Path) -> None:
    (protected.site / "new-page.html").write_text("<p>new</p>", encoding="utf-8")
    run_verification(protected.ctx)
    result = _accept(protected, _change_for(protected, "new-page.html"), key_file)
    assert result.new_version == 1
    assert outcomes(run_verification(protected.ctx)) == {}


def test_accept_deletion_stops_checking_the_file(protected: Protected, key_file: Path) -> None:
    (protected.site / "about.html").unlink()
    run_verification(protected.ctx)
    _accept(protected, _change_for(protected, "about.html"), key_file)
    assert outcomes(run_verification(protected.ctx)) == {}
    with protected.ctx.session() as session:
        statuses = {Path(b.file_path).name: b.status for b in session.scalars(select(FileBaseline))}
    assert statuses["about.html"] is BaselineStatus.DELETED


def test_restore_puts_back_the_exact_approved_bytes(protected: Protected) -> None:
    target = protected.site / "index.html"
    original = target.read_bytes()
    target.write_text("<h1>Defaced</h1>", encoding="utf-8")
    run_verification(protected.ctx)

    with protected.ctx.session() as session:
        result = _service(session, protected).restore(
            _change_for(protected, "index.html"), actor_user_id=ADMIN, reason="defacement"
        )
    assert result.action == "restored"
    assert target.read_bytes() == original
    assert outcomes(run_verification(protected.ctx)) == {}


def test_restore_a_deleted_file(protected: Protected) -> None:
    target = protected.site / "js" / "app.js"
    original = target.read_bytes()
    target.unlink()
    run_verification(protected.ctx)
    with protected.ctx.session() as session:
        _service(session, protected).restore(
            _change_for(protected, "app.js"), actor_user_id=ADMIN, reason="oops"
        )
    assert target.read_bytes() == original


def test_restore_repairs_a_tampered_record(protected: Protected) -> None:
    """Scenario 2 recovery: file and database hash were both changed by an attacker."""
    target = protected.site / "index.html"
    original = target.read_bytes()
    target.write_text("<h1>Hacked</h1>", encoding="utf-8")
    with protected.ctx.session() as session:
        baseline = session.scalar(
            select(FileBaseline).where(FileBaseline.file_path == normalize_path(target))
        )
        baseline.sha256 = sha256_file(target)
    assert outcomes(run_verification(protected.ctx)) == {"index.html": "RECORD_TAMPERED"}

    with protected.ctx.session() as session:
        _service(session, protected).restore(
            _change_for(protected, "index.html"), actor_user_id=ADMIN, reason="tamper"
        )
    assert target.read_bytes() == original
    assert outcomes(run_verification(protected.ctx)) == {}


@pytest.mark.skipif(sys.platform != "win32", reason="read-only attribute semantics are Windows specific")
def test_restore_puts_back_the_read_only_flag(protected: Protected) -> None:
    target = protected.site / "about.html"
    target.chmod(stat.S_IREAD)
    with protected.ctx.session() as session:
        baseline = session.scalar(
            select(FileBaseline).where(FileBaseline.file_path == normalize_path(target))
        )
    try:
        run_verification(protected.ctx)
        with protected.ctx.session() as session:
            _service(session, protected).restore(
                _change_for(protected, "about.html"), actor_user_id=ADMIN, reason="permissions"
            )
        assert baseline.permissions == "rw" and target.stat().st_mode & stat.S_IWRITE
    finally:
        target.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_quarantine_removes_an_unknown_file_but_keeps_evidence(protected: Protected) -> None:
    intruder = protected.site / "upload.php"
    intruder.write_text("<?php echo 'unexpected'; ?>", encoding="utf-8")
    content = intruder.read_bytes()
    run_verification(protected.ctx)

    with protected.ctx.session() as session:
        _service(session, protected).quarantine(
            _change_for(protected, "upload.php"), actor_user_id=ADMIN, reason="not ours"
        )
        evidence_sha = session.scalars(select(ChangeEvent)).one().evidence.sha256
    assert not intruder.exists()
    assert protected.ctx.vault().load(evidence_sha) == content
    assert outcomes(run_verification(protected.ctx)) == {}


def test_reject_keeps_the_baseline_so_the_change_is_found_again(protected: Protected) -> None:
    (protected.site / "index.html").write_text("still different", encoding="utf-8")
    run_verification(protected.ctx)
    with protected.ctx.session() as session:
        _service(session, protected).reject(
            _change_for(protected, "index.html"), actor_user_id=ADMIN, reason="fp"
        )
    assert outcomes(run_verification(protected.ctx)) == {"index.html": "FILE_MODIFIED"}
    with protected.ctx.session() as session:
        assert len(session.scalars(select(ChangeEvent)).all()) == 2


def test_escalated_changes_stay_open(protected: Protected) -> None:
    (protected.site / "index.html").write_text("suspicious", encoding="utf-8")
    run_verification(protected.ctx)
    change_id = _change_for(protected, "index.html")
    with protected.ctx.session() as session:
        _service(session, protected).escalate(change_id, actor_user_id=ADMIN, reason="needs security team")
    run_verification(protected.ctx)
    with protected.ctx.session() as session:
        event = session.get(ChangeEvent, change_id)
        assert event.review_status is ReviewStatus.ESCALATED and event.occurrence_count == 2


def test_a_closed_change_cannot_be_decided_twice(protected: Protected) -> None:
    (protected.site / "index.html").write_text("x", encoding="utf-8")
    run_verification(protected.ctx)
    change_id = _change_for(protected, "index.html")
    with protected.ctx.session() as session:
        service = _service(session, protected)
        service.reject(change_id, actor_user_id=ADMIN, reason="fp")
        with pytest.raises(ReviewError):
            service.restore(change_id, actor_user_id=ADMIN, reason="again")
