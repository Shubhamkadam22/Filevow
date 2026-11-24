"""Security scenarios from chapter 16 of the manual, run against the real engine."""

from __future__ import annotations

import shutil
import stat
from pathlib import Path

from sqlalchemy import select

from filevow.core.paths import normalize_path
from filevow.crypto import keys, signing
from filevow.db.enums import BaselineStatus, KeyPurpose, ObjectKind, Outcome, ReviewStatus, Severity
from filevow.db.models import ChangeEvent, FileBaseline, FileVersion, SigningKey, VerificationRun
from filevow.services import trust
from filevow.services.records import record_for
from tests.conftest import Protected, outcomes, run_verification


def _baseline(session, path: Path) -> FileBaseline:  # type: ignore[no-untyped-def]
    return session.scalar(select(FileBaseline).where(FileBaseline.file_path == normalize_path(path)))


def test_untouched_files_verify_ok(protected: Protected) -> None:
    summary = run_verification(protected.ctx)
    assert summary.files_checked == 3  # the .log file is excluded
    assert summary.issues == []


def test_modified_file_is_flagged_with_evidence(protected: Protected) -> None:
    target = protected.site / "index.html"
    target.write_text("<h1>Hacked</h1>\n", encoding="utf-8")

    summary = run_verification(protected.ctx)
    assert outcomes(summary) == {"index.html": "FILE_MODIFIED"}

    with protected.ctx.session() as session:
        event = session.scalar(select(ChangeEvent))
        assert event.review_status is ReviewStatus.PENDING_REVIEW
        assert event.severity is Severity.HIGH
        assert event.evidence is not None and event.evidence.kind is ObjectKind.EVIDENCE
        assert protected.ctx.vault().load(event.evidence.sha256) == target.read_bytes()
        assert _baseline(session, target).status is BaselineStatus.PENDING_REVIEW


def test_repeat_detection_updates_the_same_change(protected: Protected) -> None:
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    run_verification(protected.ctx)
    run_verification(protected.ctx)
    with protected.ctx.session() as session:
        events = session.scalars(select(ChangeEvent)).all()
    assert len(events) == 1 and events[0].occurrence_count == 2


def test_changes_are_never_accepted_automatically(protected: Protected) -> None:
    target = protected.site / "index.html"
    target.write_text("changed", encoding="utf-8")
    for _ in range(3):
        assert outcomes(run_verification(protected.ctx)) == {"index.html": "FILE_MODIFIED"}


def test_deleted_file_is_flagged_and_still_restorable(protected: Protected) -> None:
    (protected.site / "about.html").unlink()
    summary = run_verification(protected.ctx)
    assert outcomes(summary) == {"about.html": "FILE_DELETED"}
    assert summary.issues[0].mirror_valid is True


def test_file_replaced_by_folder_is_a_type_change(protected: Protected) -> None:
    target = protected.site / "about.html"
    target.unlink()
    target.mkdir()
    assert outcomes(run_verification(protected.ctx)) == {"about.html": "TYPE_CHANGED"}


def test_permission_change_with_same_content(protected: Protected) -> None:
    target = protected.site / "about.html"
    target.chmod(stat.S_IREAD)
    try:
        assert outcomes(run_verification(protected.ctx)) == {"about.html": "PERMISSION_CHANGED"}
    finally:
        target.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_unknown_files_are_reported_with_severity_by_type(protected: Protected) -> None:
    (protected.site / "upload.php").write_text("<?php echo 'hello'; ?>", encoding="utf-8")
    (protected.site / "notes.txt").write_text("notes", encoding="utf-8")
    (protected.site / "debug.log").write_text("excluded", encoding="utf-8")

    summary = run_verification(protected.ctx)
    assert outcomes(summary) == {"upload.php": "UNKNOWN_FILE_CREATED", "notes.txt": "UNKNOWN_FILE_CREATED"}
    with protected.ctx.session() as session:
        severity = {Path(e.file_path).name: e.severity for e in session.scalars(select(ChangeEvent))}
    assert severity == {"upload.php": Severity.HIGH, "notes.txt": Severity.MEDIUM}


def test_editing_the_stored_hash_is_caught_by_the_signature(protected: Protected) -> None:
    """Scenario 2: attacker changes the file AND its hash in the database."""
    target = protected.site / "index.html"
    target.write_text("<h1>Hacked</h1>\n", encoding="utf-8")
    from filevow.core.hashing import sha256_file

    with protected.ctx.session() as session:
        _baseline(session, target).sha256 = sha256_file(target)

    assert outcomes(run_verification(protected.ctx)) == {"index.html": "RECORD_TAMPERED"}


def test_swapping_signatures_between_files_is_caught(protected: Protected) -> None:
    with protected.ctx.session() as session:
        index = _baseline(session, protected.site / "index.html")
        about = _baseline(session, protected.site / "about.html")
        index.rsa_signature, about.rsa_signature = about.rsa_signature, index.rsa_signature

    result = outcomes(run_verification(protected.ctx))
    assert result == {"index.html": "RECORD_TAMPERED", "about.html": "RECORD_TAMPERED"}


def test_rollback_to_an_older_genuine_record_is_caught(
    protected: Protected, rsa_key: keys.PrivateKey
) -> None:
    """Scenario 5: version 2 exists, but the database is put back to the genuine version 1."""
    with protected.ctx.session() as session:
        baseline = _baseline(session, protected.site / "index.html")
        newer = {**record_for(baseline), "version": 2, "sha256": "a" * 64}
        session.add(
            FileVersion(
                file_baseline_id=baseline.id,
                version=2,
                sha256="a" * 64,
                file_size=10,
                signed_record=newer,
                rsa_signature=signing.sign_payload(rsa_key, newer),
                signing_key_id=baseline.signing_key_id,
            )
        )

    assert outcomes(run_verification(protected.ctx)) == {"index.html": "ROLLBACK_DETECTED"}


def test_records_signed_by_an_unpinned_key_are_untrusted(protected: Protected) -> None:
    """Scenario 4: attacker registers their own key and re-signs a record with it."""
    attacker_key = keys.generate_private_key()
    with protected.ctx.session() as session:
        attacker_row = trust.register_public_key(session, attacker_key.public_key(), KeyPurpose.BASELINE)
        baseline = _baseline(session, protected.site / "index.html")
        baseline.signing_key = attacker_row
        baseline.rsa_signature = signing.sign_payload(attacker_key, record_for(baseline))

    assert outcomes(run_verification(protected.ctx)) == {"index.html": "KEY_UNTRUSTED"}


def test_editing_the_stored_public_key_removes_trust(protected: Protected) -> None:
    other = keys.generate_private_key()
    with protected.ctx.session() as session:
        row = session.scalar(select(SigningKey).where(SigningKey.purpose == KeyPurpose.BASELINE))
        row.public_key_pem = keys.public_key_to_pem(other.public_key())

    summary = run_verification(protected.ctx)
    assert set(outcomes(summary).values()) == {"KEY_UNTRUSTED"}


def test_corrupted_mirror_copy_is_detected_by_a_deep_check(protected: Protected) -> None:
    with protected.ctx.session() as session:
        sha = _baseline(session, protected.site / "about.html").mirror_object.sha256
    obj = protected.ctx.vault().object_path(sha)
    data = bytearray(obj.read_bytes())
    data[-5] ^= 0xFF
    obj.write_bytes(bytes(data))

    assert outcomes(run_verification(protected.ctx)) == {}
    assert outcomes(run_verification(protected.ctx, deep=True)) == {"about.html": "MIRROR_CORRUPTED"}


def test_modified_file_with_a_destroyed_mirror_is_critical(protected: Protected) -> None:
    with protected.ctx.session() as session:
        sha = _baseline(session, protected.site / "index.html").mirror_object.sha256
    protected.ctx.vault().object_path(sha).unlink()
    (protected.site / "index.html").write_text("changed", encoding="utf-8")

    assert outcomes(run_verification(protected.ctx)) == {"index.html": "FILE_MODIFIED_NO_CLEAN_COPY"}
    with protected.ctx.session() as session:
        assert session.scalar(select(ChangeEvent)).severity is Severity.CRITICAL


def test_run_report_is_signed_by_the_agent_key(protected: Protected) -> None:
    (protected.site / "index.html").write_text("changed", encoding="utf-8")
    summary = run_verification(protected.ctx)
    assert summary.signed
    with protected.ctx.session() as session:
        run = session.get(VerificationRun, summary.run_id)
        agent_public = protected.ctx.agent_private_key().public_key()
        assert signing.verify_payload(agent_public, run.report_json, run.agent_signature)
        assert run.report_json["issue_count"] == 1
        run.report_json = {**run.report_json, "issue_count": 0}  # a forged report no longer verifies
        assert not signing.verify_payload(agent_public, run.report_json, run.agent_signature)


def test_whole_folder_removed(protected: Protected) -> None:
    shutil.rmtree(protected.site / "js")
    assert outcomes(run_verification(protected.ctx)) == {"app.js": "FILE_DELETED"}


def test_outcome_values_match_the_manual() -> None:
    assert Outcome.RECORD_TAMPERED == "RECORD_TAMPERED"
