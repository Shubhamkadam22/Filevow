from __future__ import annotations

from sqlalchemy import delete, select

from filevow.db.models import AuditEntry
from filevow.services import audit
from filevow.services.context import AppContext


def _write_entries(ctx: AppContext, count: int) -> None:
    with ctx.session() as session:
        for number in range(count):
            audit.record_event(session, "TEST_EVENT", details={"n": number})


def test_fresh_chain_is_intact(ctx: AppContext) -> None:
    _write_entries(ctx, 5)
    with ctx.session() as session:
        report = audit.verify_chain(session)
    assert report.intact and report.entries_checked == 5


def test_editing_an_entry_is_detected(ctx: AppContext) -> None:
    _write_entries(ctx, 5)
    with ctx.session() as session:
        third = session.scalars(select(AuditEntry).order_by(AuditEntry.id)).all()[2]
        third.details = {"n": "edited"}
    with ctx.session() as session:
        report = audit.verify_chain(session)
    assert not report.intact and report.first_broken_id == third.id


def test_deleting_an_entry_is_detected(ctx: AppContext) -> None:
    _write_entries(ctx, 5)
    with ctx.session() as session:
        third_id = session.scalars(select(AuditEntry.id).order_by(AuditEntry.id)).all()[2]
        session.execute(delete(AuditEntry).where(AuditEntry.id == third_id))
    with ctx.session() as session:
        report = audit.verify_chain(session)
    assert not report.intact and "link is broken" in (report.reason or "")
