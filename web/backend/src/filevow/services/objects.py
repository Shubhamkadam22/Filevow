"""Keep the ``mirror_objects`` table in step with the vault on disk."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.db.enums import ObjectKind
from filevow.db.models import MirrorObject
from filevow.vault import StoredObject


def register_object(session: Session, stored: StoredObject, kind: ObjectKind) -> MirrorObject:
    """Get or create the row for a stored object.

    An evidence object that later becomes an accepted baseline is promoted to
    ``baseline`` so retention never deletes content that a signed version points to.
    """
    row = session.scalar(select(MirrorObject).where(MirrorObject.sha256 == stored.sha256))
    if row is None:
        row = MirrorObject(
            sha256=stored.sha256,
            storage_path=stored.storage_path,
            original_size=stored.original_size,
            stored_size=stored.stored_size,
            kind=kind,
        )
        session.add(row)
        session.flush()
    elif kind is ObjectKind.BASELINE and row.kind is ObjectKind.EVIDENCE:
        row.kind = ObjectKind.BASELINE
    return row
