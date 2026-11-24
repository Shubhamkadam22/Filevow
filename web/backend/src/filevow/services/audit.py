"""The hash-chained audit log.

``entry_hash = SHA-256(prev_hash + canonical(entry))``. Editing, deleting or
inserting an entry breaks the chain from that point on.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.crypto import keys, signing
from filevow.crypto.canonical import canonical_json, format_timestamp
from filevow.db.base import utcnow
from filevow.db.models import AuditCheckpoint, AuditEntry, SigningKey
from filevow.secrets import AUDIT_CHAIN_HEAD, SecretStore

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class ChainReport:
    intact: bool
    entries_checked: int
    first_broken_id: int | None = None
    reason: str | None = None


def _entry_payload(entry: AuditEntry) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "actor_user_id": entry.actor_user_id,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details,
        "ip_address": entry.ip_address,
        "created_at": format_timestamp(entry.created_at),
        "prev_hash": entry.prev_hash,
    }
    if entry.owner_id is not None:  # absent for older entries, so their hashes stay valid
        payload["owner_id"] = entry.owner_id
    return payload


def compute_entry_hash(entry: AuditEntry) -> str:
    return hashlib.sha256(entry.prev_hash.encode("ascii") + canonical_json(_entry_payload(entry))).hexdigest()


def record_event(
    session: Session,
    action: str,
    *,
    actor_user_id: int | None = None,
    owner_id: int | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditEntry:
    """Append one entry to the chain. The caller's transaction commits it."""
    last = session.scalar(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1).with_for_update())
    entry = AuditEntry(
        actor_user_id=actor_user_id,
        owner_id=owner_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=details,
        ip_address=ip_address,
        created_at=utcnow().replace(microsecond=0),
        prev_hash=last.entry_hash if last else GENESIS_HASH,
    )
    entry.entry_hash = compute_entry_hash(entry)
    session.add(entry)
    session.flush()
    return entry


def verify_chain(session: Session) -> ChainReport:
    expected_prev = GENESIS_HASH
    checked = 0
    for entry in session.scalars(select(AuditEntry).order_by(AuditEntry.id)):
        if entry.prev_hash != expected_prev:
            return ChainReport(
                False, checked, entry.id, "previous-hash link is broken (entry removed or inserted)"
            )
        if compute_entry_hash(entry) != entry.entry_hash:
            return ChainReport(False, checked, entry.id, "entry content was modified")
        expected_prev = entry.entry_hash
        checked += 1
    return ChainReport(True, checked)


# --------------------------------------------------------------------------- signed checkpoints


def _checkpoint_payload(checkpoint: AuditCheckpoint) -> dict[str, Any]:
    return {
        "last_entry_id": checkpoint.last_entry_id,
        "entry_hash": checkpoint.entry_hash,
        "run_id": checkpoint.run_id,
        "created_at": format_timestamp(checkpoint.created_at),
    }


def create_checkpoint(
    session: Session,
    agent_key: keys.PrivateKey,
    agent_key_row: SigningKey,
    run_id: int | None = None,
) -> AuditCheckpoint | None:
    """Sign the current chain head with the agent key.

    A rebuilt chain no longer matches its signed checkpoints. Call
    ``remember_chain_head`` after the transaction commits so the head is also kept
    outside the database, where restoring an old database copy cannot reach it.
    """
    head = session.scalar(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1))
    if head is None:
        return None
    checkpoint = AuditCheckpoint(
        last_entry_id=head.id,
        entry_hash=head.entry_hash,
        run_id=run_id,
        signing_key_id=agent_key_row.id,
        created_at=utcnow().replace(microsecond=0),
        agent_signature=b"",
    )
    checkpoint.agent_signature = signing.sign_payload(agent_key, _checkpoint_payload(checkpoint))
    session.add(checkpoint)
    session.flush()
    return checkpoint


def remember_chain_head(secrets: SecretStore, checkpoint: AuditCheckpoint) -> None:
    secrets.set(AUDIT_CHAIN_HEAD, f"{checkpoint.last_entry_id}:{checkpoint.entry_hash}")


def verify_checkpoints(session: Session) -> list[str]:
    """Return a description of every checkpoint that fails; an empty list means all good."""
    problems: list[str] = []
    for checkpoint in session.scalars(select(AuditCheckpoint).order_by(AuditCheckpoint.id)):
        key_row = session.get(SigningKey, checkpoint.signing_key_id)
        if key_row is None:
            problems.append(f"checkpoint {checkpoint.id}: signing key is missing")
            continue
        public_key = keys.load_public_key(key_row.public_key_pem)
        if keys.fingerprint(public_key) != key_row.fingerprint:
            problems.append(f"checkpoint {checkpoint.id}: signing key was altered")
            continue
        payload = _checkpoint_payload(checkpoint)
        if not signing.verify_payload(public_key, payload, checkpoint.agent_signature):
            problems.append(f"checkpoint {checkpoint.id}: signature does not verify")
            continue
        entry = session.get(AuditEntry, checkpoint.last_entry_id)
        if entry is None or entry.entry_hash != checkpoint.entry_hash:
            problems.append(f"checkpoint {checkpoint.id}: audit entry {checkpoint.last_entry_id} was changed")
    return problems


def detect_database_rollback(session: Session, secrets: SecretStore) -> str | None:
    """Compare the chain head remembered in the OS secret store with the database."""
    if not secrets.exists(AUDIT_CHAIN_HEAD):
        return None
    entry_id_text, _, expected_hash = secrets.get(AUDIT_CHAIN_HEAD).partition(":")
    entry = session.get(AuditEntry, int(entry_id_text))
    if entry is None:
        return f"audit entry {entry_id_text} is missing: the database was restored from an older copy"
    if entry.entry_hash != expected_hash:
        return f"audit entry {entry_id_text} no longer matches its remembered hash"
    return None
