"""Integrity records: the exact data that gets RSA-signed for each file version."""

from __future__ import annotations

from typing import Any

from filevow.crypto import keys, signing
from filevow.crypto.canonical import format_timestamp
from filevow.db.models import FileBaseline


def build_record(baseline: FileBaseline, *, mirror_sha256: str | None, key_id: str) -> dict[str, Any]:
    """Everything an attacker might want to swap is inside the signature:
    path (no record swapping), version (no rollback), mirror reference (no
    pointing at a malicious copy) and the signing key id."""
    return {
        "record_id": baseline.id,
        "file_path": baseline.file_path,
        "version": baseline.current_version,
        "sha256": baseline.sha256,
        "file_size": baseline.file_size,
        "file_type": str(baseline.file_type),
        "permissions": baseline.permissions,
        "owner": baseline.owner,
        "acl_hash": baseline.acl_hash,
        "mirror_object_sha256": mirror_sha256,
        "signing_key_id": key_id,
        "signed_at": format_timestamp(baseline.signed_at),
    }


def record_for(baseline: FileBaseline) -> dict[str, Any]:
    """Rebuild the record from the stored row (used when verifying)."""
    mirror_sha = baseline.mirror_object.sha256 if baseline.mirror_object else None
    return build_record(baseline, mirror_sha256=mirror_sha, key_id=baseline.signing_key.key_id)


def sign_record(private_key: keys.PrivateKey, record: dict[str, Any]) -> bytes:
    return signing.sign_payload(private_key, record)


def verify_record(public_key: keys.PublicKey, record: dict[str, Any], signature: bytes) -> bool:
    return signing.verify_payload(public_key, record, signature)
