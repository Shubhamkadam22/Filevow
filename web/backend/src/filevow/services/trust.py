"""Which public keys FileVow trusts, and why.

A baseline signing key is trusted only when its fingerprint is *pinned* in the
secret store. This defeats an attacker who inserts their own public key into the
database and re-signs every record with it. Each key also belongs to one workspace
(its owner) and may only sign records for files in that workspace.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.config import Settings
from filevow.crypto import keys
from filevow.db.enums import KeyPurpose, KeyStatus
from filevow.db.models import SigningKey, User
from filevow.secrets import BASELINE_FINGERPRINT, SecretStore
from filevow.services import audit

MIN_KEY_PASSPHRASE_LENGTH = 12


class UntrustedKeyError(Exception):
    pass


class SigningKeyError(ValueError):
    """The user's signing key cannot be created or unlocked (missing, wrong passphrase…)."""


@dataclass(frozen=True)
class TrustedKeys:
    """Public keys allowed to sign integrity records, keyed by ``signing_keys.id``."""

    by_row_id: dict[int, keys.PublicKey]
    owners: dict[int, int | None] = field(default_factory=dict)

    def get(self, row_id: int) -> keys.PublicKey | None:
        return self.by_row_id.get(row_id)

    def for_owner(self, row_id: int, owner_id: int | None) -> keys.PublicKey | None:
        """The key, but only if it belongs to the same workspace as the file it signed."""
        if row_id not in self.by_row_id or self.owners.get(row_id) != owner_id:
            return None
        return self.by_row_id[row_id]


def pinned_fingerprints(secrets: SecretStore) -> set[str]:
    if not secrets.exists(BASELINE_FINGERPRINT):
        return set()
    return {fp for fp in secrets.get(BASELINE_FINGERPRINT).split(",") if fp}


def pin_fingerprint(secrets: SecretStore, fingerprint: str) -> None:
    current = pinned_fingerprints(secrets)
    secrets.set(BASELINE_FINGERPRINT, ",".join(sorted(current | {fingerprint})))


def register_public_key(
    session: Session, public_key: keys.PublicKey, purpose: KeyPurpose, owner_id: int | None = None
) -> SigningKey:
    full_fingerprint = keys.fingerprint(public_key)
    existing = session.scalar(select(SigningKey).where(SigningKey.fingerprint == full_fingerprint))
    if existing:
        return existing
    row = SigningKey(
        key_id=keys.short_key_id(full_fingerprint),
        fingerprint=full_fingerprint,
        purpose=purpose,
        algorithm=keys.ALGORITHM,
        public_key_pem=keys.public_key_to_pem(public_key),
        owner_id=owner_id,
    )
    session.add(row)
    session.flush()
    return row


def load_trusted_baseline_keys(session: Session, secrets: SecretStore) -> TrustedKeys:
    """Return baseline keys that are pinned, not revoked, and whose stored PEM really
    hashes to the stored fingerprint (so editing the PEM column is caught too)."""
    pinned = pinned_fingerprints(secrets)
    trusted: dict[int, keys.PublicKey] = {}
    owners: dict[int, int | None] = {}
    rows = session.scalars(select(SigningKey).where(SigningKey.purpose == KeyPurpose.BASELINE))
    for row in rows:
        if row.status == KeyStatus.REVOKED or row.fingerprint not in pinned:
            continue
        public_key = keys.load_public_key(row.public_key_pem)
        if keys.fingerprint(public_key) == row.fingerprint:
            trusted[row.id] = public_key
            owners[row.id] = row.owner_id
    return TrustedKeys(trusted, owners)


def unlock_baseline_key(
    session: Session, secrets: SecretStore, key_file: Path, passphrase: bytes
) -> tuple[keys.PrivateKey, SigningKey]:
    """Load a baseline private key file and confirm it is a pinned, active key."""
    private_key = keys.load_private_key(key_file.read_bytes(), passphrase)
    full_fingerprint = keys.fingerprint(private_key.public_key())
    if full_fingerprint not in pinned_fingerprints(secrets):
        raise UntrustedKeyError("this key file is not the pinned baseline key")
    row = session.scalar(select(SigningKey).where(SigningKey.fingerprint == full_fingerprint))
    if row is None or row.status != KeyStatus.ACTIVE:
        raise UntrustedKeyError("this key is not registered as an active baseline key")
    return private_key, row


# --------------------------------------------------------------------------- per-user keys


def active_signing_key(session: Session, owner_id: int | None) -> SigningKey | None:
    query = select(SigningKey).where(
        SigningKey.purpose == KeyPurpose.BASELINE,
        SigningKey.status == KeyStatus.ACTIVE,
        SigningKey.owner_id.is_(None) if owner_id is None else SigningKey.owner_id == owner_id,
    )
    return session.scalars(query.order_by(SigningKey.id.desc())).first()


def create_user_signing_key(
    session: Session, settings: Settings, secrets: SecretStore, user: User, passphrase: str
) -> SigningKey:
    """Generate a workspace signing key, encrypted with a passphrase only the user knows.

    The encrypted key file lives under ``FILEVOW_HOME/keys``. Without the passphrase it is
    useless, so a stolen database or disk still cannot be used to approve changes.
    """
    if len(passphrase) < MIN_KEY_PASSPHRASE_LENGTH:
        raise SigningKeyError(
            f"Use a signing-key passphrase of at least {MIN_KEY_PASSPHRASE_LENGTH} characters"
        )
    if active_signing_key(session, user.id) is not None:
        raise SigningKeyError("Your workspace already has a signing key")

    private_key = keys.generate_private_key()
    row = register_public_key(session, private_key.public_key(), KeyPurpose.BASELINE, owner_id=user.id)
    folder = settings.home / "keys" / f"user-{user.id}"
    folder.mkdir(parents=True, exist_ok=True)
    key_file = folder / f"{row.key_id}.pem"
    key_file.write_bytes(keys.private_key_to_pem(private_key, passphrase.encode("utf-8")))
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
    row.key_file = str(key_file)
    pin_fingerprint(secrets, row.fingerprint)
    audit.record_event(
        session,
        "KEY_GENERATED",
        actor_user_id=user.id,
        owner_id=user.id,
        target_type="signing_key",
        target_id=row.key_id,
        details={"purpose": "baseline", "algorithm": row.algorithm},
    )
    return row


def unlock_user_signing_key(
    session: Session, settings: Settings, secrets: SecretStore, owner_id: int | None, passphrase: str
) -> tuple[keys.PrivateKey, SigningKey]:
    """Unlock the workspace's signing key with its passphrase (needed to approve changes)."""
    row = active_signing_key(session, owner_id)
    key_path = Path(row.key_file) if row is not None and row.key_file else settings.baseline_key_path
    if row is None or key_path is None or not key_path.is_file():
        raise SigningKeyError("Create your signing key first (Settings → Signing key)")
    try:
        private_key, unlocked = unlock_baseline_key(session, secrets, key_path, passphrase.encode("utf-8"))
    except keys.KeyLoadError as exc:
        raise SigningKeyError("The signing-key passphrase is not correct") from exc
    if unlocked.owner_id != owner_id:
        raise UntrustedKeyError("this key belongs to another workspace")
    return private_key, unlocked
