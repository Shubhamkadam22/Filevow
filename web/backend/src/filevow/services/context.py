"""Application context and first-time initialisation."""

from __future__ import annotations

import secrets as token_source
from contextlib import AbstractContextManager
from dataclasses import dataclass, field

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from filevow.config import Settings
from filevow.crypto import aead, keys
from filevow.db import build_engine, build_session_factory, session_scope
from filevow.db.enums import KeyPurpose
from filevow.db.migrate import upgrade_database
from filevow.db.models import SigningKey
from filevow.secrets import AGENT_PRIVATE_KEY, JWT_SECRET, VAULT_KEY, SecretStore
from filevow.vault import MirrorVault


@dataclass
class AppContext:
    settings: Settings
    secrets: SecretStore
    engine: Engine = field(init=False)
    session_factory: sessionmaker[Session] = field(init=False)

    def __post_init__(self) -> None:
        self.engine = build_engine(self.settings.resolved_database_url)
        self.session_factory = build_session_factory(self.engine)

    def session(self) -> AbstractContextManager[Session]:
        return session_scope(self.session_factory)

    def vault(self) -> MirrorVault:
        return MirrorVault(self.settings.vault_dir, self.vault_key())

    def vault_key(self) -> bytes:
        return bytes.fromhex(self.secrets.get(VAULT_KEY))

    def jwt_secret(self) -> str:
        return self.secrets.get(JWT_SECRET)

    def agent_private_key(self) -> keys.PrivateKey:
        return keys.load_private_key(self.secrets.get(AGENT_PRIVATE_KEY).encode("ascii"), passphrase=None)


@dataclass(frozen=True)
class InitReport:
    created_vault_key: bool
    created_agent_key: bool
    agent_key_id: str


def initialize(ctx: AppContext) -> InitReport:
    """Create folders, tables, the vault key and the agent key. Safe to run repeatedly."""
    for folder in (ctx.settings.home, ctx.settings.data_dir, ctx.settings.vault_dir, ctx.settings.log_dir):
        folder.mkdir(parents=True, exist_ok=True)
    upgrade_database(ctx.engine)

    created_vault_key = not ctx.secrets.exists(VAULT_KEY)
    if created_vault_key:
        ctx.secrets.set(VAULT_KEY, aead.generate_key().hex())

    if not ctx.secrets.exists(JWT_SECRET):
        ctx.secrets.set(JWT_SECRET, token_source.token_urlsafe(48))

    created_agent_key = not ctx.secrets.exists(AGENT_PRIVATE_KEY)
    if created_agent_key:
        agent_key = keys.generate_private_key()
        ctx.secrets.set(
            AGENT_PRIVATE_KEY, keys.private_key_to_pem(agent_key, passphrase=None).decode("ascii")
        )

    public_key = ctx.agent_private_key().public_key()
    agent_fingerprint = keys.fingerprint(public_key)
    with ctx.session() as session:
        registered = session.scalar(select(SigningKey).where(SigningKey.fingerprint == agent_fingerprint))
        if registered is None:
            session.add(
                SigningKey(
                    key_id=keys.short_key_id(agent_fingerprint),
                    fingerprint=agent_fingerprint,
                    purpose=KeyPurpose.AGENT,
                    algorithm=keys.ALGORITHM,
                    public_key_pem=keys.public_key_to_pem(public_key),
                )
            )
    return InitReport(created_vault_key, created_agent_key, keys.short_key_id(agent_fingerprint))
