from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from filevow.config import Settings
from filevow.crypto import keys
from filevow.db.enums import KeyPurpose, RunType
from filevow.db.models import MonitoredPath, SigningKey
from filevow.secrets import MemorySecretStore
from filevow.services import trust
from filevow.services.baseline import BaselineBuilder, add_monitored_path
from filevow.services.context import AppContext, initialize
from filevow.services.verification import RunSummary, Verifier

PASSPHRASE = b"correct horse battery staple"


@pytest.fixture(scope="session")
def rsa_key() -> keys.PrivateKey:
    """RSA-3072 generation is slow, so the whole test session shares one baseline key."""
    return keys.generate_private_key()


@pytest.fixture
def ctx(tmp_path: Path) -> Iterator[AppContext]:
    # _env_file=None: a developer's .env (e.g. real Supabase settings) must never leak into tests.
    settings = Settings(_env_file=None, home=tmp_path / "filevow-home", database_url=None)
    app_ctx = AppContext(settings, MemorySecretStore())
    initialize(app_ctx)
    yield app_ctx
    app_ctx.engine.dispose()


@pytest.fixture
def key_file(ctx: AppContext, rsa_key: keys.PrivateKey, tmp_path: Path) -> Path:
    path = tmp_path / "usb" / "baseline.pem"
    path.parent.mkdir()
    path.write_bytes(keys.private_key_to_pem(rsa_key, PASSPHRASE))
    with ctx.session() as session:
        row = trust.register_public_key(session, rsa_key.public_key(), KeyPurpose.BASELINE)
        trust.pin_fingerprint(ctx.secrets, row.fingerprint)
    return path


@pytest.fixture
def site(tmp_path: Path) -> Path:
    root = tmp_path / "wwwroot"
    (root / "js").mkdir(parents=True)
    (root / "index.html").write_text("<h1>Hello</h1>\n", encoding="utf-8")
    (root / "about.html").write_text("<p>About us</p>\n", encoding="utf-8")
    (root / "js" / "app.js").write_text("export function init() {}\n", encoding="utf-8")
    (root / "server.log").write_text("ignored\n", encoding="utf-8")
    return root


@dataclass
class Protected:
    ctx: AppContext
    site: Path
    signing_key_id: int


@pytest.fixture
def protected(ctx: AppContext, site: Path, key_file: Path) -> Protected:
    """A site whose files are monitored, mirrored and signed."""
    with ctx.session() as session:
        monitored = add_monitored_path(session, ctx.settings, site, exclude=["*.log"])
        private_key, signing_key = trust.unlock_baseline_key(session, ctx.secrets, key_file, PASSPHRASE)
        BaselineBuilder(session, ctx.settings, ctx.vault(), private_key, signing_key).protect(monitored)
        return Protected(ctx, site, signing_key.id)


def run_verification(ctx: AppContext, *, deep: bool = False) -> RunSummary:
    with ctx.session() as session:
        verifier = Verifier(
            session,
            ctx.settings,
            ctx.vault(),
            trust.load_trusted_baseline_keys(session, ctx.secrets),
            ctx.agent_private_key(),
            deep_mirror_check=deep,
        )
        return verifier.run(RunType.MANUAL)


def outcomes(summary: RunSummary) -> dict[str, str]:
    return {Path(issue.file_path).name: str(issue.outcome) for issue in summary.issues}


def monitored_path(session: Session) -> MonitoredPath:
    return session.query(MonitoredPath).one()


def baseline_signing_key(session: Session) -> SigningKey:
    return session.query(SigningKey).filter_by(purpose=KeyPurpose.BASELINE).one()
