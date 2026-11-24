"""Application settings.

Values come from environment variables prefixed with ``FILEVOW_`` or from a ``.env``
file. Secrets (keys, passwords) are never configured here; they live in the
operating system's credential store (see ``filevow.secrets``).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def default_home() -> Path:
    """Per Windows user (%LOCALAPPDATA%/FileVow), matching where the OS keyring keeps its secrets."""
    local_app_data = os.environ.get("LOCALAPPDATA")
    return Path(local_app_data) / "FileVow" if local_app_data else Path.home() / ".filevow"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FILEVOW_", env_file=".env", extra="ignore")

    home: Path = Field(default_factory=default_home)
    database_url: str | None = None

    verification_interval_minutes: int = 15
    monitoring_gap_minutes: int = 20
    hash_chunk_size: int = 64 * 1024
    max_mirror_file_mb: int = 200

    baseline_key_fingerprint: str | None = None
    baseline_key_path: Path | None = None

    keyring_service: str = "FileVow"
    # "file" for development or servers without an OS keyring.
    key_storage: Literal["keyring", "file"] = "keyring"

    allow_registration: bool = True  # anyone who can reach the dashboard may create an account
    browse_roots: list[Path] = Field(default_factory=list)  # empty: all drives and the home folder

    # Cloud sign-in with Supabase (Google and one-time e-mail codes). Both values are public
    # by design (the anon key only allows what row-level security permits). When unset,
    # accounts are local username + password, as in development and server mode.
    supabase_url: str | None = None
    supabase_anon_key: str | None = None
    cloud_google: bool = True
    cloud_email: bool = True

    api_host: str = "127.0.0.1"
    api_port: int = 8443
    cors_origins: list[str] = Field(default_factory=list)
    cookie_secure: bool = True  # set FILEVOW_COOKIE_SECURE=false only for local http development
    frontend_dist: Path | None = None

    @property
    def cloud_enabled(self) -> bool:
        return bool(self.supabase_url and self.supabase_anon_key)

    @property
    def data_dir(self) -> Path:
        return self.home / "data"

    @property
    def vault_dir(self) -> Path:
        return self.home / "vault"

    @property
    def log_dir(self) -> Path:
        return self.home / "logs"

    @property
    def internal_dirs(self) -> tuple[Path, ...]:
        """FileVow's own folders: never monitored and never offered in the folder browser."""
        return (self.data_dir, self.vault_dir, self.log_dir, self.home / "keys", self.home / "secrets")

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'filevow.db').as_posix()}"

    @property
    def max_mirror_file_bytes(self) -> int:
        return self.max_mirror_file_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
