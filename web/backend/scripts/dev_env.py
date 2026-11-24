"""Shared settings for the local development environment (never used in production)."""

from __future__ import annotations

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEV_HOME = BACKEND_DIR / ".dev-home"
DEMO_SITE = DEV_HOME / "demo-site"

# Development-only test credentials for the local demo environment.
# "admin" owns a ready-made workspace protecting the demo site; "newuser" starts
# empty so the first-run setup guide can be tried.
DEV_KEY_PASSPHRASE = "dev signing key passphrase"
DEV_USERS = {
    "admin": ("dev admin passphrase", "admin"),
    "newuser": ("dev newuser passphrase", "user"),
}


def apply_environment() -> None:
    os.environ.setdefault("FILEVOW_HOME", str(DEV_HOME))
    os.environ.setdefault("FILEVOW_KEY_STORAGE", "file")
    os.environ.setdefault("FILEVOW_COOKIE_SECURE", "false")
    os.environ.setdefault("FILEVOW_FRONTEND_DIST", str(BACKEND_DIR.parent / "frontend" / "dist"))
    os.environ.setdefault("FILEVOW_API_PORT", "8443")
