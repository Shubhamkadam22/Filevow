"""Getting started: workspace status, the user's signing key, and the folder browser."""

from __future__ import annotations

import os
import string
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from filevow.api.deps import confirm_step_up, get_ctx, get_session, rate_limit, require
from filevow.api.schemas import FsEntry, FsListing, FsPlace, KeyOut, SigningKeyIn, WorkspaceOut
from filevow.config import Settings
from filevow.core.paths import is_within
from filevow.db.enums import OPEN_REVIEW_STATUSES, BaselineStatus, Role
from filevow.db.models import ChangeEvent, FileBaseline, MonitoredPath, NotificationChannel, User
from filevow.services import trust
from filevow.services.context import AppContext

router = APIRouter(tags=["setup"])
viewer = require(Role.VIEWER)
owner = require(Role.USER)
MAX_ENTRIES = 500


# --------------------------------------------------------------------------- workspace status


@router.get("/workspace", response_model=WorkspaceOut)
def workspace_status(user: User = Depends(viewer), session: Session = Depends(get_session)) -> WorkspaceOut:
    key = trust.active_signing_key(session, user.id)
    folders = session.scalars(select(MonitoredPath).where(MonitoredPath.owner_id == user.id)).all()
    counts = dict(
        session.execute(
            select(FileBaseline.monitored_path_id, func.count(FileBaseline.id))
            .join(MonitoredPath)
            .where(MonitoredPath.owner_id == user.id, FileBaseline.status != BaselineStatus.DELETED)
            .group_by(FileBaseline.monitored_path_id)
        ).all()
    )
    channels = session.scalar(
        select(func.count(NotificationChannel.id)).where(
            NotificationChannel.owner_id == user.id, NotificationChannel.enabled.is_(True)
        )
    )
    open_changes = session.scalar(
        select(func.count(ChangeEvent.id)).where(
            ChangeEvent.owner_id == user.id, ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES)
        )
    )
    return WorkspaceOut(
        has_signing_key=key is not None,
        key_id=key.key_id if key else None,
        folders=len(folders),
        protected_files=sum(counts.values()),
        unprotected_folders=sum(1 for f in folders if not counts.get(f.id)),
        mfa_enabled=user.mfa_enabled,
        channels=channels or 0,
        open_changes=open_changes or 0,
    )


@router.post(
    "/workspace/signing-key",
    response_model=KeyOut,
    status_code=201,
    dependencies=[Depends(rate_limit("step-up", 30))],
)
def create_signing_key(
    body: SigningKeyIn,
    user: User = Depends(owner),
    session: Session = Depends(get_session),
    ctx: AppContext = Depends(get_ctx),
) -> KeyOut:
    confirm_step_up(session, ctx, user, body)
    try:
        row = trust.create_user_signing_key(session, ctx.settings, ctx.secrets, user, body.key_passphrase)
    except trust.SigningKeyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return KeyOut.model_validate(row).model_copy(update={"pinned": True})


@router.get("/workspace/signing-key/backup")
def download_key_backup(user: User = Depends(owner), session: Session = Depends(get_session)) -> FileResponse:
    """The private key file, still encrypted with the user's passphrase: safe to keep on a USB drive."""
    key = trust.active_signing_key(session, user.id)
    if key is None or not key.key_file or not Path(key.key_file).is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "You don't have a signing key yet")
    return FileResponse(
        key.key_file,
        media_type="application/x-pem-file",
        filename=f"filevow-signing-key-{key.key_id}.pem",
    )


# --------------------------------------------------------------------------- folder browser


def _roots(settings: Settings) -> list[Path]:
    if settings.browse_roots:
        return [Path(p) for p in settings.browse_roots]
    if sys.platform == "win32":
        return [Path(f"{letter}:\\") for letter in string.ascii_uppercase if Path(f"{letter}:\\").exists()]
    return [Path("/")]


def _allowed(path: Path, settings: Settings) -> bool:
    if any(is_within(path, folder) for folder in settings.internal_dirs):
        return False  # FileVow's own data is never offered for monitoring
    return not settings.browse_roots or any(is_within(path, root) for root in settings.browse_roots)


@router.get("/fs/places", response_model=list[FsPlace])
def places(_: User = Depends(owner), ctx: AppContext = Depends(get_ctx)) -> list[FsPlace]:
    """Shortcuts shown at the top of the browser, like a Windows file dialog."""
    home = Path.home()
    candidates = [
        ("Desktop", home / "Desktop", "home"),
        ("Documents", home / "Documents", "file"),
        ("Downloads", home / "Downloads", "download"),
        ("Pictures", home / "Pictures", "folder"),
        ("Home folder", home, "user"),
    ]
    found = [
        FsPlace(label=label, path=str(path), icon=icon) for label, path, icon in candidates if path.is_dir()
    ]
    drives = [FsPlace(label=f"Drive {root}", path=str(root), icon="folder") for root in _roots(ctx.settings)]
    return [p for p in found + drives if _allowed(Path(p.path), ctx.settings)]


@router.get("/fs/list", response_model=FsListing)
def list_folder(
    path: str | None = Query(default=None, max_length=1024),
    include_files: bool = True,
    _: User = Depends(owner),
    ctx: AppContext = Depends(get_ctx),
) -> FsListing:
    """Folders (and files) inside ``path``; without a path, the drives of this computer."""
    settings = ctx.settings
    if not path:
        drives = [FsEntry(name=str(r), path=str(r), kind="drive") for r in _roots(settings)]
        return FsListing(path=None, parent=None, entries=drives, truncated=False)

    folder = Path(os.path.abspath(path))
    if not folder.is_dir() or not _allowed(folder, settings):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That folder can't be opened")
    entries: list[FsEntry] = []
    truncated = False
    try:
        children = sorted(
            os.scandir(folder), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower())
        )
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Windows doesn't allow opening this folder") from exc
    for child in children:
        if child.name.startswith(("$", ".")) or child.is_symlink():
            continue  # system folders, hidden files and links are not offered
        try:
            is_dir = child.is_dir(follow_symlinks=False)
            if not is_dir and not include_files:
                continue
            if not _allowed(Path(child.path), settings):
                continue
            size = None if is_dir else child.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            break
        entries.append(
            FsEntry(name=child.name, path=child.path, kind="folder" if is_dir else "file", size=size)
        )
    parent = None if folder.parent == folder else str(folder.parent)
    return FsListing(path=str(folder), parent=parent, entries=entries, truncated=truncated)
