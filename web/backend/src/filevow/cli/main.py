"""The ``filevow`` command-line tool."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select
from sqlalchemy.orm import Session

from filevow.config import get_settings
from filevow.crypto import keys
from filevow.db.enums import (
    OPEN_REVIEW_STATUSES,
    BaselineStatus,
    KeyPurpose,
    Outcome,
    Role,
    RunType,
    Severity,
)
from filevow.db.models import ChangeEvent, FileBaseline, MonitoredPath, User
from filevow.secrets import create_secret_store
from filevow.services import alerts, audit, trust, users
from filevow.services.baseline import BaselineBuilder, MonitoredPathError, add_monitored_path
from filevow.services.context import AppContext, initialize
from filevow.services.monitor import MonitoringService
from filevow.services.review import ReviewError, ReviewResult, ReviewService

app = typer.Typer(help="FileVow: three-layer file integrity monitoring.", no_args_is_help=True)
path_app = typer.Typer(help="Manage monitored files and folders.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect the tamper-evident audit log.", no_args_is_help=True)
app.add_typer(path_app, name="path")
app.add_typer(audit_app, name="audit")

console = Console()

OUTCOME_STYLE = {
    Outcome.OK: "green",
    Outcome.PERMISSION_CHANGED: "cyan",
    Outcome.OWNER_CHANGED: "cyan",
    Outcome.UNKNOWN_FILE_CREATED: "yellow",
    Outcome.FILE_MODIFIED: "yellow",
    Outcome.FILE_DELETED: "yellow",
    Outcome.UNREADABLE: "dim",
}


@app.callback()
def _load_context(ctx: typer.Context) -> None:
    if ctx.obj is None:  # tests inject their own context
        settings = get_settings()
        ctx.obj = AppContext(settings, create_secret_store(settings))


def _context(ctx: typer.Context) -> AppContext:
    assert isinstance(ctx.obj, AppContext)
    return ctx.obj


def _owner_id(app_ctx: AppContext, username: str | None) -> int | None:
    """Resolve ``--owner``; without it the shared (unowned) workspace is used."""
    if username is None:
        return None
    with app_ctx.session() as session:
        user_id = session.scalar(select(User.id).where(User.username == username))
    if user_id is None:
        raise _fail(f"there is no account called {username!r}")
    return user_id


def _fail(message: str) -> typer.Exit:
    console.print(f"[red]Error:[/red] {message}")
    return typer.Exit(code=1)


# --------------------------------------------------------------------------- setup


@app.command()
def init(ctx: typer.Context) -> None:
    """Create FileVow's folders, database, vault key and agent key."""
    app_ctx = _context(ctx)
    report = initialize(app_ctx)
    console.print(f"FileVow home: [bold]{app_ctx.settings.home}[/bold]")
    console.print(f"Database:     {app_ctx.settings.resolved_database_url}")
    console.print(f"Vault key:    {'created' if report.created_vault_key else 'already present'}")
    console.print(
        f"Agent key:    {'created' if report.created_agent_key else 'already present'} "
        f"(id {report.agent_key_id})"
    )
    console.print("\nNext: [bold]filevow keygen --out <USB drive>\\filevow_baseline_key.pem[/bold]")


@app.command()
def keygen(
    ctx: typer.Context,
    out: Annotated[
        Path, typer.Option(help="Where to write the encrypted private key (ideally a USB drive).")
    ],
    owner: Annotated[
        str | None, typer.Option(help="Workspace owner (username); default: shared workspace.")
    ] = None,
) -> None:
    """Generate the baseline signing key, register it and pin its fingerprint."""
    app_ctx = _context(ctx)
    if out.exists():
        raise _fail(f"{out} already exists; refusing to overwrite a key file")
    passphrase = typer.prompt(
        "New key passphrase (16+ characters)", hide_input=True, confirmation_prompt=True
    )
    if len(passphrase) < 16:
        raise _fail("the passphrase must be at least 16 characters")

    private_key = keys.generate_private_key()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(keys.private_key_to_pem(private_key, passphrase.encode("utf-8")))

    with app_ctx.session() as session:
        row = trust.register_public_key(
            session, private_key.public_key(), KeyPurpose.BASELINE, owner_id=_owner_id(app_ctx, owner)
        )
        trust.pin_fingerprint(app_ctx.secrets, row.fingerprint)
        audit.record_event(
            session,
            "KEY_GENERATED",
            target_type="signing_key",
            target_id=row.key_id,
            details={"purpose": "baseline", "algorithm": row.algorithm},
        )
        console.print(f"Baseline key written to [bold]{out}[/bold]")
        console.print(f"Fingerprint (keep a copy somewhere safe): [bold]{row.fingerprint}[/bold]")


# --------------------------------------------------------------------------- monitored paths


@path_app.command("add")
def path_add(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(help="File or folder to protect.")],
    severity: Annotated[Severity, typer.Option(help="Severity of alerts for this path.")] = Severity.HIGH,
    include: Annotated[list[str] | None, typer.Option(help="Only files matching this pattern.")] = None,
    exclude: Annotated[list[str] | None, typer.Option(help="Skip files matching this pattern.")] = None,
    recursive: Annotated[bool, typer.Option(help="Include subfolders.")] = True,
    owner: Annotated[
        str | None, typer.Option(help="Workspace owner (username); default: shared workspace.")
    ] = None,
) -> None:
    """Start monitoring a file or folder (run `filevow baseline` afterwards)."""
    app_ctx = _context(ctx)
    owner_id = _owner_id(app_ctx, owner)
    try:
        with app_ctx.session() as session:
            monitored = add_monitored_path(
                session,
                app_ctx.settings,
                path,
                recursive=recursive,
                include=include or [],
                exclude=exclude or [],
                severity=severity,
                owner_id=owner_id,
            )
            console.print(
                f"Monitoring [bold]{monitored.path}[/bold] (id {monitored.id}, severity {severity})"
            )
    except MonitoredPathError as exc:
        raise _fail(str(exc)) from exc


@path_app.command("list")
def path_list(ctx: typer.Context) -> None:
    """Show monitored paths and how many files each protects."""
    with _context(ctx).session() as session:
        table = Table("ID", "Path", "Severity", "Protected files", "Enabled")
        for monitored in session.scalars(select(MonitoredPath).order_by(MonitoredPath.id)):
            protected = len(monitored.baselines)
            table.add_row(
                str(monitored.id),
                monitored.path,
                str(monitored.severity),
                str(protected),
                "yes" if monitored.enabled else "no",
            )
        console.print(table)


# --------------------------------------------------------------------------- baseline and verify


@app.command()
def baseline(
    ctx: typer.Context,
    key: Annotated[Path, typer.Option(help="Path to the baseline private key file.")],
    path_id: Annotated[int | None, typer.Option("--path-id", help="Only this monitored path.")] = None,
) -> None:
    """Hash, mirror and sign every unprotected file under the monitored paths."""
    app_ctx = _context(ctx)
    passphrase = typer.prompt("Baseline key passphrase", hide_input=True)
    with app_ctx.session() as session:
        try:
            private_key, signing_key = trust.unlock_baseline_key(
                session, app_ctx.secrets, key, passphrase.encode("utf-8")
            )
        except (keys.KeyLoadError, trust.UntrustedKeyError, FileNotFoundError) as exc:
            raise _fail(str(exc)) from exc

        query = select(MonitoredPath).where(MonitoredPath.enabled.is_(True))
        if path_id is not None:
            query = query.where(MonitoredPath.id == path_id)
        builder = BaselineBuilder(session, app_ctx.settings, app_ctx.vault(), private_key, signing_key)
        for monitored in session.scalars(query).all():
            summary = builder.protect(monitored)
            console.print(
                f"[bold]{monitored.path}[/bold]: {summary.created} signed, "
                f"{summary.already_protected} already protected, {summary.mirrored} mirrored"
            )
            for skipped in summary.too_large_to_mirror:
                console.print(f"  [yellow]not mirrored (too large):[/yellow] {skipped}")
            for unreadable in summary.unreadable:
                console.print(f"  [red]unreadable:[/red] {unreadable}")
        del private_key


@app.command()
def verify(
    ctx: typer.Context,
    deep: Annotated[bool, typer.Option(help="Also decrypt and check every mirror copy.")] = False,
) -> None:
    """Run the three-layer check on every protected file now."""
    result = MonitoringService(_context(ctx)).verify(RunType.MANUAL, deep=deep)
    summary = result.summary
    for problem in result.system_problems:
        console.print(f"[bold red]FileVow integrity problem:[/bold red] {problem}")

    console.print(
        f"Run #{summary.run_id}: checked {summary.files_checked} files in "
        f"{summary.duration_ms / 1000:.1f} s · [green]{summary.ok_count} OK[/green]"
        + (f" · [red]{summary.issue_count} need review[/red]" if summary.issues else "")
    )
    if summary.issues:
        table = Table("Outcome", "File")
        for issue in summary.issues:
            style = OUTCOME_STYLE.get(issue.outcome, "bold red")
            table.add_row(f"[{style}]{issue.outcome}[/{style}]", issue.file_path)
        console.print(table)
    console.print(
        "Report signed with the agent key." if summary.signed else "[yellow]Report not signed.[/yellow]"
    )
    if summary.issues:
        raise typer.Exit(code=2)


@app.command()
def status(ctx: typer.Context) -> None:
    """Summarise what is protected and what needs attention."""
    app_ctx = _context(ctx)
    with app_ctx.session() as session:
        paths = session.scalars(select(MonitoredPath)).all()
        files = session.scalars(select(FileBaseline)).all()
        pending = [f for f in files if f.status is BaselineStatus.PENDING_REVIEW]
        pinned = trust.pinned_fingerprints(app_ctx.secrets)
    console.print(
        f"Monitored paths: {len(paths)} · protected files: {len(files)} · pending review: {len(pending)}"
    )
    console.print(
        f"Pinned baseline keys: {', '.join(fp[:16] for fp in pinned) or 'none (run filevow keygen)'}"
    )


@audit_app.command("verify")
def audit_verify(ctx: typer.Context) -> None:
    """Check that no audit entry was edited, removed or inserted."""
    with _context(ctx).session() as session:
        report = audit.verify_chain(session)
    if report.intact:
        console.print(f"[green]Audit chain intact[/green] · {report.entries_checked} entries checked")
    else:
        console.print(f"[red]Audit chain broken at entry {report.first_broken_id}[/red]: {report.reason}")
        raise typer.Exit(code=2)


# --------------------------------------------------------------------------- review from the terminal

changes_app = typer.Typer(help="Review detected changes.", no_args_is_help=True)
app.add_typer(changes_app, name="changes")


def _review_service(app_ctx: AppContext, session: Session) -> ReviewService:
    trusted = trust.load_trusted_baseline_keys(session, app_ctx.secrets)
    return ReviewService(session, app_ctx.settings, app_ctx.vault(), trusted)


def _show_decision(result: ReviewResult) -> None:
    console.print(f"[green]#{result.change_id} {result.action}[/green]: {result.message}")


@changes_app.command("list")
def changes_list(ctx: typer.Context) -> None:
    """Show changes waiting for a decision."""
    with _context(ctx).session() as session:
        events = session.scalars(
            select(ChangeEvent)
            .where(ChangeEvent.review_status.in_(OPEN_REVIEW_STATUSES))
            .order_by(ChangeEvent.detected_at)
        ).all()
        table = Table("ID", "Severity", "Change", "File", "Observed SHA-256")
        for event in events:
            table.add_row(
                str(event.id),
                str(event.severity),
                event.event_type,
                event.file_path,
                (event.observed_sha256 or "-")[:16],
            )
    console.print(table if events else "[green]No changes are waiting for review.[/green]")


@changes_app.command("accept")
def changes_accept(
    ctx: typer.Context,
    change_id: Annotated[int, typer.Argument(help="Change ID from `filevow changes list`.")],
    key: Annotated[Path, typer.Option(help="Path to the baseline private key file.")],
    reason: Annotated[str, typer.Option(help="Why this change is legitimate (saved in the audit log).")],
) -> None:
    """Approve a change: the current file becomes a new signed version."""
    app_ctx = _context(ctx)
    passphrase = typer.prompt("Baseline key passphrase", hide_input=True)
    try:
        with app_ctx.session() as session:
            private_key, signing_key = trust.unlock_baseline_key(
                session, app_ctx.secrets, key, passphrase.encode("utf-8")
            )
            result = _review_service(app_ctx, session).accept(
                change_id, actor_user_id=None, reason=reason, private_key=private_key, signing_key=signing_key
            )
            alerts.resolve_for_changes(session, [change_id])
    except (ReviewError, keys.KeyLoadError, trust.UntrustedKeyError) as exc:
        raise _fail(str(exc)) from exc
    _show_decision(result)


def _simple_decision(ctx: typer.Context, change_id: int, reason: str, action: str) -> None:
    app_ctx = _context(ctx)
    try:
        with app_ctx.session() as session:
            service = _review_service(app_ctx, session)
            decide = {
                "restore": service.restore,
                "quarantine": service.quarantine,
                "reject": service.reject,
            }[action]
            result = decide(change_id, actor_user_id=None, reason=reason)
            alerts.resolve_for_changes(session, [change_id])
    except ReviewError as exc:
        raise _fail(str(exc)) from exc
    _show_decision(result)


@changes_app.command("restore")
def changes_restore(ctx: typer.Context, change_id: int, reason: Annotated[str, typer.Option()]) -> None:
    """Put back the newest genuine approved version from the encrypted vault."""
    _simple_decision(ctx, change_id, reason, "restore")


@changes_app.command("quarantine")
def changes_quarantine(ctx: typer.Context, change_id: int, reason: Annotated[str, typer.Option()]) -> None:
    """Remove an unknown file after keeping an evidence copy."""
    _simple_decision(ctx, change_id, reason, "quarantine")


@changes_app.command("reject")
def changes_reject(ctx: typer.Context, change_id: int, reason: Annotated[str, typer.Option()]) -> None:
    """Mark a change as a false positive (it is detected again if the file still differs)."""
    _simple_decision(ctx, change_id, reason, "reject")


# --------------------------------------------------------------------------- users, server and agent

user_app = typer.Typer(help="Manage dashboard accounts.", no_args_is_help=True)
app.add_typer(user_app, name="user")


@user_app.command("add")
def user_add(
    ctx: typer.Context,
    username: str,
    role: Annotated[Role, typer.Option(help="admin, analyst or viewer.")] = Role.VIEWER,
) -> None:
    """Create a dashboard account. Two-step verification is set up after the first sign-in."""
    password = typer.prompt("Password (12+ characters)", hide_input=True, confirmation_prompt=True)
    try:
        with _context(ctx).session() as session:
            created = users.create_user(session, username, password, role)
            console.print(f"Created [bold]{created.username}[/bold] ({created.role})")
    except users.UserError as exc:
        raise _fail(str(exc)) from exc


@app.command()
def agent(
    ctx: typer.Context,
    realtime: Annotated[bool, typer.Option(help="Also react to file changes within seconds.")] = True,
) -> None:
    """Run the background agent: 15-minute verification, real-time watching, alerts."""
    from filevow.agent.runtime import AgentRuntime

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app_ctx = _context(ctx)
    initialize(app_ctx)
    runtime = AgentRuntime(app_ctx, realtime=realtime)
    runtime.start()
    console.print("FileVow agent running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        runtime.stop()
        console.print("Agent stopped.")


@app.command()
def serve(
    ctx: typer.Context,
    host: Annotated[str | None, typer.Option(help="Interface to listen on.")] = None,
    port: Annotated[int | None, typer.Option(help="Port to listen on.")] = None,
    with_agent: Annotated[bool, typer.Option(help="Run the monitoring agent in the same process.")] = True,
    certfile: Annotated[Path | None, typer.Option(help="TLS certificate (PEM) for HTTPS.")] = None,
    keyfile: Annotated[Path | None, typer.Option(help="TLS private key (PEM) for HTTPS.")] = None,
) -> None:
    """Start the web dashboard and API."""
    import uvicorn

    from filevow.api.app import create_app

    app_ctx = _context(ctx)
    settings = app_ctx.settings
    uvicorn.run(
        create_app(app_ctx, start_agent=with_agent),
        host=host or settings.api_host,
        port=port or settings.api_port,
        ssl_certfile=str(certfile) if certfile else None,
        ssl_keyfile=str(keyfile) if keyfile else None,
        proxy_headers=True,
        log_level="info",
    )


@app.command()
def desktop(
    ctx: typer.Context,
    background: Annotated[
        bool, typer.Option(help="Monitor in the background without opening a window.")
    ] = False,
    keep_running: Annotated[bool, typer.Option(help="Keep monitoring after the window is closed.")] = False,
) -> None:
    """Open FileVow as a desktop app (starts monitoring if it is not running yet)."""
    from logging.handlers import RotatingFileHandler

    from filevow.desktop import desktop_settings, run_desktop, show_error

    base = _context(ctx)
    app_ctx = AppContext(desktop_settings(base.settings), base.secrets)
    app_ctx.settings.log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        app_ctx.settings.log_dir / "filevow.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8"
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[handler],
    )
    log_file = app_ctx.settings.log_dir / "filevow.log"
    try:
        run_desktop(app_ctx, background=background, keep_running=keep_running)
    except Exception as exc:
        logging.getLogger("filevow.desktop").exception("FileVow could not start")
        show_error(f"FileVow could not start.\n\n{exc}\n\nDetails are in:\n{log_file}")
        raise _fail(str(exc)) from exc


@app.command()
def autostart(
    state: Annotated[
        str, typer.Argument(help="on: start with Windows. off: stop doing that.", metavar="on|off")
    ],
) -> None:
    """Start monitoring in the background whenever you sign in to Windows."""
    from filevow.desktop import set_autostart

    if state.lower() not in {"on", "off"}:
        raise _fail("use `filevow autostart on` or `filevow autostart off`")
    enable = state.lower() == "on"
    try:
        set_autostart(enable)
    except RuntimeError as exc:
        raise _fail(str(exc)) from exc
    console.print(
        "FileVow will start with Windows." if enable else "FileVow will no longer start with Windows."
    )


if __name__ == "__main__":
    app()
