"""Run FileVow as a desktop app on this computer.

The dashboard and the monitoring agent run in one local process that only listens on
the loopback interface. The window is Microsoft Edge (or Chrome) in "app" mode with a
profile of its own, so it looks and behaves like an installed program and its sign-in
cookies are kept apart from the user's normal browsing.

Only one copy runs at a time: starting FileVow while it is already running (for example
in the background after sign-in) just opens another window onto it.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from filevow.config import Settings
from filevow.services.context import AppContext

log = logging.getLogger(__name__)

STARTUP_TIMEOUT_SECONDS = 60
AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE = "FileVow"

_BROWSER_CANDIDATES = (
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
)


def desktop_settings(settings: Settings) -> Settings:
    """Settings for a single-computer install: loopback only, dashboard bundled."""
    update: dict[str, object] = {
        "api_host": "127.0.0.1",
        # The Secure flag adds nothing on loopback, and plain http keeps the window simple.
        "cookie_secure": False,
        "frontend_dist": settings.frontend_dist or bundled_dashboard(),
    }
    if not settings.cloud_enabled:
        update.update(bundled_cloud_config())
    return settings.model_copy(update=update)


def bundled_cloud_config() -> dict[str, str]:
    """Supabase URL and public anon key written into the installed app by the release build."""
    base = (
        Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) if getattr(sys, "frozen", False) else None
    )
    if base is None or not (base / "cloud.json").is_file():
        return {}
    try:
        data = json.loads((base / "cloud.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        log.warning("cloud.json in the app folder could not be read; cloud sign-in is off")
        return {}
    url, key = data.get("supabase_url"), data.get("supabase_anon_key")
    if not (isinstance(url, str) and url.startswith("https://") and isinstance(key, str) and key):
        return {}
    return {"supabase_url": url, "supabase_anon_key": key}


def bundled_dashboard() -> Path | None:
    """The built dashboard: inside the installed app, or next to the source checkout."""
    candidates = []
    if getattr(sys, "frozen", False):
        candidates.append(Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "dashboard")
    candidates.append(Path(__file__).resolve().parents[3] / "frontend" / "dist")
    return next((path for path in candidates if (path / "index.html").is_file()), None)


def app_url(settings: Settings) -> str:
    return f"http://127.0.0.1:{settings.api_port}/"


def is_running(settings: Settings) -> bool:
    """True when a FileVow instance already answers on this computer's port."""
    try:
        with urllib.request.urlopen(f"{app_url(settings)}api/v1/health", timeout=1.5) as response:  # noqa: S310 - fixed loopback URL
            return bool(json.load(response).get("status") == "ok")
    except (OSError, ValueError, urllib.error.URLError):
        return False


def find_app_browser() -> Path | None:
    for candidate in _BROWSER_CANDIDATES:
        path = Path(os.path.expandvars(candidate))
        if path.is_file():
            return path
    for name in ("msedge", "chrome", "chromium"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def open_window(settings: Settings) -> subprocess.Popen[bytes] | None:
    """Open the dashboard in an app-style window; returns the window process when known."""
    url = app_url(settings)
    browser = find_app_browser()
    if browser is None:
        webbrowser.open(url)
        return None
    profile = settings.home / "window-profile"
    profile.mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(  # noqa: S603 - fixed arguments, no shell
        [
            str(browser),
            f"--app={url}",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-size=1280,820",
        ]
    )


class LocalServer:
    """Uvicorn plus the agent, running on a background thread."""

    def __init__(self, app_ctx: AppContext) -> None:
        import uvicorn

        from filevow.api.app import create_app

        settings = app_ctx.settings
        config = uvicorn.Config(
            create_app(app_ctx, start_agent=True),
            host=settings.api_host,
            port=settings.api_port,
            log_level="warning",
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, name="filevow-server", daemon=True)

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("FileVow could not start. The port may be used by another program.")
            if time.monotonic() > deadline:
                raise RuntimeError("FileVow took too long to start.")
            time.sleep(0.1)

    def wait(self) -> None:
        while self._thread.is_alive():
            self._thread.join(timeout=1)

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=15)


def run_desktop(app_ctx: AppContext, *, background: bool = False, keep_running: bool = False) -> None:
    """Start FileVow (unless it is already running) and open its window."""
    settings = app_ctx.settings
    if is_running(settings):
        if not background:
            open_window(settings)
        return

    server = LocalServer(app_ctx)
    server.start()
    log.info("FileVow is running at %s", app_url(settings))
    if background:
        server.wait()
        return

    window = open_window(settings)
    try:
        if window is None or keep_running or autostart_enabled():
            # Monitoring continues after the window closes; the next launch reopens it.
            server.wait()
        else:
            window.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


# --------------------------------------------------------------------------- autostart


def launch_command(*arguments: str) -> str:
    """The command line that starts this FileVow installation."""
    if getattr(sys, "frozen", False):
        parts = [sys.executable, *arguments]
    else:
        parts = [sys.executable, "-m", "filevow", *arguments]
    return subprocess.list2cmdline(parts)


def autostart_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY) as key:
            winreg.QueryValueEx(key, AUTOSTART_VALUE)
        return True
    except OSError:
        return False


def set_autostart(enabled: bool) -> None:
    """Start monitoring in the background when this Windows user signs in."""
    if sys.platform != "win32":
        raise RuntimeError("Starting with Windows is only available on Windows.")
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(
                key, AUTOSTART_VALUE, 0, winreg.REG_SZ, launch_command("desktop", "--background")
            )
        else:
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteValue(key, AUTOSTART_VALUE)
