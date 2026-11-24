"""The desktop launcher: settings it forces, single-instance check and launch command."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

from filevow import desktop
from filevow.config import Settings


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_desktop_settings_listen_on_loopback_only(tmp_path: Path) -> None:
    settings = desktop.desktop_settings(Settings(home=tmp_path, api_host="0.0.0.0", cookie_secure=True))  # noqa: S104

    assert settings.api_host == "127.0.0.1"
    assert settings.cookie_secure is False
    assert desktop.app_url(settings) == f"http://127.0.0.1:{settings.api_port}/"


def test_nothing_is_running_on_a_free_port(tmp_path: Path) -> None:
    assert desktop.is_running(Settings(home=tmp_path, api_port=_free_port())) is False


def test_launch_command_starts_the_module_from_source() -> None:
    command = desktop.launch_command("desktop", "--background")

    assert sys.executable in command or f'"{sys.executable}"' in command
    assert command.endswith("-m filevow desktop --background")


def test_default_home_is_per_user(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("LOCALAPPDATA", "C:/Users/someone/AppData/Local")
    from filevow.config import default_home

    assert default_home() == Path("C:/Users/someone/AppData/Local/FileVow")
