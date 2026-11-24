"""Entry point of the installed FileVow.exe.

Double-clicking the app (no arguments) opens the desktop window; the Start-with-Windows
entry runs ``FileVow.exe desktop --background``. Other CLI commands work as well.
"""

from __future__ import annotations

import multiprocessing
import os
import sys


def main() -> None:
    multiprocessing.freeze_support()
    # A windowed executable has no console: give libraries somewhere harmless to write.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
    if len(sys.argv) == 1:
        sys.argv.append("desktop")

    from filevow.cli.main import app

    app(prog_name="FileVow")


if __name__ == "__main__":
    main()
