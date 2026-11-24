# PyInstaller spec for the FileVow desktop app. Build with build.ps1 (it sets the paths).
# -*- mode: python -*-
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

HERE = Path(SPECPATH)
WEB = HERE.parents[1]
BACKEND = WEB / "backend" / "src" / "filevow"
DASHBOARD = Path(os.environ.get("FILEVOW_DASHBOARD_DIST", WEB / "frontend" / "dist"))

if not (DASHBOARD / "index.html").is_file():
    raise SystemExit(f"Build the dashboard first (npm run build): {DASHBOARD} has no index.html")

hiddenimports = [
    *collect_submodules("filevow"),
    *collect_submodules("uvicorn"),
    *collect_submodules("keyring.backends"),
    "win32timezone",
    "win32security",
    "win32crypt",
    "plyer.platforms.win.notification",
]

datas = [
    (str(DASHBOARD), "dashboard"),
    # Alembic reads migration scripts from disk, so ship them as files.
    (str(BACKEND / "db" / "migrations"), "filevow/db/migrations"),
    *collect_data_files("alembic"),
]

a = Analysis(
    [str(HERE / "launcher.py")],
    pathex=[str(BACKEND.parent)],
    hiddenimports=hiddenimports,
    datas=datas,
    excludes=["tkinter", "pytest", "mypy", "ruff", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FileVow",
    icon=str(HERE / "build" / "filevow.ico"),
    version=str(HERE / "version_info.txt"),
    console=False,  # a desktop app: no console window
    disable_windowed_traceback=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="FileVow", upx=False)
