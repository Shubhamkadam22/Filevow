# Deploying FileVow

FileVow has two deliverables:

| Deliverable | What it is | Where it runs |
|---|---|---|
| **Website** (`web/website`) | Static pages: Home, Features, About, Privacy, Download | Any static host |
| **Desktop app** (`FileVow-Setup-<version>.exe`) | Dashboard + monitoring agent in one local process | Each user's Windows PC |

The user journey: visit the website → read about FileVow → **Download** → install →
open FileVow → create an account → add the folders and files to protect.

---

## Go live: first release in 6 steps

Everything below is done once. Afterwards a new version is just step 4 again.

**1. Create the GitHub repository.** On github.com: **New repository**, name `filevow`,
public or private, and *don't* add a README or licence (the project has them). Then
push this project:

```powershell
git remote add origin https://github.com/shubhamkadam22/filevow.git
git push -u origin main
```

The first push opens a GitHub sign-in window (Git Credential Manager).

**2. Check the website points at your repository.** `web/website/vercel.json` sends
`/downloads/*` and `/releases` to `github.com/shubhamkadam22/filevow`; change it there if
the repository moves. Check the contact address in `web/website/privacy.html` too.

**3. Check CI is green.** The **Actions** tab runs `CI` on every push: backend lint, types
and tests on Windows; dashboard type-check, lint, tests and build.

**4. Release the installer.** Make sure the version in `web/backend/pyproject.toml`
matches the tag, then:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow builds `FileVow.exe` and the Inno Setup installer on a GitHub
Windows machine (about 10 minutes) and publishes a release with `FileVow-Setup.exe`,
`FileVow-Setup-0.1.0.exe` and their `.sha256` files. The website's Download button
always points at the newest release.

**5. Deploy the website on Vercel.** On vercel.com: **Add New → Project →** import the
`filevow` repository → **Root Directory** `web/website` → Framework Preset **Other**, no
build command → **Deploy**. You get a `*.vercel.app` address; add your own domain under
**Settings → Domains** if you have one.

**6. Test the live site as a new user would.** Open the Vercel address, click
**Download**, run the installer, create an account, protect a folder, change a file and
restore it. Windows SmartScreen will warn about an unsigned installer until you sign
it (see *Code signing*).

---

## 1. Build the desktop app

Requirements on the build machine: Windows 10/11 x64, Python 3.11+ (3.13 tested),
Node.js 20+, and [Inno Setup 6](https://jrsoftware.org/isinfo.php) for the installer
(`winget install JRSoftware.InnoSetup`).

```powershell
powershell -ExecutionPolicy Bypass -File web\packaging\windows\build.ps1
```

The script:

1. builds the dashboard (`npm ci` + `npm run build` in `web/frontend`);
2. creates a clean build environment in `web/packaging/windows/build/venv` and installs
   the backend, PyInstaller and Pillow;
3. draws the app icon and bundles `FileVow.exe` with PyInstaller
   (`build/dist/FileVow/`), then runs a smoke test;
4. builds `web/packaging/windows/dist/FileVow-Setup-<version>.exe` with Inno Setup;
5. writes `.sha256` checksums and a versionless copy `FileVow-Setup.exe`, which the
   website's "latest" download link uses.

You normally don't run this yourself: the `Release` workflow runs it on GitHub for every
version tag. Run it locally to test packaging changes.

Options: `-SkipDashboard` (reuse an existing `dist`), `-SkipInstaller` (stop after
PyInstaller; the app folder can be zipped and run as is).

### What the installer does

- Installs per user to `%LOCALAPPDATA%\Programs\FileVow` (no administrator rights).
- Adds a Start menu shortcut and, optionally, a desktop shortcut.
- Optionally registers `FileVow.exe desktop --background` under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` so monitoring starts at sign-in.
  Users can change this later with `FileVow.exe autostart on|off`.
- Uninstall removes the program and the startup entry; data in
  `%LOCALAPPDATA%\FileVow` stays until the user deletes it.

### How the desktop app runs

- `FileVow.exe` (no arguments) = `filevow desktop`: if FileVow is already running it
  just opens a window; otherwise it starts the API, the dashboard and the agent on
  `http://127.0.0.1:8443` and opens Microsoft Edge in app mode with a separate profile
  (`%LOCALAPPDATA%\FileVow\window-profile`). Without Edge or Chrome it uses the default
  browser.
- The server only listens on the loopback interface. Logs: `%LOCALAPPDATA%\FileVow\logs\filevow.log`.
- Database migrations run automatically at start-up, so updates are installed by simply
  running the newer installer.

### Code signing (recommended before public release)

Unsigned installers trigger Windows SmartScreen warnings. Sign both `FileVow.exe` and the
installer with an Authenticode certificate (OV or EV) before publishing:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a web\packaging\windows\build\dist\FileVow\FileVow.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a web\packaging\windows\dist\FileVow-Setup-0.1.0.exe
```

Sign `FileVow.exe` before Inno Setup packs it (or configure `SignTool=` in
`installer.iss`), then recompute the checksum.

## 2. Publish the website and the installer

- **Website: Vercel.** Import the GitHub repository in Vercel, set the Root Directory to
  `web/website` (framework *Other*, no build command). `vercel.json` sets a strict CSP,
  HSTS and no framing. Every push to `main` redeploys.
- **Installer: GitHub Releases.** Pushing a tag `v<version>` runs
  `.github/workflows/release.yml`, which builds and publishes the installer. Vercel
  redirects `/downloads/FileVow-Setup.exe` to the newest release. GitHub shows the
  download count for each file (also via the REST API), so no database is needed to
  count downloads.
- **Accounts stay on each PC.** FileVow has no central user database: each installation
  keeps its own accounts (Argon2id password hashes, two-step secrets, audit log) in its
  local SQLite file. The website collects nothing.

Release checklist:

- [ ] Version bumped in `web/backend/pyproject.toml`, `src/filevow/__init__.py`,
      `web/packaging/windows/version_info.txt` and `installer.iss`.
- [ ] All checks pass (section 4).
- [ ] Tag pushed; the Release workflow succeeded and the release has the installer and checksums.
- [ ] Installer tested on a clean Windows user account: install, sign up, protect a
      folder, change a file, restore it, reboot (background start), uninstall.
- [ ] Privacy policy still matches what the app stores; contact address correct.
- [ ] Download button on the live site downloads the new version.

## 3. Server mode (optional)

For teams that want one shared FileVow instance (for example to watch a web server's
files), run the same backend as a service instead of the desktop app:

```powershell
cd web\backend
python -m venv .venv; .venv\Scripts\python -m pip install .
copy .env.example .env      # set FILEVOW_HOME, FILEVOW_API_HOST, etc.
.venv\Scripts\filevow init
.venv\Scripts\filevow serve --host 0.0.0.0 --port 8443 --certfile cert.pem --keyfile key.pem
```

- Always use HTTPS (`--certfile/--keyfile` or a reverse proxy such as IIS, nginx or
  Caddy) and keep `FILEVOW_COOKIE_SECURE=true`.
- Set `FILEVOW_ALLOW_REGISTRATION=false` once the accounts you need exist, and limit the
  folder browser with `FILEVOW_BROWSE_ROOTS`.
- Run it as a Windows service (for example with NSSM or `sc.exe` wrapping
  `filevow serve`) under a dedicated account that can read the monitored folders.
- PostgreSQL: `pip install ".[postgres]"` and set `FILEVOW_DATABASE_URL`.

## 4. Quality checks

```powershell
cd web\backend
.venv\Scripts\python -m pytest
.venv\Scripts\python -m ruff check src tests
.venv\Scripts\python -m mypy src
.venv\Scripts\alembic check

cd ..\frontend
npx tsc -b; npx eslint .; npx vitest run; npx vite build
```
