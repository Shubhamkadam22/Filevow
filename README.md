# FileVow

Three-layer file integrity monitoring: SHA-256 fingerprints, RSA-PSS signed integrity
records and an AES-256-GCM encrypted mirror vault, verified every 15 minutes and within
seconds of a change. Changes are never accepted automatically.

## Repository layout

| Folder | Contents |
|---|---|
| `web/backend/` | Python: verification engine, agent, REST API, CLI, desktop launcher ([README](web/backend/README.md)) |
| `web/frontend/` | React + TypeScript dashboard ([README](web/frontend/README.md)) |
| `web/website/` | Public website: Home, Features, About, Privacy, Download ([README](web/website/README.md)) |
| `web/packaging/` | Windows build: PyInstaller app + Inno Setup installer |
| `docs/` | [User guide](docs/USER_GUIDE.md), [deployment guide](docs/DEPLOYMENT.md), project manual (PDF) |
| `demo/` | Clickable UI prototype used to agree the design |
| `design/` | Logo, colour tokens and the brand guide |

## How people use it

1. Visit the website and click **Download**.
2. Install FileVow (per user, no administrator rights) and open it from the Start menu.
3. Create an account: every account gets its own private workspace.
4. Create a signing key, click **Add folder or file → Browse…** and choose what to protect.
5. FileVow checks within seconds of any change and fully every 15 minutes; you review
   and accept or restore each change.

## Run it locally (development)

```powershell
cd web\frontend; npm install; npm run build
cd ..\backend; python -m venv .venv; .venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python scripts\seed_dev.py --reset
.venv\Scripts\python scripts\run_dev.py
```

Open http://127.0.0.1:8443 and sign in with a demo account from `web/backend/scripts/dev_env.py`
(`admin` has a ready-made workspace; `newuser` starts empty to try the setup guide).

Build the installer: `web\packaging\windows\build.ps1` (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

## What is implemented

- Baselines: hash, encrypted mirror copy and RSA-3072-PSS signature for every file
- Verification every 15 minutes, at start-up and in real time (file watcher)
- Detection of modified, deleted, new, replaced and permission-changed files, tampered or
  rolled-back records, untrusted keys and damaged mirror copies
- Review workflow: accept (new signed version), restore, quarantine, reject, escalate, bulk
- Tamper-evident audit log with agent-signed checkpoints and database-rollback detection
- Alerts with escalation; e-mail, webhook (Slack/Teams/SIEM) and Windows notifications
- Monitoring-gap alerts, heartbeat and agent self-integrity check
- Accounts with Argon2id, TOTP two-step verification, recovery codes, lockout, roles,
  short-lived JWT sessions with rotating refresh tokens, CSRF protection, rate limits
- Personal workspaces: sign-up, per-account signing keys, folders, changes, alerts and
  audit entries invisible to other accounts; first account becomes administrator
- Folder browser (Desktop, Documents, drives), first-run setup guide, in-app Help
- Windows 11 style dashboard: review workspace, command palette, keyboard shortcuts,
  live updates, light and dark themes
- Desktop app: single-instance launcher in an Edge app window, start with Windows,
  per-user installer

The full design is in [docs/FileVow_Project_Manual.pdf](docs/FileVow_Project_Manual.pdf).
