# FileVow backend

Python package with the verification engine, background agent, REST API and CLI.

## Setup

```powershell
cd web\backend
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

## Quality checks

```powershell
.venv\Scripts\python -m pytest                 # 100+ tests incl. the manual's attack scenarios
.venv\Scripts\python -m ruff check src tests   # lint
.venv\Scripts\python -m ruff format src tests  # format
.venv\Scripts\python -m mypy src               # strict type checking
.venv\Scripts\alembic check                    # models and migrations in sync
```

## Local demo environment

```powershell
.venv\Scripts\python scripts\seed_dev.py --reset   # demo accounts; admin's workspace protects a sample site
.venv\Scripts\python scripts\run_dev.py            # API + agent + dashboard on http://127.0.0.1:8443
```

Demo accounts and the demo key passphrase are defined in `scripts/dev_env.py`
(development only). Build the dashboard first: `cd ..\frontend; npm install; npm run build`.

## Desktop app

```powershell
.venv\Scripts\filevow desktop               # start (or reuse) FileVow and open its window
.venv\Scripts\filevow desktop --background  # monitor without a window (used at Windows sign-in)
.venv\Scripts\filevow autostart on          # start in the background whenever you sign in
```

People normally get this through the installer (`web/packaging/windows/build.ps1`); see
`docs/DEPLOYMENT.md`. Accounts, signing keys and folders are then set up in the app.

## Server mode / terminal-only setup

```powershell
filevow init                                        # folders, database, vault key, agent key
filevow user add alice --role admin
filevow keygen --owner alice --out E:\alice_key.pem # or create the key in the dashboard
filevow path add C:\inetpub\wwwroot --owner alice --exclude "*.log"
filevow baseline --key E:\alice_key.pem
filevow serve                                       # dashboard + API + agent
```

Run behind HTTPS in production: either pass `--certfile/--keyfile` to `filevow serve`
or put it behind a reverse proxy (IIS, nginx, Caddy) that terminates TLS.

## CLI reference

| Command | Purpose |
|---|---|
| `filevow init` | Create folders, run database migrations, create the vault and agent keys |
| `filevow keygen --out PATH` | Generate the baseline signing key (passphrase protected) and pin its fingerprint |
| `filevow path add PATH` / `path list` | Manage monitored files and folders |
| `filevow baseline --key PATH` | Hash, mirror and sign unprotected files |
| `filevow verify [--deep]` | Run the three-layer check now (exit code 2 when something needs review) |
| `filevow changes list / accept / restore / quarantine / reject` | Review changes from the terminal |
| `filevow user add NAME --role admin` | Create a dashboard account |
| `filevow audit verify` | Verify the hash-chained audit log |
| `filevow agent` | Background agent only (15-minute schedule, real-time watcher, alerts) |
| `filevow serve` | Dashboard, API and (by default) the agent in one process |
| `filevow desktop [--background]` | Desktop app: one local instance plus an app window |
| `filevow autostart on\|off` | Start monitoring when this Windows user signs in |
| `filevow status` | Summary of what is protected |

## Configuration

All settings are environment variables (or a `.env` file, see `.env.example`) prefixed with `FILEVOW_`.

| Variable | Default | Meaning |
|---|---|---|
| `FILEVOW_HOME` | `%LOCALAPPDATA%\FileVow` | Data, vault, keys and logs |
| `FILEVOW_DATABASE_URL` | SQLite in `HOME\data` | e.g. `postgresql+psycopg://user:pass@host/filevow` (install `.[postgres]`) |
| `FILEVOW_KEY_STORAGE` | `keyring` | `keyring` = Windows Credential Manager; `file` = JSON file for dev/Linux servers |
| `FILEVOW_ALLOW_REGISTRATION` | `true` | Let people create accounts on the sign-in screen |
| `FILEVOW_BROWSE_ROOTS` | `[]` | Limit the folder browser, e.g. `["C:/Users"]` (empty = all drives) |
| `FILEVOW_VERIFICATION_INTERVAL_MINUTES` | `15` | Scheduled run interval |
| `FILEVOW_MONITORING_GAP_MINUTES` | `20` | Raise MONITORING_GAP after this long without a run |
| `FILEVOW_API_HOST` / `FILEVOW_API_PORT` | `127.0.0.1` / `8443` | Where `serve` listens |
| `FILEVOW_COOKIE_SECURE` | `true` | Keep `true` whenever HTTPS is used |
| `FILEVOW_CORS_ORIGINS` | `[]` | Only needed if the dashboard is served from another origin |
| `FILEVOW_FRONTEND_DIST` | — | Path to `web/frontend/dist` to serve the dashboard |

API documentation is served at `/api/v1/docs` (OpenAPI).

## Layout

```
src/filevow/
  config.py        settings (pydantic-settings)
  secrets.py       Credential Manager / file secret stores
  core/            hashing, paths, metadata, file walker
  crypto/          canonical JSON, RSA-PSS keys and signatures, AES-256-GCM
  db/              SQLAlchemy models, enums, sessions, Alembic migrations
  vault/           encrypted content-addressed mirror vault
  services/        baseline, verification, review, alerts, notifications,
                   monitoring, audit chain, users, tokens, trust/pinning
  agent/           scheduler + real-time watcher runtime
  api/             FastAPI app, routes, security middleware, WebSocket events
  cli/             the `filevow` command
tests/             unit, API and security-scenario tests
scripts/           local demo environment
```
