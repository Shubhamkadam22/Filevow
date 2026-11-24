[[PART:Part I — Overview|What the system is, how it is shaped, and what it is built with]]

# Introduction

## What problem does this project solve?

Every computer system depends on files staying exactly as they were intended to be: configuration files, website pages, executables, scripts, DLLs, system files such as `hosts`, and business documents. When one of these files changes **without anyone intending it**, the consequences range from a broken service to a fully compromised machine.

Files change unexpectedly for many reasons:

- **Attackers** modify web pages (defacement), plant backdoors in scripts, or replace executables with trojaned versions.
- **Malware and ransomware** rewrite or encrypt files.
- **Insiders** quietly change configuration or financial data.
- **Accidents**: an administrator edits the wrong file, a deployment overwrites a setting, a bad update corrupts a file.
- **Hardware and storage faults** silently corrupt data (bit rot).

The difficult part is not that files change. It is that **nobody notices** until much later. A **File Integrity Monitoring System (FIMS)** closes that gap. It records a trusted "known-good" state of selected files and continuously checks whether the current state still matches it. When it does not, the system raises an alert, keeps evidence, and lets a human decide what to do.

> KEY IDEA: A FIMS does not prevent changes. It **detects** them reliably, **proves** what changed, **preserves evidence**, and makes **recovery** possible. Detection, proof, evidence and recovery are the four outcomes every feature in this manual serves.

## What FileVow does, in one paragraph

**FileVow** is the file integrity monitoring system described in this manual. It calculates a **SHA-256 hash** (a cryptographic fingerprint) of every monitored file and stores it as a reference value. Each reference value is placed in an **integrity record** that is **digitally signed with RSA**, so nobody can alter the stored reference without being detected. An **encrypted reference copy (mirror)** of each file is kept in a protected vault so that you can always see what the file looked like and restore it. Every **15 minutes** an automated job re-checks all three layers. Any difference is recorded as a **suspicious change** that waits for human review. **Nothing is ever accepted automatically.** Every human action is written to a **tamper-evident audit log**.

> NOTE: **Why the name FileVow?** A vow is a solemn promise. FileVow promises that every protected file stays exactly as it was approved, and backs that promise with a SHA-256 fingerprint, an RSA signature that works like a sworn seal, and an encrypted reference copy. Nothing changes without a human renewing the vow. Pronounced "file-vow".

## The three verification layers

| Layer | Technique | Question it answers | Without it... |
|---|---|---|---|
| Layer 1 | SHA-256 hashing | Has the content of the file changed? | You could not detect edits at all. |
| Layer 2 | RSA-PSS digital signatures | Is the stored reference value genuine, approved by an authorised admin, and unaltered? | An attacker could change a file **and** its stored hash and remain invisible. |
| Layer 3 | AES-256-GCM encrypted mirror | What did the file look like before, and can we get it back? | You would know a file changed but have no evidence of the original and no way to restore it. |

Each layer covers a weakness in the others. Hashing alone can be defeated by editing the database. Signatures alone tell you that something changed but not what the original content was. A mirror alone could itself be tampered with. Together they form a system where every attack either fails or leaves evidence.

## Goals of the project

1. **Detect** any change to the content, size, permissions or ownership of monitored files.
2. **Authenticate** every reference value so that the reference data itself cannot be silently forged.
3. **Preserve** an encrypted, versioned reference copy of every file for comparison and restoration.
4. **Verify automatically** every 15 minutes, plus optional real-time detection.
5. **Never auto-accept**: every change requires an authenticated human decision.
6. **Account for everything**: every action is recorded in a hash-chained, signed audit log.
7. **Alert** through multiple channels, with escalation when alerts are ignored.
8. **Be secure itself**: strong authentication, least privilege, encrypted secrets, and defence in depth.

## Threat model: who are we defending against?

A **threat model** is a clear statement of which attackers and failures a security system is designed to handle. Writing it down keeps the design honest. It is also one of the first questions an examiner will ask.

| Threat | Example | Handled? |
|---|---|---|
| Accidental modification | An admin overwrites `web.config` by mistake | Yes: detected, original restorable from the mirror |
| Malware modifying files | A virus appends code to `.exe` or `.js` files | Yes: content hash mismatch |
| Attacker modifies a file **and** its stored hash | Edits `index.php`, then updates the database row | Yes: RSA signature check fails |
| Attacker corrupts the reference copy | Deletes or alters mirror files | Yes: GCM authentication and hash check fail |
| Attacker restores an old file together with its old signed record | Rollback attack | Yes: version and audit-chain checks |
| Attacker stops the monitoring agent | Kills the process before editing files | Yes: monitoring-gap alert and a full re-check on restart |
| Attacker edits the audit history | Deletes the log entry for an approval | Yes: the hash chain breaks |
| Attacker steals a dashboard password | Phishing | Mitigated: MFA, re-authentication for sensitive actions, lockout |
| Attacker with full administrator or kernel control of the machine | Rootkit | Partially: detection is made harder for them and evidence is preserved, but no software-only system can guarantee protection here |
| Hardware failure destroying the disk | Disk crash | Mitigated by an optional secondary mirror |

> NOTE: Be honest about the last rows in your presentation. A system that claims to stop everything is not credible. A system that clearly states its limits and uses **defence in depth** (several independent layers) is.

## Key terms used throughout this manual

| Term | Meaning |
|---|---|
| Monitored path | A file or folder the user chose to protect |
| Baseline | The trusted, approved state of a file at a point in time |
| Integrity record | The data that describes a file's baseline: path, SHA-256 hash, size, permissions, version, mirror reference |
| Signature | An RSA-PSS signature over an integrity record, proving it was approved by the holder of the private key |
| Mirror / vault | The encrypted store holding reference copies of files |
| Verification run | One execution of the checks over all monitored files (every 15 minutes) |
| Change event | A recorded difference between a file and its baseline |
| Pending review | The state of a change that is waiting for a human decision |
| Evidence copy | A copy of the suspicious version of a file, saved in the vault before any decision is made |
| Audit log | The tamper-evident history of every action in the system |

## How to read this manual

- **Part I** (this part) explains the purpose, architecture and tools.
- **Part II** teaches the cryptography from first principles: hashing, signatures, key management and encryption. Read it carefully; everything else depends on it.
- **Part III** describes each core feature in detail: the mirror vault, baselining, the verification engine, the review workflow, alerts and the audit log.
- **Part IV** covers the security of the system itself: authentication, hardening and a full threat walkthrough.
- **Part V** gives the complete database design, the API, the dashboard and the CLI.
- **Part VI** is the build guide: project structure, roadmap, testing and deployment.
- **Appendices** contain a glossary, configuration reference, example data, parameter cheat sheet and viva questions with answers.

# System Architecture

## The big picture

The system is made of a small number of cooperating components. The **agent** does the monitoring work in the background. The **server** exposes data and actions to the **dashboard** that humans use. Both share the **database** and the **mirror vault**.

[[DIAGRAM:architecture]]

## Components and their responsibilities

| Component | Responsibility | Module |
|---|---|---|
| Real-time watcher | Receives operating-system notifications when watched files are created, modified, moved or deleted, and queues a check | `agent/watcher.py` |
| 15-minute scheduler | Triggers a full verification run every 15 minutes, detects missed runs | `agent/scheduler.py` |
| Hasher | Computes SHA-256 of files in chunks | `agent/hasher.py` |
| Verification engine | Runs the three-layer check on each file and applies the decision table | `agent/verifier.py` |
| Crypto module | Canonical JSON, RSA-PSS signing and verification, key loading, fingerprints | `crypto/` |
| Mirror vault | Stores, deduplicates, encrypts, verifies and restores reference copies | `mirror/` |
| Review workflow | Accept, restore, reject and escalate pending changes, with re-authentication | `review/workflow.py` |
| Alert manager | Creates alerts, chooses channels by severity, groups duplicates, escalates | `alerts/` |
| Audit chain | Appends hash-chained audit entries and signs periodic checkpoints | `audit/chain.py` |
| Database layer | SQLAlchemy models, sessions and migrations | `db/` |
| API server | REST endpoints, WebSocket push, authentication, authorisation | `api/` |
| Dashboard | The web interface for monitoring and decisions | `dashboard/` |
| CLI | Command-line administration: key generation, baselining, manual verification | `cli.py` |

## The life of a monitored file

The following sequence shows everything that happens to a single file from the moment it is added to the moment a suspicious change is resolved.

1. **Registration.** An admin adds `C:\inetpub\wwwroot\` as a monitored path with severity *High*, recursive, excluding `*.log`.
2. **Baseline creation.** For every file under that folder the agent computes the SHA-256 hash, collects metadata, stores an encrypted copy in the vault, builds an integrity record and asks the admin to unlock the baseline signing key once. Each record is signed and saved.
3. **Steady state.** Every 15 minutes the verification engine checks the RSA signature of each record, the integrity of the mirror copy, and the live file hash. All three pass, so it updates `last_verified_at`.
4. **A change happens.** Someone edits `index.html`. The real-time watcher notices within seconds (or the next 15-minute run catches it).
5. **Detection.** The live hash no longer matches the signed record. The engine saves an **evidence copy** of the new content into the vault, creates a `change_event` with status `PENDING_REVIEW`, and the alert manager sends notifications.
6. **Review.** An admin opens the dashboard, sees a side-by-side diff of the mirror version and the current version, and decides.
7. **Decision.** If the change is legitimate, the admin **accepts** it: they re-authenticate, enter a TOTP code and the key passphrase. A new version is mirrored and signed. If it is malicious, the admin **restores** the mirror copy. Either way, an audit entry is appended to the hash chain.
8. **Back to steady state** with the new (or restored) baseline.

## Design principles

- **Separation of duties.** The component that runs continuously (the agent) cannot approve anything. Only an authenticated human holding the private key can.
- **Fail loudly, never silently.** If a check cannot be completed (file locked, key missing, vault unreachable), that is itself an alert, not a skipped file.
- **Evidence first.** Before anything is changed, the current state is preserved.
- **Least privilege.** Every component has only the access it needs.
- **Defence in depth.** No single check is trusted alone.
- **Everything is reproducible.** Canonical data formats ensure a signature verified today will still verify in a year.

# Technology Stack

## Why Python?

Python has a mature, well-audited cryptography library, an excellent file-system monitoring library, first-class database tooling and a fast modern web framework. Its readability makes the security logic easy to review, which matters in a security project. It runs on Windows, Linux and macOS without changes.

## Core libraries

| Purpose | Library | Why this one | Alternatives |
|---|---|---|---|
| Hashing | `hashlib` (standard library) | Built in, fast C implementation of SHA-256 | none needed |
| RSA, AES-GCM, key handling | `cryptography` | Industry standard, maintained by the Python Cryptographic Authority, uses OpenSSL underneath | PyCryptodome |
| Real-time file events | `watchdog` | Cross-platform; uses `ReadDirectoryChangesW` on Windows and `inotify` on Linux | polling only |
| Scheduling | `APScheduler` | Interval jobs with overlap prevention and misfire handling | `schedule`, cron |
| Database ORM | `SQLAlchemy 2.0` | Prevents SQL injection by design, database-independent | Peewee, raw `sqlite3` |
| Migrations | `Alembic` | Versioned schema changes | manual SQL |
| Database engine | SQLite, later PostgreSQL | SQLite needs no server; PostgreSQL for multiple agents | MySQL |
| Compression | `zstandard` | Fast, strong compression before encryption | `zlib` |
| Secret storage | `keyring` | Uses Windows Credential Manager, which is protected by DPAPI | environment variables (weaker) |
| Windows ACL and owner info | `pywin32` | Reads file owners and security descriptors | none on Windows |
| Web API | `FastAPI` + `uvicorn` | Async, automatic validation and OpenAPI docs, native WebSocket | Flask, Django |
| Password hashing | `argon2-cffi` | Argon2id, winner of the Password Hashing Competition | bcrypt |
| Multi-factor authentication | `pyotp` + `qrcode` | Standard TOTP compatible with Google/Microsoft Authenticator | none |
| Session tokens | `PyJWT` | Simple, well-maintained JWT implementation | python-jose |
| Rate limiting | `slowapi` | Limits login and sensitive endpoints | custom middleware |
| CLI | `Typer` | Clean command-line interfaces from type hints | argparse, click |
| Config | `python-dotenv`, `PyYAML` | `.env` for secrets references, YAML for settings | TOML |
| Logging | `structlog` | Structured (JSON) logs that are easy to search | logging |
| Desktop notification | `plyer` | Windows toast notifications | win10toast |
| Testing | `pytest`, `pytest-cov` | Simple, powerful test framework | unittest |

## Frontend

| Purpose | Choice | Why |
|---|---|---|
| Framework | React 18 + Vite | Component-based, fast development server |
| Styling | Tailwind CSS | Utility classes, consistent design |
| Diff viewer | `react-diff-viewer-continued` | Side-by-side text diffs for the review screen |
| Charts | Recharts | Alert and verification trends on the overview page |
| Data fetching | TanStack Query | Caching and automatic refresh |

> NOTE: If frontend work is not the focus of your project, a server-rendered dashboard using Jinja2 templates and HTMX is a perfectly valid, simpler alternative. The backend design does not change.

## requirements.txt

```
cryptography>=43
watchdog>=5
APScheduler>=3.10,<4
SQLAlchemy>=2.0
alembic>=1.13
zstandard>=0.23
keyring>=25
pywin32>=306 ; sys_platform == "win32"
fastapi>=0.115
uvicorn[standard]>=0.30
argon2-cffi>=23
pyotp>=2.9
qrcode>=7.4
PyJWT>=2.9
slowapi>=0.1.9
typer>=0.12
python-dotenv>=1.0
PyYAML>=6.0
structlog>=24
plyer>=2.1
pytest>=8
pytest-cov>=5
```
