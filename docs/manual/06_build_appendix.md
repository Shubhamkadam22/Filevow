[[PART:Part VI — Building the Project|Project structure, roadmap, testing strategy and deployment]]

# Project Structure

```
filevow/
|-- pyproject.toml / requirements.txt
|-- config.example.yaml          # copied to config.yaml by `filevow init`
|-- .gitignore                   # .env, *.pem, vault/, data/, logs/
|-- cli.py                       # Typer entry point
|-- filevow/
|   |-- config.py                # load + validate config.yaml, paths, pinned fingerprint
|   |-- secrets.py               # keyring wrapper (vault key, agent key, JWT secret)
|   |-- crypto/
|   |   |-- canonical.py         # canonical JSON + path normalisation
|   |   |-- keys.py              # generate, load, fingerprint, rotate, pin check
|   |   |-- signer.py            # RSA-PSS sign / verify
|   |   `-- aead.py              # AES-256-GCM seal / unseal (+ zstd)
|   |-- mirror/
|   |   |-- vault.py             # store, load, verify, dedup, replicate
|   |   `-- restore.py           # evidence capture + atomic restore
|   |-- agent/
|   |   |-- hasher.py            # chunked, TOCTOU-safe hashing
|   |   |-- metadata.py          # stat, owner, ACL hash, file type (pywin32)
|   |   |-- walker.py            # walk monitored paths with include/exclude, no links
|   |   |-- baseline.py          # create baselines
|   |   |-- verifier.py          # per-file 3-layer check + decision table
|   |   |-- runner.py            # a full verification run, signed report
|   |   |-- scheduler.py         # 15-minute job, start-up run, gap detection
|   |   |-- watcher.py           # watchdog handler + debouncer
|   |   |-- heartbeat.py
|   |   `-- self_check.py        # agent manifest verification
|   |-- review/
|   |   `-- workflow.py          # accept / restore / reject / escalate / bulk
|   |-- alerts/
|   |   |-- manager.py           # create, group, route, escalate
|   |   `-- channels/            # email.py, desktop.py, webhook.py, slack.py
|   |-- audit/
|   |   `-- chain.py             # append, verify, checkpoint, rollback check
|   |-- db/
|   |   |-- models.py            # all tables from Chapter 17
|   |   |-- session.py           # engine, pragmas, session factory
|   |   `-- migrations/          # Alembic
|   `-- api/
|       |-- main.py              # FastAPI app, middleware, security headers
|       |-- auth.py              # login, JWT, TOTP, step-up, RBAC dependencies
|       |-- schemas.py           # Pydantic request/response models
|       |-- websocket.py
|       `-- routes/              # paths, files, changes, alerts, runs, audit, keys, users
|-- dashboard/                   # React + Vite frontend
|-- tests/
|   |-- unit/                    # hashing, canonical, signer, aead, decision table, chain
|   |-- integration/             # baseline -> modify -> verify -> accept/restore
|   `-- security/                # tamper tests (Chapter 22)
`-- docs/
    `-- FileVow_Project_Manual.pdf
```

The layout follows one rule: **cryptography, storage, monitoring, decisions and presentation live in separate packages**. The verification engine never imports the API; the API never touches files directly; only `review/workflow.py` can create new signed versions.

# Development Roadmap

Build in this order. Each phase ends with something you can run and demonstrate, and each depends only on earlier phases.

| Phase | Build | Done when (acceptance test) |
|---|---|---|
| 1. Foundations | Config, database models and session, canonical JSON, chunked hasher | Unit tests pass; `filevow init` creates the database and folders |
| 2. Signatures | Key generation, passphrase protection, fingerprints, pinning, sign and verify, `filevow keygen` | Editing any field of a signed record by hand makes verification fail |
| 3. Mirror vault | AES-GCM seal/unseal, content-addressed store, dedup, verify | Flipping one byte in a vault object is detected; identical files are stored once |
| 4. Baseline | Walker with patterns, metadata, baseline procedure, `filevow path add`, `filevow baseline` | 1,000 test files baselined, mirrored and signed with one passphrase entry |
| 5. Verification engine | Per-file algorithm, decision table, change events, evidence capture, `filevow verify` | Modify, delete, add, rename, chmod and link-swap tests each produce the correct outcome |
| 6. Automation | 15-minute scheduler, start-up run, gap detection, heartbeat, signed run reports, watcher with debounce | Stopping the agent for 20 minutes produces MONITORING_GAP; a modification is caught within seconds |
| 7. Review workflow | Accept, restore, reject, escalate, bulk accept (CLI first) | Accept creates version n+1 with a valid signature; restore brings back the exact original bytes |
| 8. Audit chain | Append, verify, checkpoints, database-rollback check | Deleting or editing any audit row is detected; restoring an old database copy is detected |
| 9. Alerts | Alert manager, grouping, routing, escalation, desktop and email channels | A modification produces exactly one alert and one email, repeated detections do not |
| 10. API and security | FastAPI routes, Argon2, TOTP, JWT, step-up, RBAC, rate limits, headers | Viewer cannot accept (403); accept without TOTP fails; 6th wrong password locks the account |
| 11. Dashboard | Pages from Chapter 19, diff viewer, live updates | Full review flow done in the browser |
| 12. Hardening and release | Self-check manifest, Windows service, retention, backups, documentation, full test suite | All security tests pass; installation from scratch works on a clean machine |

> NOTE: If time is limited, phases 1 to 9 with the CLI already form a complete, defensible project that meets every requirement in the specification. The API and dashboard (phases 10 and 11) make it presentable.

# Testing Strategy

## Unit tests

| Module | Tests |
|---|---|
| hasher | Known SHA-256 test vectors (empty string = `e3b0c442...b855`); file larger than one chunk; file changed during read raises an error |
| canonical | Key order and whitespace do not change the output; timestamps are formatted identically |
| signer | Valid signature verifies; changing any single field fails; wrong key fails; signatures of the same record differ (PSS salt) yet both verify |
| aead | Round trip; modified ciphertext, nonce, tag or AAD each raise `InvalidTag` |
| decision table | Every row of the table in Chapter 10 produces the expected outcome and severity |
| audit chain | Intact chain verifies; edit, delete, insert and truncation are each detected |
| auth | Argon2 verify; TOTP accepts current and adjacent steps, rejects reuse and old codes; JWT expiry |

## Integration tests

Use `pytest`'s `tmp_path` fixture to create a temporary monitored folder, vault and database for each test.

```python
def test_modify_then_restore(filevow_env):
    f = filevow_env.make_file("site/index.html", b"<h1>Hello</h1>")
    filevow_env.baseline()
    f.write_bytes(b"<h1>Hacked</h1>")
    run = filevow_env.verify()
    assert run.outcomes[str(f)] == "FILE_MODIFIED"
    change = filevow_env.pending_changes()[0]
    filevow_env.restore(change.id)
    assert f.read_bytes() == b"<h1>Hello</h1>"
    assert filevow_env.verify().outcomes[str(f)] == "OK"
```

## Security (tamper) tests

These tests prove the security claims. Show them in your demonstration.

| Test | Action | Expected |
|---|---|---|
| Hash substitution | Update `file_baselines.sha256` with SQL | RECORD_TAMPERED |
| Field substitution | Change `file_path` of a record to another file's path | RECORD_TAMPERED |
| Key substitution | Insert a new public key and re-sign records | KEY_SUBSTITUTION_DETECTED |
| Rollback | Restore an old file and its old signed record | ROLLBACK_DETECTED |
| Database rollback | Replace the database with yesterday's copy | DATABASE_ROLLBACK_DETECTED |
| Vault tampering | Flip one byte in a vault object | MIRROR_CORRUPTED |
| Vault swap | Rename an old object to the current object's name | MIRROR_CORRUPTED |
| Audit edit | Change the `details` of an audit row | AUDIT_CHAIN_BROKEN |
| Audit rebuild | Recompute the whole chain after an edit | Checkpoint signature mismatch |
| Timestamp reset | Modify a file and restore its mtime | FILE_MODIFIED (deep scan) |
| Link swap | Replace a file with a symlink | TYPE_CHANGED |
| Agent stop | Stop the agent for 20 minutes | MONITORING_GAP |
| Privilege | Viewer calls accept endpoint | 403 Forbidden |
| Step-up | Admin accepts without a TOTP code | Refused |
| Brute force | 6 wrong passwords | Account locked, alert raised |

## Demonstration script (10 minutes)

1. Show the dashboard: all files OK, agent online, key fingerprint in the footer.
2. Edit `index.html` in a text editor. Within seconds an alert appears; open the diff.
3. Restore it with step-up authentication. Verify it is OK again.
4. "The attacker is smarter": edit a file and update its hash in the database with a SQLite browser. Run verify: RECORD_TAMPERED.
5. Flip a byte in a vault object: MIRROR_CORRUPTED.
6. Delete an audit row: the "Verify chain" button shows the break.
7. Stop the agent, wait, start it: MONITORING_GAP.
8. Accept a legitimate change: show the passphrase prompt, the new version, and the audit entry.

# Deployment on Windows

## Folder layout

```
C:\FileVow\
    app\        source code and virtual environment       (Administrators: full, FileVow-svc: read)
    data\       filevow.db                                     (Administrators, FileVow-svc: modify)
    vault\      mirror objects                              (Administrators, FileVow-svc: modify)
    logs\       application logs                            (Administrators, FileVow-svc: modify)
    config\     config.yaml                                 (Administrators: full, FileVow-svc: read)
E:\             USB drive holding filevow_baseline_key.pem     (only plugged in for approvals)
```

## Installation steps

```
python -m venv C:\FileVow\app\.venv
C:\FileVow\app\.venv\Scripts\pip install -r requirements.txt
C:\FileVow\app\.venv\Scripts\python cli.py init
C:\FileVow\app\.venv\Scripts\python cli.py keygen --out E:\filevow_baseline_key.pem
C:\FileVow\app\.venv\Scripts\python cli.py user add admin --role admin
C:\FileVow\app\.venv\Scripts\python cli.py path add "C:\inetpub\wwwroot" --severity high
C:\FileVow\app\.venv\Scripts\python cli.py baseline
```

## Running as a Windows service

The agent must start automatically at boot and run without anyone logged in. Options:

| Option | Notes |
|---|---|
| `pywin32` service class (`win32serviceutil.ServiceFramework`) | Pure Python, no extra tools; recommended |
| NSSM (Non-Sucking Service Manager) | Wraps any command as a service; very simple |
| Task Scheduler "At startup" task | Simplest, but less control over restarts |

Configure the service to run as the `FileVow-svc` account, start automatically, and restart on failure. Run the API server as a second service.

## Lock down permissions

```
icacls C:\FileVow\vault  /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "FileVow-svc:(OI)(CI)M"
icacls C:\FileVow\data   /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "FileVow-svc:(OI)(CI)M"
icacls C:\FileVow\config /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "FileVow-svc:(OI)(CI)RX"
```

## Operations checklist

- Daily: review pending changes and alerts.
- Daily (automatic): database backup, full mirror verification sample cycle, full audit chain verification.
- Weekly: confirm backup restore works; check the agent heartbeat history for gaps.
- Yearly or on suspicion: rotate the baseline key.
- After every planned deployment: review and bulk-accept the expected changes.

[[PART:Appendices|Glossary, configuration, examples, cheat sheet and viva preparation]]

# Appendix A — Glossary

| Term | Definition |
|---|---|
| AAD | Additional authenticated data: data protected by GCM's tag but not encrypted |
| ACL | Access control list: the permissions attached to a file on Windows |
| AES | Advanced Encryption Standard, a symmetric block cipher |
| Argon2id | Memory-hard password hashing function |
| Atomic operation | An operation that either completes fully or not at all |
| Avalanche effect | A small input change causes a large, unpredictable output change |
| Baseline | The approved, trusted state of a file |
| Canonical form | A single, standard byte representation of data |
| Collision | Two different inputs with the same hash |
| Content addressing | Naming stored data by the hash of its content |
| Debouncing | Waiting until a burst of events stops before acting once |
| Defence in depth | Using several independent security layers |
| DPAPI | Windows Data Protection API, which encrypts secrets per user account |
| Fingerprint | A hash of a public key used to identify it |
| GCM | Galois/Counter Mode, an authenticated encryption mode |
| HMAC | Hash-based message authentication code, a symmetric keyed hash |
| JWT | JSON Web Token, a signed token carrying session claims |
| MFA | Multi-factor authentication |
| Nonce | A number that must be used only once with a given key |
| PEM | Text encoding of keys between BEGIN/END lines |
| Pinning | Hard-coding the expected fingerprint of a trusted key |
| PKCS #8 | Standard format for storing private keys |
| PSS | Probabilistic Signature Scheme, secure padding for RSA signatures |
| RBAC | Role-based access control |
| Rollback attack | Replaying an older, genuinely signed state |
| RSA | Public-key algorithm based on the difficulty of factoring large numbers |
| Salt | Random data added before hashing so identical inputs give different outputs |
| SHA-256 | Secure Hash Algorithm with a 256-bit output |
| Step-up authentication | Re-verifying identity before a sensitive action |
| TOCTOU | Time-of-check to time-of-use race condition |
| TOTP | Time-based one-time password |

# Appendix B — Configuration Reference

```yaml
# C:\FileVow\config\config.yaml
agent:
  id: "WEB01"
  verification_interval_minutes: 15
  gap_alert_minutes: 20
  heartbeat_seconds: 60
  deep_scan: every_run            # every_run | nightly
  hash_workers: 4
  max_mirror_file_mb: 200
  mirror_verify_sample_percent: 5 # plus every mismatched file
  realtime_watcher: true
  debounce_seconds: 2

crypto:
  baseline_key_fingerprint: "<64 hex characters pinned at keygen>"
  baseline_key_path: "E:\\filevow_baseline_key.pem"
  algorithm: "RSA-3072-PSS-SHA256"

paths:
  data_dir: "C:\\FileVow\\data"
  vault_dir: "C:\\FileVow\\vault"
  secondary_vault_dir: null       # e.g. "\\\\NAS\\filevow-mirror"
  log_dir: "C:\\FileVow\\logs"

database:
  url: "sqlite:///C:/FileVow/data/filevow.db"

retention:
  verification_results_days: 30
  evidence_days: 180

alerts:
  escalation_minutes: { critical: 15, high: 60 }
  burst_threshold_per_minute: 20

api:
  host: "127.0.0.1"
  port: 8443
  tls_cert: "C:\\FileVow\\config\\cert.pem"
  tls_key: "C:\\FileVow\\config\\cert-key.pem"
  access_token_minutes: 15
  refresh_token_hours: 8
  login_rate_limit: "5/minute"
  lockout: { attempts: 5, minutes: 15 }
```

# Appendix C — Example Data

## A signed integrity record

```json
{
  "acl_hash": "4be1f0...c2",
  "file_path": "c:/inetpub/wwwroot/index.html",
  "file_size": 5120,
  "file_type": "regular",
  "mirror_object_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "owner": "BUILTIN\\Administrators",
  "permissions": "rw",
  "record_id": 42,
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "signed_at": "2026-11-23T10:15:00Z",
  "signing_key_id": "a1b2c3d4e5f60718",
  "version": 3
}
signature (base64, 384 bytes): "kV7Qm2...=="
```

## A signed verification run report

```json
{
  "agent_id": "WEB01",
  "files_checked": 1284,
  "finished_at": "2026-11-23T10:30:09Z",
  "issues": [
    {"event": "FILE_MODIFIED", "file_path": "c:/inetpub/wwwroot/index.html",
     "expected": "9f86d0...0a08", "observed": "a1c3e5...77b2"}
  ],
  "ok_count": 1283,
  "results_sha256": "d4e5f6...a9",
  "run_id": 4182,
  "run_type": "scheduled",
  "started_at": "2026-11-23T10:30:00Z"
}
agent_signature: "Pq81aZ...=="  (agent key 5e6f7a8b9c0d1e2f)
```

## An audit log entry

```json
{
  "id": 1833,
  "actor_user_id": 1,
  "action": "CHANGE_ACCEPTED",
  "target_type": "change_event",
  "target_id": "918",
  "details": {"file": "c:/inetpub/wwwroot/index.html", "new_version": 4,
              "reason": "Release 2.4 deployment, ticket CHG-1182"},
  "ip_address": "127.0.0.1",
  "created_at": "2026-11-23T10:52:31Z",
  "prev_hash": "52bd77...e1",
  "entry_hash": "0c9a14...7f"
}
```

# Appendix D — Algorithm Cheat Sheet

| Item | Value |
|---|---|
| Content hash | SHA-256, 64 KB chunks, binary mode |
| Signature algorithm | RSA-PSS, SHA-256, MGF1-SHA-256, salt length = maximum |
| RSA key size and exponent | 3072 bits, e = 65537 |
| Signature size | 384 bytes |
| Private key format | PKCS #8 PEM, passphrase encrypted (baseline) / DPAPI via keyring (agent) |
| Key identifier | First 16 hex of SHA-256 of the DER public key |
| Mirror encryption | AES-256-GCM, 96-bit random nonce, 128-bit tag, AAD = object SHA-256 |
| Mirror compression | Zstandard level 10, before encryption |
| Password hashing | Argon2id, m = 64 MB, t = 3, p = 4, 16-byte salt |
| MFA | TOTP (RFC 6238), HMAC-SHA1, 30 s step, 6 digits, window +/- 1 |
| Session tokens | JWT HS256, access 15 min, refresh 8 h rotated |
| Audit chain | entry_hash = SHA-256(prev_hash + canonical(entry)), genesis = 64 zeros |
| Checkpoints | Every run, RSA-PSS with the agent key |
| Verification interval | 15 minutes, max_instances = 1, coalesce, run at start-up |
| Gap alert | No completed run for more than 20 minutes |

# Appendix E — Viva and Presentation Questions

**1. Why SHA-256 and not MD5 or SHA-1?**
MD5 and SHA-1 are broken: practical collisions have been demonstrated, so an attacker could craft a different file with the same hash. SHA-256 has no known practical attacks and is the industry standard.

**2. If you already hash the files, why do you need RSA?**
Anyone can compute a hash. An attacker who can modify both a file and the database can replace the stored hash. The RSA signature proves the reference value was approved by the private-key holder; the attacker cannot produce a valid signature.

**3. Why RSA signatures and not HMAC?**
HMAC uses one key for creating and checking. The always-running agent would hold the key that creates records, so compromising it would allow forgery. With RSA the agent only holds the public key.

**4. What is PSS and why is it used?**
A randomised padding scheme for RSA signatures. It prevents the malleability and determinism of textbook RSA and has a security proof.

**5. Why 3072-bit keys?**
They provide about 128-bit security, recommended by NIST for use beyond 2030. 2048 bits is the minimum; 4096 adds cost for little benefit.

**6. Why two RSA keys?**
To limit the damage of a compromise. The agent key must always be available, so it only signs reports and checkpoints. The baseline key, which approves file states, stays offline behind a passphrase.

**7. What does the mirror add if you already detect changes?**
Evidence and recovery: you can see exactly what changed and restore the original. It also preserves the attacker's version as forensic evidence.

**8. Why AES-GCM instead of AES-CBC?**
GCM is authenticated encryption: it detects any modification of the ciphertext. CBC only provides confidentiality.

**9. What happens if a GCM nonce is reused?**
Confidentiality and authenticity break for the affected messages. The system generates a fresh random 96-bit nonce for every object.

**10. Why is nothing accepted automatically?**
Otherwise an attacker's change would become trusted at the next run. Requiring an authenticated human with the offline private key keeps approval out of the attacker's reach.

**11. How do you detect a rollback attack?**
The signed record contains a version number that must equal the latest version in the history; approvals are in the signed audit chain; and the latest checkpoint is remembered outside the database to detect whole-database rollbacks.

**12. How do you stop someone replacing your public key?**
The fingerprint of the genuine key is pinned in the configuration and in Credential Manager; any other key is rejected and raises a critical alert.

**13. What if the attacker stops the agent?**
A start-up full check, a monitoring-gap alert with the exact unmonitored period, and a server-side heartbeat check.

**14. How is the audit log protected?**
Each entry includes the hash of the previous one, so edits and deletions break the chain. Periodic checkpoints signed with the agent key prevent rebuilding the chain.

**15. Why combine real-time monitoring with a 15-minute scan?**
Real-time is fast but can miss events; the scheduled full scan is complete and authoritative.

**16. Why not trust modification times?**
They can be changed with a single API call. Deep scans re-hash content regardless.

**17. What is TOCTOU and how do you handle it?**
A race where a file changes between checking and using it. The system uses stats from the open file handle before and after hashing, retries if they differ, re-hashes at acceptance time, and uses atomic replacement for restores.

**18. Why Argon2id for passwords instead of SHA-256?**
SHA-256 is too fast; attackers can test billions of guesses per second. Argon2id is deliberately slow and memory-hard, with a unique salt per password.

**19. How does TOTP work without the phone contacting the server?**
Both share a secret and compute HMAC-SHA1 over the current 30-second time step, then truncate it to 6 digits.

**20. What can a stolen session cookie do?**
Only read-only and analyst actions for at most 15 minutes. Accepting or restoring requires a fresh password and TOTP, and accepting also requires the key passphrase.

**21. What are the limits of your system?**
An attacker with full administrator or kernel control could eventually defeat software-only defences. The design makes attacks detectable and preserves evidence; hardware-backed keys (TPM) and remote log shipping are future improvements.

**22. How would you scale to many machines?**
Switch to PostgreSQL, run one agent per machine reporting to a central API, and keep the baseline key with the central administrators.

**23. Is the system resistant to quantum computers?**
SHA-256 and AES-256 remain strong. RSA would be broken by a large quantum computer; a future version could use post-quantum signatures such as ML-DSA.

**24. What happens if the baseline private key is lost?**
Monitoring continues and existing signatures still verify, but no changes can be approved. You generate a new key and re-baseline after confirming the files are trustworthy.

**25. Why canonical JSON?**
Signatures are over exact bytes. Canonical serialisation guarantees the same record always produces the same bytes, so genuine signatures always verify.
