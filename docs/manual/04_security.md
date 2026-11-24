[[PART:Part IV — Securing the System Itself|Authentication, access control, hardening, and a full threat walkthrough]]

# Authentication and Access Control

A security tool with weak login protection becomes the attacker's best tool: whoever controls the dashboard can accept malicious changes. This chapter explains every layer protecting user accounts.

## Password storage with Argon2id

### Why not just store a SHA-256 of the password?

SHA-256 is designed to be **fast**. A modern graphics card can compute billions of SHA-256 hashes per second, so if the user table leaked, most passwords could be guessed quickly by trying dictionaries and common patterns. Password storage needs the opposite: a function that is **deliberately slow and memory-hungry**.

### How Argon2id works

**Argon2** won the Password Hashing Competition in 2015. The **id** variant combines resistance to GPU cracking and to side-channel attacks. It has three cost parameters:

| Parameter | Default (argon2-cffi) | Effect |
|---|---|---|
| `memory_cost` | 65,536 KiB (64 MB) | Every guess needs 64 MB of RAM, which makes GPU and custom-hardware cracking expensive |
| `time_cost` | 3 passes | Number of passes over that memory |
| `parallelism` | 4 lanes | Threads used |

Each password also gets a random 16-byte **salt**, so two users with the same password get different hashes and precomputed tables (rainbow tables) are useless. The output contains everything needed to verify later:

```
$argon2id$v=19$m=65536,t=3,p=4$<salt in base64>$<hash in base64>
```

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()
stored = ph.hash("correct horse battery staple")

def check(stored: str, attempt: str) -> bool:
    try:
        return ph.verify(stored, attempt)
    except VerifyMismatchError:
        return False
```

### Password policy

- Minimum 12 characters; no forced complexity rules (they produce predictable patterns), but reject the most common passwords.
- Never log passwords, never send them in URLs, never return them in API responses.

## Multi-factor authentication with TOTP

A stolen password alone must not be enough. **TOTP (Time-based One-Time Password, RFC 6238)** produces the 6-digit codes shown by apps such as Google Authenticator and Microsoft Authenticator.

### How TOTP works

1. **Setup**: the server generates a random 160-bit secret, encodes it in base32, and shows it as a QR code. The user scans it; now the phone and the server share the secret. The server stores it **encrypted**.
2. **Time step**: both sides compute `T = floor(current Unix time / 30)`. The value changes every 30 seconds.
3. **HMAC**: compute `HMAC-SHA1(secret, T as an 8-byte big-endian number)`, which gives 20 bytes.
4. **Dynamic truncation**: take the last 4 bits of the HMAC as an offset (0 to 15), read 4 bytes starting at that offset, and clear the top bit to get a 31-bit number.
5. **Reduce**: `code = number mod 1,000,000`, padded to 6 digits.

The phone and the server compute the same code independently, without communicating. An attacker who sees one code can use it for at most 30 seconds.

```python
import pyotp

secret = pyotp.random_base32()                   # store encrypted in users.mfa_secret
uri = pyotp.TOTP(secret).provisioning_uri(name="admin", issuer_name="FileVow")  # -> QR code
pyotp.TOTP(secret).verify("492039", valid_window=1)   # allow +/- 30 s clock drift
```

Protections:

- Accept only the current step plus or minus one, to tolerate clock drift.
- Remember the last accepted time step per user, and reject reuse of the same code (replay).
- Provide one-time **recovery codes** at setup (stored as Argon2 hashes) in case the phone is lost.

> NOTE: TOTP uses HMAC-SHA1. SHA-1's collision weakness does not affect HMAC, which relies on different properties. HMAC-SHA1 remains secure for this purpose and is what all authenticator apps support.

## Sessions with JWT

After login, the server must recognise the user on each request without asking for the password again. The system uses **JSON Web Tokens (JWT)**.

### Structure of a JWT

A JWT is three base64url-encoded parts separated by dots: `header.payload.signature`.

```
header   {"alg": "HS256", "typ": "JWT"}
payload  {"sub": "7", "role": "admin", "iat": 1764000000, "exp": 1764000900, "jti": "f3a9..."}
signature = HMAC-SHA256(server_secret, base64url(header) + "." + base64url(payload))
```

The server can check that a token is genuine and unmodified by recomputing the signature. The payload is **readable by anyone** (it is only encoded, not encrypted), so it must never contain secrets.

### Token policy

| Token | Lifetime | Stored where | Purpose |
|---|---|---|---|
| Access token | 15 minutes | `HttpOnly`, `Secure`, `SameSite=Strict` cookie | Sent with every request |
| Refresh token | 8 hours | `HttpOnly` cookie; its hash is stored in the database | Obtains a new access token |

- **HttpOnly** cookies cannot be read by JavaScript, which protects tokens from cross-site scripting.
- Refresh tokens are **rotated**: each use issues a new one and invalidates the old. If an old refresh token is ever reused, all sessions of that user are revoked (it indicates theft).
- Logout deletes the refresh token record, so the session cannot be renewed.
- The JWT secret is a random 256-bit value stored in Credential Manager.

## Step-up authentication for sensitive actions

Being logged in is not enough for dangerous actions. **Accept**, **Restore**, adding or removing monitored paths, rotating keys and managing users all require the password **and** a fresh TOTP code at the moment of the action. A stolen session cookie therefore cannot approve a malicious change. Accepting additionally requires the baseline key passphrase.

## Role-based access control (RBAC)

| Action | Viewer | Analyst | Admin |
|---|---|---|---|
| View dashboard, files, alerts, history | Yes | Yes | Yes |
| Acknowledge alerts, add notes | No | Yes | Yes |
| Reject (false positive), escalate | No | Yes | Yes |
| Accept changes, restore files | No | No | Yes (step-up + passphrase) |
| Add, edit, remove monitored paths | No | No | Yes (step-up) |
| Manage users, channels, keys | No | No | Yes (step-up) |
| View and verify audit log | No | Yes | Yes |

Authorisation is enforced on the **server**, in every API route, using a dependency that checks the role from the verified token. Hiding buttons in the dashboard is only a convenience, never the protection.

```python
def require_role(*roles):
    def checker(user = Depends(current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Not allowed")
        return user
    return checker

@router.post("/changes/{change_id}/accept")
def accept(change_id: int, body: AcceptBody, user = Depends(require_role("admin"))):
    ...
```

## Brute-force protection

- **Account lockout**: 5 failed logins lock the account for 15 minutes; an audit entry and an alert are created.
- **Rate limiting** with `slowapi`: for example 5 login attempts per minute per IP address, 30 requests per minute on sensitive endpoints.
- **Generic error messages**: "Invalid username or password" for every failure, so attackers cannot discover which usernames exist.
- **Constant-time comparison** for secrets (`hmac.compare_digest`), so response timing does not leak information.

# Security Hardening

This chapter collects the defensive details that turn a working prototype into a robust system. Each item explains the attack, then the defence.

## TOCTOU: time-of-check to time-of-use

**The attack**: the program checks a file, then uses it, assuming nothing changed in between. An attacker swaps the file in that gap. For example, the engine reads the size and modification time, decides "unchanged", and the attacker modifies the file a moment later; or the file is replaced during hashing so the hash covers half old and half new content.

**The defence**:

```python
def hash_stable(path):
    with open(path, "rb") as f:
        before = os.fstat(f.fileno())          # stats of the OPEN handle, not the path
        h = hashlib.sha256()
        while block := f.read(CHUNK):
            h.update(block)
        after = os.fstat(f.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ChangedDuringRead(path)          # retry up to 3 times, then report
    return h.hexdigest(), after
```

- Use stats from the **open file handle** (`os.fstat`), not a separate `os.stat(path)` call that could refer to a different file.
- Compare before and after; retry if the file changed during reading.
- When accepting a change, re-hash at the moment of acceptance and compare with what the admin saw (Chapter 11).
- When restoring, write to a temporary file and use an atomic replace.

## Symbolic links and junctions

**The attack**: an attacker replaces a monitored file with a **symbolic link** pointing to another file whose content matches, or replaces a folder with a **junction** pointing elsewhere, so the monitor checks the wrong location. Links can also trick the system into reading or restoring files outside the monitored area.

**The defence**:

- By default, do **not** follow links (`follow_symlinks=False` in `os.walk`, check `os.path.islink` and `Path.is_junction()`).
- Record whether each item is a regular file in the baseline; any change of type raises `TYPE_CHANGED`.
- Resolve every path with `Path.resolve()` and confirm it is still inside the monitored root before reading or restoring.

## Path traversal

**The attack**: the API accepts a path from the user, such as a file to restore or a path to monitor, and the attacker supplies `..\..\Windows\System32\config\SAM` to escape the intended folder.

**The defence**:

```python
def safe_join(root: Path, user_path: str) -> Path:
    target = (root / user_path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("Path outside allowed root")
    return target
```

- Restore operations accept a **change ID**, never a raw path: the path comes from the signed record.
- Monitored paths can only be added by admins with step-up authentication, and are validated (must exist, must not be inside the vault or database folders).

## Clock tampering

**The attack**: an attacker changes the system clock to confuse timestamps, make gaps look smaller, or make tokens and TOTP codes behave unexpectedly.

**The defence**:

- Store all times in **UTC**.
- Use a **monotonic clock** (`time.monotonic()`) for measuring intervals inside the agent; it cannot be changed by the user.
- Detect time going backwards between runs (a new run's start time earlier than the previous run's) and raise `CLOCK_ANOMALY`.
- Keep Windows time synchronisation enabled.

## Agent self-integrity

**The attack**: modify the FileVow code itself, for example making the verifier always return "OK".

**The defence**:

- At start-up and every run, the agent hashes its own source files and compares them with a signed **agent manifest** created at installation (signed with the baseline key).
- The FileVow installation folder is also a monitored path.
- The agent reports its code hash in its heartbeat; the dashboard displays it.

> NOTE: Self-checks cannot fully protect code that an attacker can already modify (they could also modify the check). They raise the effort and leave evidence, which is the realistic goal. Mention this limit honestly.

## Least privilege

- Run the agent as a dedicated Windows service account (for example `FileVow-svc`) with read access to monitored paths and write access only to the vault, database and log folders. Restore operations need write access to monitored files; grant it only where restore is enabled.
- Run the API server as a separate, unprivileged account if possible. It needs the database, not the monitored files.
- The baseline private key is never accessible to either service account.

## Web application security

| Risk | Defence |
|---|---|
| SQL injection | Only SQLAlchemy queries with bound parameters; no string-built SQL |
| Cross-site scripting (XSS) | React escapes output by default; never use `dangerouslySetInnerHTML` with file content; diff viewer renders text, not HTML; Content-Security-Policy header |
| Cross-site request forgery (CSRF) | `SameSite=Strict` cookies plus a CSRF token header on state-changing requests |
| CORS abuse | Allow only the dashboard's own origin |
| Clickjacking | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` |
| Eavesdropping | HTTPS only, even on the local network (a locally trusted certificate made with `mkcert` is fine); `Strict-Transport-Security` header |
| Information leakage | Generic error messages to clients; detailed errors only in server logs; disable debug mode and interactive docs in production |
| Oversized requests | Request size limits; pagination on all list endpoints |

## Secrets management

| Secret | Stored in | Never stored in |
|---|---|---|
| Baseline private key | Passphrase-encrypted PEM on removable media | Database, repository, service accounts |
| Agent private key | Credential Manager (DPAPI) | Database, files |
| Vault AES key | Credential Manager, plus an encrypted backup export | Database, config |
| JWT secret | Credential Manager | Config, repository |
| SMTP password, webhook URLs | Credential Manager, or encrypted in the database with the vault key | Plain config |
| User TOTP secrets | Database, encrypted with AES-GCM | Plain text |

Add `.env`, `*.pem`, `vault/` and `*.db` to `.gitignore`. Scan the repository before publishing it.

## Logging hygiene

- Use structured JSON logs (`structlog`) with rotation (for example 10 files of 10 MB).
- Never log passwords, passphrases, tokens, keys, TOTP codes or file contents.
- Log enough to investigate: event type, file path, hashes, user, IP address, run ID.
- Application logs are for debugging; the hash-chained audit log is the authoritative record.

## Database integrity

- SQLite settings: `PRAGMA foreign_keys=ON`, `PRAGMA journal_mode=WAL` (safe concurrent reads), `PRAGMA synchronous=FULL` for durability.
- Wrap multi-step operations (accepting a change) in a single transaction: either everything is saved or nothing is.
- Back up the database daily (SQLite's online backup API). Thanks to signatures and the audit chain, a restored backup is detected and explained rather than silently trusted.
- Restrict the database file's permissions like the vault.

## Dependency security

- Pin dependency versions in `requirements.txt` and run `pip-audit` regularly to detect libraries with known vulnerabilities.
- Install packages only from PyPI using a virtual environment.

# Threat Walkthrough

This chapter tests the design against concrete attack scenarios. For each one, follow the attacker's steps and see which layer stops them. This is also excellent material for your presentation.

## Scenario 1: Simple file modification

**Attack**: malware appends a malicious script tag to `index.html`.
**Detection**: Layer 1. The live SHA-256 differs from the signed record. `FILE_MODIFIED` (High). Evidence copy saved, the diff shows the inserted line, the admin restores the mirror copy.

## Scenario 2: Modify the file and its stored hash

**Attack**: the attacker edits `config.php`, then updates `file_baselines.sha256` in the database to the new hash.
**Detection**: Layer 2. The RSA signature was computed over the old record; verification fails. `RECORD_TAMPERED` (Critical). The original content is still in the vault.

## Scenario 3: Forge a new signature

**Attack**: the attacker tries to sign the modified record.
**Result**: impossible without the baseline private key, which is encrypted with a passphrase and kept offline. Breaking RSA-3072 is computationally infeasible.

## Scenario 4: Replace the public key

**Attack**: the attacker generates their own key pair, replaces the public key in `signing_keys`, and re-signs all records.
**Detection**: fingerprint pinning. The fingerprint of the database key no longer matches the pinned fingerprint in the config and in Credential Manager. `KEY_SUBSTITUTION_DETECTED` (Critical). If they also edit the config file, that file's own signed record fails verification.

## Scenario 5: Rollback attack

**Attack**: the attacker has a backup from last month containing an old version of `config.php` (version 2) together with its genuine signed record. Today's record is version 4. They restore both the old file and the old record. Every signature is genuine.
**Detection**:

- The signed record contains `version: 2`, but `file_versions` contains versions 3 and 4 for this file. The engine requires the record's version to equal the highest known version: `ROLLBACK_DETECTED` (Critical).
- The audit chain contains signed entries for the approvals of versions 3 and 4, protected by agent-signed checkpoints.
- If the attacker rolls back the **entire database**, the locally stored latest checkpoint in Credential Manager is newer than anything in the database: `DATABASE_ROLLBACK_DETECTED`.

> KEY IDEA: Signatures prove a record was genuine **at some point**. Proving it is the **current** genuine record requires a version number inside the signature plus an independent memory of the latest state.

## Scenario 6: Corrupt or swap mirror objects

**Attack**: the attacker modifies a vault object, or renames an old object to the name of the current one, so that a restore would bring back malicious content.
**Detection**: Layer 3. AES-GCM authentication fails for modified objects; the AAD (object name) fails for swapped objects; the decrypted hash must equal the signed record's hash. `MIRROR_CORRUPTED`. A restore refuses to use an object that fails verification.

## Scenario 7: Stop the agent, change files, restore them

**Attack**: stop the FileVow service, modify a file for a few hours, put the original back, restart the service.
**Detection**: `MONITORING_GAP` (High) with the exact unmonitored period, from the start-up gap check and the server's heartbeat monitor. The audit log records `AGENT_STOPPED` and `AGENT_STARTED`. The admin knows to investigate that window even though the files now match.

## Scenario 8: Reset the timestamp after editing

**Attack**: edit a file, then reset its modification time to the original value to defeat quick checks.
**Detection**: deep scans re-hash content regardless of timestamps. With deep scans every run (the default), detection happens at the next run.

## Scenario 9: Replace a file with a symbolic link

**Attack**: replace `app.dll` with a link to an unmonitored copy that the attacker controls.
**Detection**: the type check finds a link instead of a regular file: `TYPE_CHANGED`. Links are never followed.

## Scenario 10: Tamper with the audit log

**Attack**: delete the audit entry showing a suspicious acceptance, or rewrite the whole chain.
**Detection**: the next entry's `prev_hash` no longer matches (`AUDIT_CHAIN_BROKEN`); a rebuilt chain no longer matches the agent-signed checkpoints.

## Scenario 11: Stolen dashboard password

**Attack**: the attacker phishes an admin's password and tries to accept their malicious change.
**Result**: login requires a TOTP code. Even with a hijacked session, accepting requires a fresh password and TOTP entry plus the baseline key passphrase and key file. Repeated failures lock the account and raise an alert.

## Scenario 12: Ransomware encrypts many files

**Attack**: hundreds of files are rewritten within minutes.
**Detection**: real-time watcher events and the next run produce many `FILE_MODIFIED` events; burst grouping produces one Critical summary ("412 files modified in 3 minutes"). All originals are in the encrypted vault and can be restored in bulk once the machine is cleaned.

## Summary matrix

| Scenario | SHA-256 | RSA | Mirror | Version / chain | Gap and heartbeat | Auth |
|---|---|---|---|---|---|---|
| 1 Modify file | Detects | | Restores | | | |
| 2 Modify file and hash | | Detects | Restores | | | |
| 4 Replace public key | | Pinning detects | | | | |
| 5 Rollback | | | | Detects | | |
| 6 Corrupt mirror | | | Detects | | | |
| 7 Stop agent | | | | Logged | Detects | |
| 8 Reset timestamp | Detects (deep scan) | | | | | |
| 10 Edit audit log | | Checkpoints | | Detects | | |
| 11 Stolen password | | Passphrase | | Logged | | Blocks |
| 12 Ransomware | Detects | | Restores | | | |
