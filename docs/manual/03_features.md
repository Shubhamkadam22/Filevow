[[PART:Part III — Core Features|Mirror vault, baselining, the verification engine, review workflow, alerts and the audit log]]

# The Mirror Vault

## Purpose

The mirror vault keeps an **encrypted reference copy** of every monitored file, and of every approved version of it. It answers questions that hashes alone cannot:

- *What exactly changed?* The dashboard can show a line-by-line diff between the mirror copy and the current file.
- *Can we get the original back?* Yes, the mirror copy can be restored.
- *What did the attacker put there?* The suspicious version is preserved as an **evidence copy**, even if the attacker later deletes it.

## Content addressing

Every object in the vault is named by the **SHA-256 hash of its plaintext content**. This approach is called **content-addressable storage**; Git uses the same idea.

```
C:\FileVow\vault\
    objects\
        9f\
            9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
        a1\
            a1c3e5...
```

- The first two hex characters form a sub-folder, so no single folder holds millions of files.
- **Automatic deduplication**: if 50 files have identical content, or a file is changed and then changed back, the content is stored once.
- **Built-in verification**: after decrypting an object, hashing the plaintext must give its own name. If it does not, the object is corrupt.

## Object format

```
[ 12-byte nonce ][ AES-256-GCM ciphertext of zstd(content) ][ 16-byte tag ]
AAD = the object's SHA-256 name
```

## Storing an object safely

```python
from pathlib import Path

def store(src: Path, sha256: str, key: bytes, vault: Path) -> Path:
    obj = vault / "objects" / sha256[:2] / sha256
    if obj.exists():
        return obj                                   # deduplicated
    data = src.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha256:   # file changed while we read it
        raise ChangedDuringRead(src)
    obj.parent.mkdir(parents=True, exist_ok=True)
    tmp = obj.with_name(obj.name + ".tmp")
    tmp.write_bytes(seal(data, key, sha256))
    os.replace(tmp, obj)                             # atomic rename
    return obj
```

### Why the temporary file and `os.replace`?

If the program crashed halfway through writing, a half-written object would sit in the vault under a valid name. Writing to a temporary file and then renaming it with `os.replace` is **atomic** on the same volume: the object either exists completely or not at all.

> NOTE: For very large files (hundreds of MB), read and encrypt in a streaming fashion, or store large files in fixed-size encrypted chunks, to avoid loading the whole file into memory. For the project, a size limit (for example 200 MB per mirrored file) with a clear warning is acceptable.

## Two kinds of objects

| Kind | Created when | Purpose |
|---|---|---|
| `baseline` | A file is baselined or a change is accepted | The trusted reference copy |
| `evidence` | A suspicious change is detected | Forensic copy of the unapproved version |

Both are stored identically; the `mirror_objects.kind` column records which is which.

## Versioning

Every accepted version of a file points to its own vault object through the `file_versions` table. Nothing is overwritten. An admin can view the history of a file, diff any two versions, and roll back to any earlier approved version (the rollback itself is a new, signed version, so history only moves forward).

## Verifying the mirror

During each verification run, for each file:

1. Load the object referenced by the signed record (`mirror_object_sha256`).
2. Decrypt it. A tampered object raises `InvalidTag`, giving the result **MIRROR_CORRUPTED**.
3. Hash the plaintext. It must equal both the object name and the signed record's `sha256`.

> WARNING: Decrypting every mirror object every 15 minutes can be slow for large file sets. A good compromise: verify the mirror of every file whose live hash **mismatches** (you need it for the diff anyway), and verify a rotating sample of the remaining objects each run so that the whole vault is fully checked once a day. Make the policy configurable.

## Restoring a file

Restore always requires an authenticated admin decision (Chapter 11). The procedure:

1. Save the current (suspicious) file as an evidence object, if not already saved.
2. Decrypt the mirror object and verify its hash against the signed record.
3. Write the content to a temporary file in the same folder as the target.
4. Re-apply the expected permissions.
5. Atomically replace the target with `os.replace`.
6. Re-hash the restored file and confirm it matches the record.
7. Mark the change event `RESTORED` and write an audit entry.

## Protecting the vault folder

- On Windows, restrict the folder to `SYSTEM`, `Administrators` and the FileVow service account:

```
icacls C:\FileVow\vault /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "FileVow-svc:(OI)(CI)M"
```

- Place the vault on a different drive from the monitored files when possible.
- **Optional secondary mirror**: replicate objects to a second drive or network share. Objects are immutable and content-addressed, so replication is a simple copy of objects that are missing.

## Retention

Evidence objects can be kept for a configurable period (for example 180 days) after the change is resolved. Baseline objects referenced by any `file_versions` row are never deleted automatically.

# Baseline Creation

## What a baseline is

A **baseline** is the approved, trusted state of a file. Creating it means recording everything needed to recognise that state later, protecting that record with a signature, and storing a copy.

## Choosing what to monitor

Each **monitored path** has settings:

| Setting | Example | Meaning |
|---|---|---|
| `path` | `C:\inetpub\wwwroot` | A file or folder |
| `recursive` | `true` | Include sub-folders |
| `include_patterns` | `["*.html", "*.php", "*.js", "*.config"]` | Only these files (empty means all) |
| `exclude_patterns` | `["*.log", "*.tmp", "cache/*"]` | Skip these files |
| `severity` | `high` | Severity of alerts for files under this path |
| `mirror_enabled` | `true` | Keep reference copies |
| `follow_symlinks` | `false` | Do not follow links outside the path |

Good candidates: system configuration (`C:\Windows\System32\drivers\etc\hosts`), web roots, application binaries and DLLs, scripts, service configuration, and the FileVow configuration itself. Poor candidates: logs, caches, temp folders, databases that change constantly.

## Metadata collected for each file

| Field | Source on Windows | Why |
|---|---|---|
| SHA-256 | chunked hashing | Content identity |
| Size | `os.stat().st_size` | Quick change indicator |
| Modification time | `os.stat().st_mtime_ns` | Quick change indicator (not trusted alone) |
| File ID | `os.stat().st_ino` (NTFS file index) | Detects a file being replaced by a different file with the same name; supports rename detection |
| Read-only flag / mode | `os.stat().st_mode` | Basic permission change |
| Owner | `win32security.GetFileSecurity` (pywin32) | Ownership change |
| ACL summary | hash of the security descriptor (pywin32) | Permission changes such as granting "Everyone: Full control" |
| Is link / junction | `os.path.islink`, `Path.is_junction()` | A file silently replaced by a link |

## The baseline procedure

1. **Walk** every monitored path, applying include and exclude patterns and skipping links unless allowed.
2. **Hash and collect metadata** for each file, using the TOCTOU-safe reading procedure from Chapter 15.
3. **Mirror**: store an encrypted copy in the vault (deduplicated).
4. **Build** the canonical integrity record, version 1.
5. **Unlock** the baseline private key once. The admin enters the passphrase.
6. **Sign** every record. Signing is fast (a few milliseconds per record), so thousands of files take seconds.
7. **Save** the records in `file_baselines` and `file_versions`.
8. **Discard** the private key from memory.
9. **Audit**: append an entry `BASELINE_CREATED` with the count of files and the monitored path.

```
filevow baseline --path "C:\inetpub\wwwroot"
Scanning...          1,284 files found (37 excluded)
Hashing + mirroring  [##########] 100%
Enter baseline key passphrase: ********
Signing              1,284 records signed with key a1b2c3d4e5f60718
Baseline complete.
```

> SECURITY: Create the baseline only when you trust the current state of the files, for example right after a clean installation or deployment. A baseline taken from an already-compromised system faithfully protects the compromise.

# The Verification Engine

The verification engine is the heart of the system. It runs automatically every 15 minutes, checks every monitored file against all three layers, and records anything suspicious without ever accepting it.

## Two ways checks are triggered

| Trigger | How | Strength | Weakness |
|---|---|---|---|
| Real-time watcher | The OS notifies `watchdog` of file events | Detects within seconds | Can miss events (buffer overflow, agent stopped) |
| 15-minute scheduled run | `APScheduler` interval job | Complete: checks every file regardless of events | Up to 15 minutes delay |

They complement each other: the watcher is fast, the scheduled run is thorough. The scheduled run is the authoritative check required by the specification.

## The scheduler

```python
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler(timezone="UTC")
scheduler.add_job(run_verification, "interval", minutes=15,
                  id="verify_15min",
                  max_instances=1,         # never run two verifications at once
                  coalesce=True,           # if several runs were missed, run only once
                  misfire_grace_time=300,  # still run if up to 5 minutes late
                  next_run_time=datetime.now(timezone.utc))   # run immediately at start-up
scheduler.start()
```

- **max_instances=1**: if a run takes longer than 15 minutes, the next one waits instead of overlapping.
- **coalesce=True**: after the machine wakes from sleep, the engine runs once, not ten times.
- **Run at start-up**: whenever the agent starts, it checks everything immediately, because files may have changed while it was stopped.

## The per-file algorithm

```
for each active record in file_baselines:
    1. SIGNATURE   verify RSA signature of the canonical record with the pinned public key
                   fails            -> RECORD_TAMPERED, stop checking this file
    2. VERSION     record.version must equal the highest version in file_versions
                   lower            -> ROLLBACK_DETECTED
    3. EXISTENCE   does the file exist?
                   no               -> FILE_DELETED
    4. TYPE        is it still a regular file (not a link, junction or folder)?
                   no               -> TYPE_CHANGED
    5. CONTENT     compute SHA-256 (TOCTOU-safe)
                   differs          -> FILE_MODIFIED
    6. MIRROR      (if mismatch, or file is in today's sample) decrypt + hash mirror object
                   fails            -> MIRROR_CORRUPTED
    7. METADATA    compare size, file ID, owner, ACL hash
                   differs only     -> PERMISSION_CHANGED / OWNER_CHANGED
    8. RECORD      write a verification_results row
    9. ON ISSUE    capture evidence copy, create change_event (PENDING_REVIEW), raise alert
   10. ON OK       update last_verified_at
then: scan monitored folders for files that have no record -> UNKNOWN_FILE_CREATED
```

### Why the signature is checked first

If the record itself is forged, every other comparison is meaningless: comparing a file against a fake reference proves nothing. Trust in the reference must be established before using it.

### Quick check versus deep check

Re-hashing every file every 15 minutes is the safest approach and is fast for typical sets (SHA-256 processes several hundred MB per second). For very large sets, the engine can skip hashing files whose size, modification time and file ID are unchanged, and perform a **deep scan** (re-hash everything) nightly.

> SECURITY: Modification times can be forged with a single API call. A quick-check-only system can be bypassed by an attacker who resets the timestamp after editing. Always keep periodic deep scans, and default to deep scans every run unless performance requires otherwise.

## The decision table

The engine combines the individual results into one outcome.

[[DIAGRAM:layers]]

| Signature | Mirror | Live file | Outcome | Default severity |
|---|---|---|---|---|
| invalid | any | any | RECORD_TAMPERED: the reference data was altered | Critical |
| valid, but version lower than history | any | any | ROLLBACK_DETECTED | Critical |
| valid | valid | hash matches | OK | none |
| valid | valid | hash differs | FILE_MODIFIED, restore available | Path severity (High by default) |
| valid | valid | missing | FILE_DELETED, restore available | High |
| valid | invalid | hash matches | MIRROR_CORRUPTED: the file is fine, the copy is damaged | High |
| valid | invalid | hash differs | FILE_MODIFIED_NO_CLEAN_COPY | Critical |
| valid | valid | same hash, link or folder now | TYPE_CHANGED | High |
| valid | valid | same hash, ACL or owner changed | PERMISSION_CHANGED / OWNER_CHANGED | Medium |
| no record | n/a | new file in a monitored folder | UNKNOWN_FILE_CREATED | Medium (High for `.exe`, `.dll`, `.ps1`, `.bat`) |

**Rename detection**: if in the same run a file is `FILE_DELETED` and an unknown file appears with the **same hash** (and often the same file ID), the two are merged into a single `FILE_RENAMED` event.

## What the engine never does

- It **never updates a baseline**. Not even when a change "looks harmless".
- It **never restores automatically** by default. (An optional per-path setting `auto_restore` can be offered for extremely critical files, but it still records evidence and an event, and it is off by default.)
- It **never deletes** anything.

## Signed verification reports

At the end of each run the engine builds a summary: run ID, start and end times, number of files checked, number OK, list of issues, and the SHA-256 of all individual results. The canonical summary is signed with the **agent key** and stored in `verification_runs`. These signed reports form a verifiable record that monitoring really happened, which is useful for audits and compliance.

## Monitoring-gap detection

An attacker's simplest move is to stop the agent, make changes, restore the files and restart the agent. The system defends against this in three ways:

1. **Start-up check**: every agent start triggers an immediate full verification.
2. **Gap detection**: at start-up and every run, the engine compares the time since the last **completed** run. If it exceeds 20 minutes, it raises `MONITORING_GAP` (High), stating the exact unmonitored period.
3. **Heartbeat**: the agent writes a heartbeat every minute. The API server raises an alert if the heartbeat is older than 5 minutes, so the dashboard shows "agent offline" even when the agent itself cannot report.

## Real-time watcher and debouncing

```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class Handler(FileSystemEventHandler):
    def on_any_event(self, event):
        if not event.is_directory:
            debouncer.touch(event.src_path)     # check this path 2 seconds after the LAST event
```

Saving a file in many editors triggers several events (create temp file, write, rename, change attributes). **Debouncing** waits until no new event has arrived for a path for about 2 seconds, then runs the per-file algorithm once. Events from the vault, database and log folders are ignored to avoid feedback loops.

## Performance guidelines

- Use a thread pool (4 workers is typical) for hashing; disk speed is usually the limit.
- Open files with shared read access so applications are not blocked.
- Handle locked files (`PermissionError`) by retrying, then recording `UNREADABLE` with a warning, never silently skipping.
- Store per-run statistics so you can show "1,284 files verified in 9.4 s" on the dashboard.

# Change Review Workflow

## Why nothing is accepted automatically

If the system accepted changes automatically, an attacker would only need to wait for the next run for their modification to become the new "trusted" baseline. Requiring a human decision for every change, protected by strong authentication and the offline private key, means an attacker who controls the machine still cannot make their change trusted.

## States of a change

[[DIAGRAM:lifecycle]]

| State | Meaning | Who can set it |
|---|---|---|
| PENDING_REVIEW | Detected, waiting for a decision. The file is still flagged on every run | System |
| ACCEPTED | The change is legitimate; a new signed version was created | Admin |
| RESTORED | The approved mirror copy was put back | Admin |
| REJECTED | Marked as a false positive or not requiring action; baseline unchanged | Admin, Analyst |
| ESCALATED | Sent to more people for investigation | Admin, Analyst, or the system after a timeout |

While a change is pending, every verification run keeps reporting it (grouped into the same event, not new alerts), so it cannot be forgotten.

## The review screen

For each pending change the dashboard shows:

- File path, monitored path, severity, detection time, and which run found it.
- Expected hash versus observed hash; expected versus observed size, owner and permissions.
- A **side-by-side diff** for text files (mirror version against evidence version). Binary files show size and hash differences and offer a download of both versions to admins.
- The file's version history.
- Buttons: **Accept**, **Restore**, **Reject**, **Escalate**, each requiring a written reason.

## Accepting a change

1. The admin clicks **Accept** and writes a reason (for example "Deployment of release 2.4, ticket CHG-1182").
2. **Step-up authentication**: the admin re-enters their password and a fresh TOTP code, even if already logged in.
3. The admin enters the **baseline key passphrase**. The key file must be available.
4. The system re-hashes the current file and confirms it still equals the evidence hash shown on screen. If the file changed again in the meantime, the acceptance is refused, because the admin would be approving content they have not seen.
5. The evidence object becomes the new baseline object (no re-upload needed, it is already in the vault).
6. A new integrity record with `version + 1` is built and signed.
7. `file_baselines` and `file_versions` are updated in **one database transaction**.
8. The change event becomes ACCEPTED with the reviewer and time; an audit entry is appended.
9. The private key is erased from memory.

## Restoring a file

Same step-up authentication (password and TOTP), but no private key is needed because the baseline does not change. The restore procedure in Chapter 8 is executed, and the event becomes RESTORED.

## Rejecting and escalating

- **Reject** keeps the baseline as it is. If the file still differs, it will be detected again on the next run, as it should be. Reject is therefore mainly for changes that have already been reversed manually, or for noise such as a permission change that is verified as harmless and then fixed.
- **Escalate** raises the alert level and notifies the escalation contacts.

## Bulk approvals

After a software update, hundreds of files may change at once. The dashboard allows selecting multiple pending changes from the same monitored path and accepting them in one step (one passphrase entry, one reason, one audit entry listing all files). Each file still gets its own signed record.

# Alerts and Notifications

## Severity levels

| Severity | Typical events | Default channels |
|---|---|---|
| Critical | RECORD_TAMPERED, ROLLBACK_DETECTED, KEY_SUBSTITUTION_DETECTED, AUDIT_CHAIN_BROKEN, FILE_MODIFIED_NO_CLEAN_COPY | All channels, immediate, escalate after 15 min |
| High | FILE_MODIFIED, FILE_DELETED, MIRROR_CORRUPTED, MONITORING_GAP, TYPE_CHANGED | Email, desktop, dashboard; escalate after 60 min |
| Medium | PERMISSION_CHANGED, OWNER_CHANGED, UNKNOWN_FILE_CREATED | Dashboard, daily email digest |
| Low | UNREADABLE file warnings, informational | Dashboard only |

Severity can be raised automatically by rules: executable or script extensions, changes outside business hours, or many changes in a short time (a possible ransomware pattern).

## Channels

| Channel | Implementation | Notes |
|---|---|---|
| Dashboard (live) | WebSocket push from FastAPI | Always on |
| Desktop toast | `plyer` notification | For the machine running the agent |
| Email | `smtplib` with TLS | SMTP password stored in Credential Manager |
| Slack / Discord / Teams | HTTPS webhook | Webhook URL stored encrypted |
| Generic webhook | HTTPS POST with JSON body | For integration with SIEM tools |

## Routing and grouping

- Each channel has a `min_severity`. An alert is sent to every enabled channel whose minimum it meets.
- **Grouping**: repeated detections of the same unresolved change do not create new alerts; they update the existing one (`occurrence_count`, `last_seen_at`).
- **Burst grouping**: if more than 20 alerts are produced within one minute, they are combined into one summary notification ("57 files modified under C:\inetpub\wwwroot") to avoid flooding.
- **Escalation**: if an alert is not acknowledged within its escalation time, `escalation_level` increases and the escalation contacts are notified.
- Every delivery attempt is recorded in `notification_log`. Failed deliveries are retried with increasing delays (1, 5, 15 minutes).

## What an alert message contains

Alert messages contain what is needed to act, but **never secrets or file contents**:

```
[HIGH] FILE_MODIFIED  C:\inetpub\wwwroot\index.html
Detected: 2026-11-23 10:30:12 UTC (run #4182)
Expected SHA-256: 9f86d081...0a08   Observed: a1c3e5f7...77b2
Size: 5,120 -> 5,388 bytes
Review: https://filevow.local/changes/918
```

# The Hash-Chained Audit Log

## Why the audit log needs protection

The audit log records who accepted, restored or rejected each change, who logged in, who added monitored paths and who rotated keys. If an attacker can delete the entry showing that "admin accepted a modified `login.php` at 02:13", they erase their tracks. So the log itself must be **tamper-evident**.

## The hash chain

Each audit entry stores the hash of the previous entry, and its own hash covers that value:

```
entry_hash(n) = SHA-256( prev_hash(n) || canonical(entry n without entry_hash) )
prev_hash(n)  = entry_hash(n-1)
prev_hash(1)  = 64 zeros ("genesis")
```

```
+-----------------+      +-----------------+      +-----------------+
| #1 LOGIN        |      | #2 ADD_PATH     |      | #3 ACCEPT       |
| prev: 0000...   | ---> | prev: 7a3f...   | ---> | prev: c91e...   |
| hash: 7a3f...   |      | hash: c91e...   |      | hash: 52bd...   |
+-----------------+      +-----------------+      +-----------------+
```

This is the same principle used by blockchains, without the distributed consensus.

## What the chain detects

| Tampering | How it is detected |
|---|---|
| Modifying an entry | Its recomputed hash no longer matches its stored `entry_hash` |
| Modifying an entry and fixing its hash | The next entry's `prev_hash` no longer matches |
| Deleting an entry in the middle | The following entry's `prev_hash` points to a hash that no longer exists |
| Re-computing the entire chain after a change | Detected by signed checkpoints (below) |
| Deleting the most recent entries (truncation) | Detected by signed checkpoints and the locally stored chain head |

## Signed checkpoints

A chain alone can be rebuilt by an attacker with database access: change an entry, then recompute every following hash. To prevent this, every 15 minutes (with each verification run) the agent signs the current chain head:

```
checkpoint = { last_entry_id: 1832, entry_hash: "52bd...", created_at: "..." }
signature  = RSA-PSS(agent key, canonical(checkpoint))
```

Recomputing the chain changes the hashes, so they no longer match the signed checkpoints, and the attacker does not have the agent private key to re-sign them.

## Defending against database rollback

An attacker could restore the entire database from an old backup, which is internally consistent: old chain, old checkpoints, old valid signatures. To detect this, the agent also stores the **latest checkpoint ID and hash in Windows Credential Manager**, outside the database. At start-up and each run, if the database's newest checkpoint is older than the locally remembered one, the agent raises `DATABASE_ROLLBACK_DETECTED` (Critical).

## Verifying the chain

```python
def verify_chain(entries) -> int | None:
    prev = "0" * 64
    for e in entries:                          # ordered by id
        if e.prev_hash != prev:
            return e.id                        # chain broken here
        expected = sha256((prev + canonical_entry(e)).encode()).hexdigest()
        if expected != e.entry_hash:
            return e.id                        # entry modified
        prev = e.entry_hash
    return None                                # chain intact
```

The chain is verified fully once a day and from the last checkpoint onwards on every run. A broken chain raises `AUDIT_CHAIN_BROKEN` (Critical), naming the first bad entry.

## What is logged

| Category | Actions |
|---|---|
| Authentication | LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, MFA_ENABLED, ACCOUNT_LOCKED, PASSWORD_CHANGED |
| Configuration | PATH_ADDED, PATH_UPDATED, PATH_REMOVED, CHANNEL_ADDED, SETTINGS_CHANGED |
| Baselines | BASELINE_CREATED, CHANGE_ACCEPTED, CHANGE_RESTORED, CHANGE_REJECTED, CHANGE_ESCALATED, ROLLBACK_TO_VERSION |
| Keys | KEY_GENERATED, KEY_ROTATED, KEY_REVOKED |
| System | AGENT_STARTED, AGENT_STOPPED, MONITORING_GAP, CHAIN_VERIFIED |

Each entry stores the actor, action, target, a JSON details field, the client IP address and a UTC timestamp. Inserts are serialised (one writer at a time) so that two entries never share the same `prev_hash`.
