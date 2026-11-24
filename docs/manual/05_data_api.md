[[PART:Part V — Data, API and Interfaces|The complete database design, REST API, dashboard pages and command-line tool]]

# Database Design

## Choice of database

The project starts with **SQLite**: a single file, no server, included with Python, and fully transactional. All access goes through **SQLAlchemy**, so moving to **PostgreSQL** later (for example to support several agents on different machines) only requires changing the connection URL and running the migrations.

```
SQLite:      sqlite:///C:/FileVow/data/filevow.db
PostgreSQL:  postgresql+psycopg://filevow:<password>@localhost/filevow
```

## Entity-relationship overview

```
 users ----------< refresh_tokens
   |
   +--< change_events (reviewed_by)        +--< audit_log >-- (actor)
   +--< file_versions (approved_by)        |        |
   +--< alerts (acknowledged_by)           |        +--< audit_checkpoints
                                           |
 signing_keys --< file_baselines >-- monitored_paths
                    |      |
                    |      +--< file_versions >-- mirror_objects
                    |      |                          ^
                    |      +--< change_events --------+ (evidence)
                    |               |
                    |               +--< alerts --< notification_log >-- notification_channels
                    |
                    +--< verification_results >-- verification_runs

 agent_heartbeats   (standalone)
 ----<  means "one to many"
```

## Table reference

Types are given in portable SQLAlchemy terms. `PK` = primary key, `FK` = foreign key, `NN` = not null, `UQ` = unique. All timestamps are stored in UTC.

### users

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| username | String(64) | UQ, NN | Login name |
| password_hash | String(255) | NN | Argon2id string |
| role | Enum(admin, analyst, viewer) | NN | RBAC role |
| mfa_secret_enc | LargeBinary | | TOTP secret, AES-GCM encrypted |
| mfa_enabled | Boolean | NN, default false | |
| last_totp_step | Integer | | Prevents TOTP code reuse |
| recovery_codes | JSON | | Argon2 hashes of one-time recovery codes |
| failed_attempts | Integer | NN, default 0 | For lockout |
| locked_until | DateTime | | Lockout end |
| is_active | Boolean | NN, default true | Disabled accounts cannot log in |
| last_login_at | DateTime | | |
| created_at | DateTime | NN | |

### refresh_tokens

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| user_id | Integer | FK users, NN | |
| token_hash | String(64) | UQ, NN | SHA-256 of the refresh token (the token itself is never stored) |
| issued_at, expires_at | DateTime | NN | |
| revoked_at | DateTime | | Set on logout, rotation or theft detection |
| replaced_by_id | Integer | FK refresh_tokens | Rotation chain |
| ip_address, user_agent | String | | Session information |

### signing_keys

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| key_id | String(16) | UQ, NN | First 16 hex characters of the fingerprint |
| fingerprint | String(64) | UQ, NN | SHA-256 of the DER public key |
| purpose | Enum(baseline, agent) | NN | Which of the two keys |
| algorithm | String(40) | NN | `RSA-3072-PSS-SHA256` |
| public_key_pem | Text | NN | Public key only; private keys are never stored here |
| status | Enum(active, retired, revoked) | NN | |
| created_at | DateTime | NN | |
| retired_at, revoked_at | DateTime | | |

### monitored_paths

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| path | Text | UQ, NN | Normalised absolute path |
| is_directory | Boolean | NN | |
| recursive | Boolean | NN, default true | |
| include_patterns | JSON | | Glob patterns, empty = all |
| exclude_patterns | JSON | | Glob patterns to skip |
| severity | Enum(low, medium, high, critical) | NN, default high | |
| mirror_enabled | Boolean | NN, default true | |
| follow_symlinks | Boolean | NN, default false | |
| auto_restore | Boolean | NN, default false | Optional, critical files only |
| enabled | Boolean | NN, default true | |
| created_by | Integer | FK users | |
| created_at, updated_at | DateTime | NN | |

### mirror_objects

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| sha256 | String(64) | UQ, NN | Plaintext content hash, also the object's name |
| storage_path | Text | NN | Relative path inside the vault |
| original_size | BigInteger | NN | Bytes before compression |
| stored_size | BigInteger | NN | Bytes on disk |
| encryption | String(20) | NN | `AES-256-GCM` |
| compression | String(20) | NN | `zstd` |
| kind | Enum(baseline, evidence) | NN | |
| replicated | Boolean | NN, default false | Copied to the secondary mirror |
| last_verified_at | DateTime | | |
| created_at | DateTime | NN | |

### file_baselines

The current signed integrity record of each monitored file.

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | Also `record_id` in the signed record |
| monitored_path_id | Integer | FK monitored_paths, NN | |
| file_path | Text | UQ, NN | Normalised absolute path |
| current_version | Integer | NN | Matches the latest file_versions row |
| sha256 | String(64) | NN | Approved content hash |
| file_size | BigInteger | NN | |
| file_id | BigInteger | | NTFS file index (`st_ino`) |
| permissions | String(64) | | Mode or read-only flag |
| owner | String(256) | | Owner account |
| acl_hash | String(64) | | SHA-256 of the security descriptor |
| file_type | Enum(regular, link, junction) | NN | Expected type (normally regular) |
| mirror_object_id | Integer | FK mirror_objects | |
| rsa_signature | LargeBinary | NN | 384-byte RSA-PSS signature |
| signing_key_id | Integer | FK signing_keys, NN | |
| signed_at | DateTime | NN | |
| status | Enum(active, pending_review, deleted) | NN | |
| last_verified_at | DateTime | | Last time all checks passed |
| created_at, updated_at | DateTime | NN | |

### file_versions

The full, append-only signed history.

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| file_baseline_id | Integer | FK file_baselines, NN | |
| version | Integer | NN, UQ with file_baseline_id | 1, 2, 3... |
| sha256 | String(64) | NN | |
| file_size | BigInteger | NN | |
| mirror_object_id | Integer | FK mirror_objects | |
| signed_record | JSON | NN | The exact record that was signed |
| rsa_signature | LargeBinary | NN | |
| signing_key_id | Integer | FK signing_keys, NN | |
| approved_by | Integer | FK users | NULL for the initial baseline made via CLI |
| approval_reason | Text | | |
| change_event_id | Integer | FK change_events | The change that led to this version |
| created_at | DateTime | NN | |

### verification_runs

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| run_type | Enum(scheduled, startup, manual, realtime, baseline) | NN | |
| scheduled_for | DateTime | | Planned time |
| started_at | DateTime | NN | |
| finished_at | DateTime | | |
| status | Enum(running, completed, failed, missed) | NN | |
| files_checked, ok_count, issue_count | Integer | | Statistics |
| duration_ms | Integer | | |
| results_sha256 | String(64) | | Hash over all result rows |
| report_json | JSON | | Canonical signed summary |
| agent_signature | LargeBinary | | Signed with the agent key |
| error_message | Text | | |

### verification_results

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| run_id | Integer | FK verification_runs, NN | |
| file_baseline_id | Integer | FK file_baselines, NN | |
| signature_valid | Boolean | NN | Layer 2 |
| version_valid | Boolean | NN | Rollback check |
| mirror_valid | Boolean | | Layer 3 (NULL if not sampled this run) |
| content_match | Boolean | | Layer 1 (NULL if the file is missing) |
| metadata_match | Boolean | | |
| observed_sha256 | String(64) | | |
| outcome | String(40) | NN | OK or an event type from the decision table |
| checked_at | DateTime | NN | |

> NOTE: This table grows quickly (one row per file every 15 minutes). Keep detailed rows for 30 days, then delete OK rows and keep only non-OK rows. The signed run summaries remain permanently.

### change_events

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| file_baseline_id | Integer | FK file_baselines | NULL for unknown new files |
| file_path | Text | NN | |
| run_id | Integer | FK verification_runs | First detecting run |
| event_type | String(40) | NN | FILE_MODIFIED, RECORD_TAMPERED, ... |
| severity | Enum(low, medium, high, critical) | NN | |
| expected_sha256, observed_sha256 | String(64) | | |
| expected_size, observed_size | BigInteger | | |
| details | JSON | | Metadata differences |
| evidence_object_id | Integer | FK mirror_objects | Copy of the suspicious version |
| review_status | Enum(pending_review, accepted, restored, rejected, escalated) | NN | |
| reviewed_by | Integer | FK users | |
| reviewed_at | DateTime | | |
| review_reason | Text | | Required for every decision |
| detected_at, last_seen_at | DateTime | NN | First and latest detection |
| occurrence_count | Integer | NN, default 1 | Grouped repeat detections |

### alerts

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| change_event_id | Integer | FK change_events | NULL for system alerts such as MONITORING_GAP |
| alert_type | String(40) | NN | |
| severity | Enum | NN | |
| title, message | Text | NN | Never contains secrets or file contents |
| status | Enum(new, acknowledged, resolved) | NN | |
| acknowledged_by | Integer | FK users | |
| acknowledged_at | DateTime | | |
| escalation_level | Integer | NN, default 0 | |
| next_escalation_at | DateTime | | |
| created_at | DateTime | NN | |

### notification_channels

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| name | String(64) | NN | |
| type | Enum(email, desktop, slack, discord, teams, webhook) | NN | |
| config_enc | LargeBinary | NN | Encrypted JSON (addresses, webhook URL) |
| min_severity | Enum | NN | |
| is_escalation_contact | Boolean | NN, default false | |
| enabled | Boolean | NN | |

### notification_log

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| alert_id | Integer | FK alerts, NN | |
| channel_id | Integer | FK notification_channels, NN | |
| attempt | Integer | NN | 1, 2, 3 |
| status | Enum(sent, failed) | NN | |
| error | Text | | |
| sent_at | DateTime | NN | |

### audit_log

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | Strictly increasing |
| actor_user_id | Integer | FK users | NULL = system |
| action | String(40) | NN | LOGIN_SUCCESS, CHANGE_ACCEPTED, ... |
| target_type, target_id | String, String | | What was acted on |
| details | JSON | | Extra context |
| ip_address | String(45) | | IPv4 or IPv6 |
| created_at | DateTime | NN | |
| prev_hash | String(64) | NN | Previous entry's entry_hash |
| entry_hash | String(64) | UQ, NN | SHA-256(prev_hash + canonical entry) |

### audit_checkpoints

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | Integer | PK | |
| last_entry_id | Integer | FK audit_log, NN | |
| entry_hash | String(64) | NN | Chain head at checkpoint time |
| run_id | Integer | FK verification_runs | |
| agent_signature | LargeBinary | NN | |
| signing_key_id | Integer | FK signing_keys, NN | |
| created_at | DateTime | NN | |

### agent_heartbeats

| Column | Type | Constraints | Description |
|---|---|---|---|
| agent_id | String(64) | PK | Machine name or generated ID |
| last_seen_at | DateTime | NN | Updated every minute |
| agent_version | String(20) | | |
| code_sha256 | String(64) | | Hash of the agent's own code |
| status | String(20) | | running, verifying, degraded |

## State kept outside the database

| Item | Location | Purpose |
|---|---|---|
| Pinned baseline key fingerprint | `config.yaml` and Credential Manager | Detect key substitution |
| Latest audit checkpoint ID and hash | Credential Manager | Detect database rollback |
| Vault AES key, agent private key, JWT secret | Credential Manager | Secrets |

## Indexes

| Table | Index | Supports |
|---|---|---|
| file_baselines | `file_path` (unique), `monitored_path_id`, `status` | Lookups by path, listing per folder, pending filter |
| file_versions | (`file_baseline_id`, `version`) unique | History and rollback check |
| verification_results | (`run_id`), (`file_baseline_id`, `checked_at`) | Run details, file history |
| change_events | (`review_status`, `severity`), `detected_at` | Review queue, timelines |
| alerts | (`status`, `severity`), `created_at` | Alert list |
| audit_log | `created_at`, (`actor_user_id`) | Searching history |
| mirror_objects | `sha256` (unique) | Deduplication |

## Example SQLAlchemy model

```python
class FileBaseline(Base):
    __tablename__ = "file_baselines"

    id: Mapped[int] = mapped_column(primary_key=True)
    monitored_path_id: Mapped[int] = mapped_column(ForeignKey("monitored_paths.id"), index=True)
    file_path: Mapped[str] = mapped_column(Text, unique=True)
    current_version: Mapped[int]
    sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(BigInteger)
    file_id: Mapped[int | None] = mapped_column(BigInteger)
    permissions: Mapped[str | None] = mapped_column(String(64))
    owner: Mapped[str | None] = mapped_column(String(256))
    acl_hash: Mapped[str | None] = mapped_column(String(64))
    file_type: Mapped[str] = mapped_column(String(10), default="regular")
    mirror_object_id: Mapped[int | None] = mapped_column(ForeignKey("mirror_objects.id"))
    rsa_signature: Mapped[bytes] = mapped_column(LargeBinary)
    signing_key_id: Mapped[int] = mapped_column(ForeignKey("signing_keys.id"))
    signed_at: Mapped[datetime]
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    last_verified_at: Mapped[datetime | None]

    versions: Mapped[list["FileVersion"]] = relationship(back_populates="baseline")

    def signed_record(self) -> dict:
        return {
            "record_id": self.id, "file_path": self.file_path,
            "version": self.current_version, "sha256": self.sha256,
            "file_size": self.file_size, "permissions": self.permissions,
            "owner": self.owner, "acl_hash": self.acl_hash, "file_type": self.file_type,
            "mirror_object_sha256": self.mirror.sha256 if self.mirror else None,
            "signing_key_id": self.key.key_id,
            "signed_at": self.signed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
```

## Migrations

Schema changes are managed with **Alembic**. Each change is a numbered migration script; `alembic upgrade head` brings any database to the latest schema. Never edit tables by hand in production.

```
alembic init db/migrations
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

# REST API

## Conventions

- Base URL `https://localhost:8443/api/v1`, JSON bodies, UTC timestamps in ISO 8601.
- Authentication by `HttpOnly` cookie (access token); a CSRF header on state-changing requests.
- Lists are paginated: `?page=1&page_size=50`, with filters such as `?severity=high&status=pending_review`.
- Errors use one shape: `{"error": "not_allowed", "message": "You do not have permission."}`.
- "Step-up" means the request body must include `password` and `totp_code`.

## Endpoints

| Method and path | Role | Purpose |
|---|---|---|
| POST `/auth/login` | public | Username, password and TOTP; sets cookies |
| POST `/auth/refresh` | public (refresh cookie) | New access token, rotates refresh token |
| POST `/auth/logout` | any | Revokes the session |
| POST `/auth/mfa/setup`, `/auth/mfa/confirm` | any | Enrol TOTP, returns QR code |
| GET `/dashboard/summary` | viewer | Counts, agent status, last run, open alerts |
| GET, POST `/paths` | viewer / admin (step-up) | List and add monitored paths |
| PATCH, DELETE `/paths/{id}` | admin (step-up) | Edit or remove a path |
| POST `/paths/{id}/baseline` | admin (step-up + passphrase) | Baseline a path |
| GET `/files` | viewer | Search monitored files and their status |
| GET `/files/{id}` | viewer | Record, signature status, last verification |
| GET `/files/{id}/versions` | viewer | Version history |
| GET `/files/{id}/versions/{v}/diff/{w}` | analyst | Text diff between versions |
| GET `/changes` | viewer | Review queue with filters |
| GET `/changes/{id}` | viewer | Full detail and diff |
| POST `/changes/{id}/accept` | admin (step-up + passphrase) | Accept; creates a signed version |
| POST `/changes/{id}/restore` | admin (step-up) | Restore the mirror copy |
| POST `/changes/{id}/reject` | analyst | Mark as false positive, reason required |
| POST `/changes/{id}/escalate` | analyst | Escalate |
| POST `/changes/bulk-accept` | admin (step-up + passphrase) | Accept several changes |
| GET `/alerts`, POST `/alerts/{id}/ack` | viewer / analyst | List and acknowledge alerts |
| GET `/runs`, GET `/runs/{id}` | viewer | Verification runs and results, signature status |
| POST `/runs` | admin | Trigger a manual verification |
| GET `/audit` | analyst | Search the audit log |
| GET `/audit/verify` | analyst | Verify the hash chain and checkpoints |
| GET, POST, PATCH `/channels` | admin (step-up) | Notification channels |
| GET `/keys` | admin | Key list and fingerprints |
| POST `/keys/rotate` | admin (step-up + old and new passphrases) | Rotate the baseline key |
| GET, POST, PATCH `/users` | admin (step-up) | User management |
| WS `/ws/events` | viewer | Live stream of alerts and run progress |

## Example: accepting a change

```
POST /api/v1/changes/918/accept
{
  "reason": "Release 2.4 deployment, ticket CHG-1182",
  "expected_observed_sha256": "a1c3e5f7...77b2",
  "password": "********",
  "totp_code": "492039",
  "key_passphrase": "********"
}

200 OK
{ "change_id": 918, "review_status": "accepted", "new_version": 4,
  "signed_with": "a1b2c3d4e5f60718" }
```

`expected_observed_sha256` is the hash the admin saw on screen. The server refuses (409 Conflict) if the file now has a different hash.

> SECURITY: Passphrases and passwords travel only over HTTPS, are used in memory, and are never logged. The server marks these fields as secret so they are removed from any error or log output.

# Dashboard and Command-Line Interface

## Dashboard pages

| Page | Contents |
|---|---|
| Login | Username, password, TOTP code; lockout message |
| Overview | Monitored files count, OK / pending / critical counts, agent status and heartbeat, last and next run, chart of changes over 30 days, latest alerts |
| Review queue | Pending changes sorted by severity and age; filters; bulk selection |
| Change detail | Expected and observed hashes and metadata, side-by-side diff, history, Accept / Restore / Reject / Escalate with reason and step-up dialog |
| Monitored paths | List, add, edit; include/exclude patterns; severity; baseline button |
| Files | Search all monitored files; status badges; per-file history and versions |
| Verification runs | List of runs with duration and results; signature-valid badge; drill-down to per-file results |
| Alerts | All alerts with acknowledgement and escalation state |
| Audit log | Searchable history; "Verify chain" button showing intact / broken and the first bad entry |
| Settings | Notification channels, users and roles, keys and fingerprints (with rotation), retention, scan policy |

### Visual language

- Status colours: green OK, amber pending review, red critical. Always pair colour with text so the meaning is not lost for colour-blind users.
- The fingerprint of the active baseline key is shown in the footer of every page.
- A persistent banner appears whenever the agent is offline or a monitoring gap is unresolved.

## Command-line interface

The CLI (built with Typer) is used for setup, administration and testing.

| Command | Purpose |
|---|---|
| `filevow init` | Create folders, database, vault key, agent key and default config |
| `filevow keygen --out E:\filevow_baseline_key.pem` | Generate the baseline key pair (asks for a passphrase), register the public key, pin its fingerprint |
| `filevow user add admin --role admin` | Create a user and enrol TOTP |
| `filevow path add "C:\inetpub\wwwroot" --severity high --exclude "*.log"` | Add a monitored path |
| `filevow baseline [--path P]` | Hash, mirror and sign files (asks for passphrase) |
| `filevow verify [--path P] [--deep]` | Run a verification immediately and print the results |
| `filevow watch` | Run the agent in the foreground (scheduler + watcher) |
| `filevow serve` | Start the API server |
| `filevow changes list` | Show pending changes |
| `filevow changes accept 918 --reason "..."` | Accept from the CLI (passphrase prompt) |
| `filevow changes restore 918` | Restore from the CLI |
| `filevow audit verify` | Verify the audit hash chain and checkpoints |
| `filevow keys rotate` | Rotate the baseline key |
| `filevow vault verify [--all]` | Verify mirror objects |
| `filevow export report --run 4182` | Export a signed run report as JSON |

Example session:

```
> filevow verify --deep
Run #4183 (manual, deep) started 2026-11-23 10:41:07 UTC
Checked 1,284 files in 9.6 s
  OK                     1,281
  FILE_MODIFIED              2   C:\inetpub\wwwroot\index.html
                                 C:\inetpub\wwwroot\js\app.js
  UNKNOWN_FILE_CREATED       1   C:\inetpub\wwwroot\shell.php   [HIGH]
Report signed with agent key 5e6f7a8b9c0d1e2f
3 changes pending review.
```
