// Mirrors filevow/api/schemas.py. Keep the two in step.

export type Role = "admin" | "user" | "analyst" | "viewer";
export type Severity = "low" | "medium" | "high" | "critical";

export interface User {
  id: number;
  username: string;
  role: Role;
  mfa_enabled: boolean;
  is_active: boolean;
  last_login_at: string | null;
}

export interface StepUp {
  password: string;
  totp_code?: string | null;
}

export interface RunSummary {
  id: number;
  run_type: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  files_checked: number;
  ok_count: number;
  issue_count: number;
  duration_ms: number | null;
  signed: boolean;
}

export interface RunDetail extends RunSummary {
  issues: { file_path: string; outcome: string }[];
  signature_valid: boolean | null;
  results_sha256: string | null;
}

export interface Dashboard {
  protected_files: number;
  monitored_paths: number;
  open_changes: number;
  open_by_severity: Partial<Record<Severity, number>>;
  layers: { content_ok: number; signatures_ok: number; mirror_ok: number; total: number };
  last_run: RunSummary | null;
  next_run_at: string | null;
  agent_last_seen: string | null;
  agent_online: boolean;
  audit_intact: boolean;
  key_id: string | null;
  runs_24h: { id: number; started_at: string; issue_count: number; duration_ms: number | null }[];
  activity: { created_at: string; action: string; actor: string; summary: string }[];
  open_alerts: number;
}

export interface Change {
  id: number;
  file_path: string;
  name: string;
  folder: string;
  event_type: string;
  title: string;
  severity: Severity;
  review_status: string;
  expected_sha256: string | null;
  observed_sha256: string | null;
  expected_size: number | null;
  observed_size: number | null;
  approved_version: number | null;
  detected_at: string;
  last_seen_at: string;
  occurrence_count: number;
  can_accept: boolean;
  can_restore: boolean;
  can_quarantine: boolean;
}

export interface DiffLine {
  kind: "same" | "add" | "del" | "mod";
  old_number: number | null;
  new_number: number | null;
  old_text: string | null;
  new_text: string | null;
}

export interface ChangeDetail extends Change {
  layers: { signature: boolean | null; version: boolean | null; mirror: boolean | null; content: boolean | null; metadata: boolean | null };
  metadata_changes: Record<string, (string | null)[]>;
  diff: { lines: DiffLine[]; added: number; removed: number } | null;
  diff_note: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_reason: string | null;
  run_id: number | null;
}

export interface Decision {
  change_id: number;
  action: string;
  message: string;
  new_version: number | null;
}

export interface MonitoredPath {
  id: number;
  path: string;
  is_directory: boolean;
  recursive: boolean;
  include_patterns: string[];
  exclude_patterns: string[];
  severity: Severity;
  enabled: boolean;
  mirror_enabled: boolean;
  protected_files: number;
  created_at: string;
}

export interface ProtectedFile {
  id: number;
  file_path: string;
  name: string;
  status: string;
  current_version: number;
  sha256: string;
  file_size: number;
  last_verified_at: string | null;
  open_change_id: number | null;
}

export interface FileDetail extends ProtectedFile {
  permissions: string | null;
  owner: string | null;
  mirrored: boolean;
  signed_at: string;
  key_id: string;
  versions: { version: number; sha256: string; file_size: number; approved_by: string | null; approval_reason: string | null; created_at: string; key_id: string }[];
}

export interface Alert {
  id: number;
  change_event_id: number | null;
  alert_type: string;
  severity: Severity;
  title: string;
  message: string;
  status: "new" | "acknowledged" | "resolved";
  escalation_level: number;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  created_at: string;
  action: string;
  actor: string;
  target_type: string | null;
  target_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  entry_hash: string;
}

export interface ChainReport {
  intact: boolean;
  entries_checked: number;
  first_broken_id: number | null;
  reason: string | null;
  checkpoint_problems: string[];
}

export interface SigningKey {
  id: number;
  key_id: string;
  fingerprint: string;
  purpose: string;
  algorithm: string;
  status: string;
  pinned: boolean;
  created_at: string;
}

export interface Channel {
  id: number;
  name: string;
  type: "email" | "desktop" | "slack" | "teams" | "webhook";
  min_severity: Severity;
  is_escalation_contact: boolean;
  enabled: boolean;
  target: string;
}

export interface SystemInfo {
  version: string;
  verification_interval_minutes: number;
  monitoring_gap_minutes: number;
  signing_key_configured: boolean;
  database: string;
}

export interface LiveState {
  type: "state";
  last_run_id: number | null;
  open_changes: number;
  last_alert_id: number | null;
  last_audit_id: number | null;
  agent_last_seen: string | null;
}

export interface AuthOptions {
  allow_registration: boolean;
  has_accounts: boolean;
}

export interface Workspace {
  has_signing_key: boolean;
  key_id: string | null;
  folders: number;
  protected_files: number;
  unprotected_folders: number;
  mfa_enabled: boolean;
  channels: number;
  open_changes: number;
}

export interface FsEntry {
  name: string;
  path: string;
  kind: "folder" | "file" | "drive";
  size: number | null;
}

export interface FsListing {
  path: string | null;
  parent: string | null;
  entries: FsEntry[];
  truncated: boolean;
}

export interface FsPlace {
  label: string;
  path: string;
  icon: string;
}
