import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useChannels, useKeys, useSystem, useUsers, useWorkspace } from "../api/queries";
import type { Role, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CopyButton } from "../components/CopyButton";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { SetupGuide } from "../components/SetupGuide";
import { SigningKeyDialog } from "../components/SigningKeyDialog";
import { StepUpDialog, type StepUpValues } from "../components/StepUpDialog";
import { useToast } from "../components/Toast";
import { usePreferences, type Density, type Theme } from "../hooks/usePreferences";
import { timeAgo } from "../lib/format";
import { PasswordInput } from "../components/PasswordInput";

type Pending =
  | { kind: "password"; newPassword: string }
  | { kind: "user"; username: string; newPassword: string; role: Role }
  | { kind: "user-update"; id: number; changes: { role?: Role; is_active?: boolean } }
  | { kind: "channel"; body: Record<string, unknown> }
  | { kind: "delete-account" };

export function SettingsPage() {
  const { user, can, refreshUser, logout } = useAuth();
  const prefs = usePreferences();
  const keys = useKeys();
  const system = useSystem();
  const admin = can("admin");
  const owner = can("user");
  const users = useUsers(admin);
  const channels = useChannels(owner);
  const workspace = useWorkspace();
  const [keyDialog, setKeyDialog] = useState(false);
  const queryClient = useQueryClient();
  const toast = useToast();
  const [pending, setPending] = useState<Pending | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mfaOpen, setMfaOpen] = useState(false);
  const [dialog, setDialog] = useState<"password" | "user" | "channel" | null>(null);

  const confirm = async (values: StepUpValues) => {
    if (!pending) return;
    const proof = { password: values.password, totp_code: values.totpCode || null };
    setBusy(true);
    setError(null);
    try {
      if (pending.kind === "password") {
        await api.post("/auth/password", { ...proof, new_password: pending.newPassword });
        toast("Password changed", "Other sessions were signed out.");
      } else if (pending.kind === "user") {
        await api.post("/users", { ...proof, username: pending.username, new_password: pending.newPassword, role: pending.role });
        toast("Account created", `${pending.username} can now sign in.`);
      } else if (pending.kind === "user-update") {
        await api.patch(`/users/${pending.id}`, { ...proof, ...pending.changes });
        toast("Account updated");
      } else if (pending.kind === "delete-account") {
        await api.post("/auth/cloud/delete-account", proof);
        setPending(null);
        await logout();
        return;
      } else {
        await api.post("/channels", { ...proof, ...pending.body });
        toast("Notification channel added");
      }
      setPending(null);
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  const testChannel = async (id: number) => {
    try {
      await api.post(`/channels/${id}/test`);
      toast("Test notification sent");
    } catch (err) {
      toast("Test failed", err instanceof Error ? err.message : undefined);
    }
  };

  const setUsageReporting = async (on: boolean) => {
    try {
      await api.post("/auth/cloud/preferences", { usage_reporting: on });
      await refreshUser();
    } catch (err) {
      toast("Could not save", err instanceof Error ? err.message : undefined);
    }
  };

  const disableChannel = async (id: number) => {
    await api.delete(`/channels/${id}`);
    await queryClient.invalidateQueries();
    toast("Channel turned off");
  };

  return (
    <section className="page on">
      <h1 className="ptitle">Settings</h1>
      {owner && <SetupGuide />}

      <h2 className="sec" id="account-settings" style={{ marginTop: 0 }}>Your account</h2>
      <div className="row">
        <Icon name="lock" />
        <div className="txt">
          <b>Two-step verification</b>
          <span>Authenticator codes are required to sign in and for every sensitive action</span>
        </div>
        {user?.mfa_enabled ? <span className="pill ok"><Icon name="check" />On</span> : <button className="btn primary" onClick={() => setMfaOpen(true)}>Turn on</button>}
      </div>
      {user?.is_cloud ? (
        <>
          <div className="row">
            <Icon name="user" />
            <div className="txt">
              <b>{user.email}</b>
              <span>Signs in with an e-mail code · {user.username} ({user.role}) · last sign-in {timeAgo(user.last_login_at)}</span>
            </div>
          </div>
          <div className="row">
            <Icon name="verify" />
            <div className="txt">
              <b>Count me as an active user</b>
              <span>Once a day FileVow tells its publisher this account used the app, with the app and Windows version. Never file names or contents.</span>
            </div>
            <label className="toggle" title={user.usage_reporting ? "On" : "Off"}>
              <input type="checkbox" checked={user.usage_reporting} aria-label="Daily active-use count"
                onChange={(e) => void setUsageReporting(e.target.checked)} />
            </label>
          </div>
          <div className="row">
            <Icon name="warn" />
            <div className="txt">
              <b>Delete my account</b>
              <span>Removes your online account and usage data and signs you out. Protected files and their backups on this PC stay.</span>
            </div>
            <button className="btn danger" onClick={() => setPending({ kind: "delete-account" })}>Delete</button>
          </div>
        </>
      ) : (
        <div className="row">
          <Icon name="key" />
          <div className="txt"><b>Password</b><span>Signed in as {user?.username} ({user?.role}) · last sign-in {timeAgo(user?.last_login_at)}</span></div>
          <button className="btn" onClick={() => setDialog("password")}>Change</button>
        </div>
      )}

      <h2 className="sec">Signing keys</h2>
      <div className="row">
        <Icon name="key" />
        <div className="txt">
          <b>Your signing key</b>
          <span>
            {workspace.data?.has_signing_key
              ? `Key ${workspace.data.key_id} signs every file you protect. Keep a backup of it on a USB drive.`
              : "Create it once; you'll need its passphrase to protect folders and approve changes."}
          </span>
        </div>
        {workspace.data?.has_signing_key ? (
          <a className="btn" href="/api/v1/workspace/signing-key/backup"><Icon name="download" />Download backup</a>
        ) : (
          owner && <button className="btn primary" onClick={() => setKeyDialog(true)}>Create key</button>
        )}
      </div>
      <div className="table keys">
        <div className="tr th"><div>Key</div><div>Purpose</div><div>Fingerprint</div><div>Status</div><div>Pinned</div></div>
        {(keys.data ?? []).map((key) => (
          <div className="tr" key={key.id}>
            <div className="mono">{key.key_id}</div>
            <div>{key.purpose === "baseline" ? "Baseline (approvals)" : "Agent (reports)"}</div>
            <div className="mono ellip" title={key.fingerprint}>{key.fingerprint.slice(0, 32)}… <CopyButton text={key.fingerprint} label="Copy fingerprint" /></div>
            <div>{key.status}</div>
            <div>{key.purpose === "baseline" ? (key.pinned ? <span className="pill ok">Pinned</span> : <span className="pill crit">Not pinned</span>) : "—"}</div>
          </div>
        ))}
      </div>

      {admin && (
        <>
          <h2 className="sec">Accounts on this computer<span className="sp" />{!user?.is_cloud && <button className="btn" onClick={() => setDialog("user")}><Icon name="plus" />Add user</button>}</h2>
          <div className="table users">
            <div className="tr th"><div>User</div><div>Role</div><div>Two-step</div><div>Last sign-in</div><div /></div>
            {(users.data ?? []).map((account) => (
              <div className="tr" key={account.id}>
                <div>{account.username}{account.is_active ? "" : " (disabled)"}</div>
                <div>
                  <select className="sel" value={account.role} disabled={account.id === user?.id} aria-label={`Role of ${account.username}`}
                    onChange={(e) => setPending({ kind: "user-update", id: account.id, changes: { role: e.target.value as Role } })}>
                    <option value="admin">Admin</option><option value="user">User</option><option value="analyst">Analyst</option><option value="viewer">Viewer</option>
                  </select>
                </div>
                <div>{account.mfa_enabled ? <span className="pill ok">On</span> : <span className="pill high">Off</span>}</div>
                <div className="muted">{timeAgo(account.last_login_at)}</div>
                <div className="row-actions">
                  {account.id !== user?.id && (
                    <button className="btn subtle" onClick={() => setPending({ kind: "user-update", id: account.id, changes: { is_active: !account.is_active } })}>
                      {account.is_active ? "Disable" : "Enable"}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

        </>
      )}

      {owner && (
        <>
          <h2 className="sec" id="notification-settings">Notifications<span className="sp" /><button className="btn" onClick={() => setDialog("channel")}><Icon name="plus" />Add channel</button></h2>
          <div className="table channels">
            <div className="tr th"><div>Name</div><div>Type</div><div>Sends to</div><div>Minimum</div><div>Escalation</div><div /></div>
            {(channels.data ?? []).length === 0 && <div className="empty" style={{ padding: 20 }}>No channels yet. Alerts still appear in the dashboard.</div>}
            {(channels.data ?? []).map((channel) => (
              <div className="tr" key={channel.id} style={channel.enabled ? undefined : { opacity: 0.55 }}>
                <div>{channel.name}</div>
                <div>{channel.type}</div>
                <div className="ellip">{channel.target}</div>
                <div>{channel.min_severity}</div>
                <div>{channel.is_escalation_contact ? "Yes" : "No"}</div>
                <div className="row-actions">
                  {channel.enabled && <button className="btn subtle" onClick={() => testChannel(channel.id)}>Test</button>}
                  {channel.enabled && <button className="btn subtle" onClick={() => disableChannel(channel.id)}>Turn off</button>}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <h2 className="sec">Appearance and accessibility</h2>
      <div className="row">
        <Icon name="palette" />
        <div className="txt"><b>App theme</b><span>Follow Windows, or choose light or dark</span></div>
        <select className="sel" value={prefs.theme} onChange={(e) => prefs.setTheme(e.target.value as Theme)} aria-label="App theme">
          <option value="system">Use system setting</option><option value="light">Light</option><option value="dark">Dark</option>
        </select>
      </div>
      <div className="row">
        <Icon name="density" />
        <div className="txt"><b>Density</b><span>Compact shows more rows at once on smaller screens</span></div>
        <select className="sel" value={prefs.density} onChange={(e) => prefs.setDensity(e.target.value as Density)} aria-label="Density">
          <option value="comfortable">Comfortable</option><option value="compact">Compact</option>
        </select>
      </div>

      <h2 className="sec">About</h2>
      <div className="row">
        <img src="/logo-mark.svg" alt="" className="themed-logo" style={{ width: 20, height: 20 }} />
        <div className="txt">
          <b>FileVow {system.data?.version}</b>
          <span>
            Checks every {system.data?.verification_interval_minutes ?? 15} min · {system.data?.database ?? ""} database ·
            signing key {system.data?.signing_key_configured ? "available" : "not plugged in"}
          </span>
        </div>
      </div>

      <SigningKeyDialog open={keyDialog} onClose={() => setKeyDialog(false)} />
      <MfaDialog open={mfaOpen} onClose={() => setMfaOpen(false)} onDone={() => { setMfaOpen(false); void refreshUser(); }} />
      <PasswordDialog open={dialog === "password"} onClose={() => setDialog(null)}
        onSubmit={(newPassword) => { setDialog(null); setPending({ kind: "password", newPassword }); }} />
      <UserDialog open={dialog === "user"} onClose={() => setDialog(null)}
        onSubmit={(username, newPassword, role) => { setDialog(null); setPending({ kind: "user", username, newPassword, role }); }} />
      <ChannelDialog open={dialog === "channel"} onClose={() => setDialog(null)}
        onSubmit={(body) => { setDialog(null); setPending({ kind: "channel", body }); }} />
      <StepUpDialog open={pending !== null}
        title={pending?.kind === "delete-account" ? "Delete your account?" : undefined}
        description={pending?.kind === "delete-account"
          ? "Your online FileVow account and its usage data are deleted for good, and you're signed out. Files and backups on this PC are not touched."
          : "This change needs a fresh confirmation of your identity."}
        confirmLabel={pending?.kind === "delete-account" ? "Delete my account" : "Confirm"} needsReason={false} busy={busy} error={error}
        onCancel={() => { setPending(null); setError(null); }} onConfirm={confirm} />
    </section>
  );
}

function MfaDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; qr_svg: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const start = async () => {
    setError(null);
    try {
      setSetup(await api.post<{ secret: string; qr_svg: string }>("/auth/mfa/setup"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start");
    }
  };
  const confirm = async () => {
    try {
      setCodes(await api.post<string[]>("/auth/mfa/confirm", { code }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "That code is not correct");
    }
  };
  const reset = () => { setSetup(null); setCode(""); setCodes(null); setError(null); };

  return (
    <Dialog open={open} onClose={() => { reset(); onClose(); }} title="Turn on two-step verification"
      footer={codes ? <button className="btn primary" onClick={() => { reset(); onDone(); }} style={{ gridColumn: "1 / -1" }}>I saved my recovery codes</button>
        : setup ? <><button className="btn primary" onClick={confirm}>Verify code</button><button className="btn" onClick={() => { reset(); onClose(); }}>Cancel</button></>
        : <><button className="btn primary" onClick={start}>Start</button><button className="btn" onClick={onClose}>Cancel</button></>}>
      {!setup && <p>You'll need an authenticator app such as Microsoft Authenticator or Google Authenticator on your phone.</p>}
      {setup && !codes && (
        <>
          <p>Scan this code with your authenticator app, then enter the 6-digit code it shows.</p>
          {/* QR SVG generated by the server from our own data; contains no user input */}
          <div className="qr" dangerouslySetInnerHTML={{ __html: setup.qr_svg }} />
          <p className="subtle">Can't scan? Enter this key: <span className="mono">{setup.secret}</span></p>
          <div className="field">
            <label htmlFor="mfa-code">Code from the app</label>
            <input id="mfa-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))} />
          </div>
        </>
      )}
      {codes && (
        <>
          <p>Two-step verification is on. Keep these one-time recovery codes somewhere safe; each signs you in once if you lose your phone.</p>
          <div className="codes">{codes.map((c) => <span key={c}>{c}</span>)}</div>
        </>
      )}
      {error && <div className="form-error" role="alert">{error}</div>}
    </Dialog>
  );
}

function PasswordDialog({ open, onClose, onSubmit }: { open: boolean; onClose: () => void; onSubmit: (password: string) => void }) {
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [touched, setTouched] = useState(false);
  const problem = password.length < 12 ? "Use at least 12 characters." : password !== repeat ? "The passwords don't match." : null;
  return (
    <Dialog open={open} onClose={onClose} title="Change password"
      footer={<><button className="btn primary" form="pw-form" type="submit">Continue</button><button className="btn" onClick={onClose}>Cancel</button></>}>
      <form id="pw-form" onSubmit={(e) => { e.preventDefault(); setTouched(true); if (!problem) { onSubmit(password); setPassword(""); setRepeat(""); } }}>
        <div className="field"><label htmlFor="np">New password</label><PasswordInput id="np" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        <div className={`field ${touched && problem ? "err" : ""}`}><label htmlFor="np2">Repeat new password</label><PasswordInput id="np2" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} /><div className="msg">{problem}</div></div>
      </form>
    </Dialog>
  );
}

function UserDialog({ open, onClose, onSubmit }: { open: boolean; onClose: () => void; onSubmit: (u: string, p: string, r: Role) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [touched, setTouched] = useState(false);
  const invalid = username.length < 3 || password.length < 12;
  return (
    <Dialog open={open} onClose={onClose} title="Add user"
      footer={<><button className="btn primary" form="user-form" type="submit">Continue</button><button className="btn" onClick={onClose}>Cancel</button></>}>
      <form id="user-form" onSubmit={(e) => { e.preventDefault(); setTouched(true); if (!invalid) onSubmit(username, password, role); }}>
        <div className="field"><label htmlFor="un">Username</label><input id="un" value={username} onChange={(e) => setUsername(e.target.value)} /></div>
        <div className={`field ${touched && invalid ? "err" : ""}`}>
          <label htmlFor="up">Initial password</label>
          <PasswordInput id="up" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <div className="msg">Usernames need 3+ characters and passwords 12+.</div>
        </div>
        <div className="field">
          <label htmlFor="ur">Role</label>
          <select id="ur" className="sel" style={{ width: "100%" }} value={role} onChange={(e) => setRole(e.target.value as Role)}>
            <option value="user">User: own private workspace (recommended)</option>
            <option value="admin">Admin: own workspace, plus manages accounts</option>
            <option value="analyst">Analyst: review-only workspace</option>
            <option value="viewer">Viewer: look only</option>
          </select>
        </div>
      </form>
    </Dialog>
  );
}

function ChannelDialog({ open, onClose, onSubmit }: { open: boolean; onClose: () => void; onSubmit: (body: Record<string, unknown>) => void }) {
  const [type, setType] = useState("webhook");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [host, setHost] = useState("");
  const [sender, setSender] = useState("");
  const [recipients, setRecipients] = useState("");
  const [smtpUser, setSmtpUser] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const [minimum, setMinimum] = useState<Severity>("high");
  const [escalation, setEscalation] = useState(false);

  const config =
    type === "email"
      ? { host, port: 587, sender, recipients: recipients.split(",").map((r) => r.trim()).filter(Boolean), username: smtpUser || undefined, password: smtpPassword || undefined, starttls: true }
      : type === "desktop" ? {} : { url };

  return (
    <Dialog open={open} onClose={onClose} title="Add notification channel" width={540}
      footer={<><button className="btn primary" form="ch-form" type="submit">Continue</button><button className="btn" onClick={onClose}>Cancel</button></>}>
      <form id="ch-form" onSubmit={(e) => { e.preventDefault(); onSubmit({ name: name || type, type, config, min_severity: minimum, is_escalation_contact: escalation }); }}>
        <div className="split-form">
          <div className="field"><label htmlFor="cn">Name</label><input id="cn" value={name} onChange={(e) => setName(e.target.value)} placeholder="Security team" /></div>
          <div className="field">
            <label htmlFor="ct">Type</label>
            <select id="ct" className="sel" style={{ width: "100%" }} value={type} onChange={(e) => setType(e.target.value)}>
              <option value="webhook">Webhook</option><option value="slack">Slack</option><option value="teams">Teams</option><option value="email">E-mail</option><option value="desktop">Windows notification</option>
            </select>
          </div>
        </div>
        {type === "email" ? (
          <>
            <div className="split-form">
              <div className="field"><label htmlFor="sh">SMTP server</label><input id="sh" value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" /></div>
              <div className="field"><label htmlFor="ss">From address</label><input id="ss" value={sender} onChange={(e) => setSender(e.target.value)} placeholder="filevow@example.com" /></div>
            </div>
            <div className="field"><label htmlFor="sr">Recipients (comma separated)</label><input id="sr" value={recipients} onChange={(e) => setRecipients(e.target.value)} /></div>
            <div className="split-form">
              <div className="field"><label htmlFor="su">SMTP user (optional)</label><input id="su" value={smtpUser} onChange={(e) => setSmtpUser(e.target.value)} /></div>
              <div className="field"><label htmlFor="sp">SMTP password</label><PasswordInput id="sp" autoComplete="off" value={smtpPassword} onChange={(e) => setSmtpPassword(e.target.value)} /></div>
            </div>
          </>
        ) : type !== "desktop" ? (
          <div className="field"><label htmlFor="cu">Webhook URL (https only, stored encrypted)</label><input id="cu" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/…" /></div>
        ) : null}
        <div className="split-form">
          <div className="field">
            <label htmlFor="cm">Send alerts from</label>
            <select id="cm" className="sel" style={{ width: "100%" }} value={minimum} onChange={(e) => setMinimum(e.target.value as Severity)}>
              <option value="critical">Critical only</option><option value="high">High and above</option><option value="medium">Medium and above</option><option value="low">Everything</option>
            </select>
          </div>
          <label className="toggle" style={{ marginTop: 26 }}><input type="checkbox" checked={escalation} onChange={(e) => setEscalation(e.target.checked)} />Escalation contact</label>
        </div>
      </form>
    </Dialog>
  );
}
