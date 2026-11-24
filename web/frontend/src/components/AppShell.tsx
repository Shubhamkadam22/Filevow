import { useMemo, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useAlerts, useChanges, useDashboard, useStartRun } from "../api/queries";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useHotkeys } from "../hooks/useHotkeys";
import { useLiveEvents, useNow } from "../hooks/useLiveEvents";
import { usePreferences } from "../hooks/usePreferences";
import { clockTime, countdown, timeAgo } from "../lib/format";
import { CommandPalette, type Command } from "./CommandPalette";
import { Icon, SeverityIcon } from "./Icon";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { useToast } from "./Toast";

export const PAGES = [
  { path: "/", label: "Home", icon: "home" },
  { path: "/review", label: "Review changes", icon: "review" },
  { path: "/files", label: "Protected files", icon: "file" },
  { path: "/folders", label: "Monitored folders", icon: "folder" },
  { path: "/runs", label: "Verification history", icon: "verify" },
  { path: "/audit", label: "Audit log", icon: "audit" },
  { path: "/settings", label: "Settings", icon: "settings" },
  { path: "/help", label: "Help", icon: "info" },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();
  const now = useNow();
  const prefs = usePreferences();
  const live = useLiveEvents(Boolean(user));
  const dashboard = useDashboard();
  const changes = useChanges("open");
  const alerts = useAlerts();
  const startRun = useStartRun();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [keysOpen, setKeysOpen] = useState(false);
  const [flyoutOpen, setFlyoutOpen] = useState(false);

  const openChanges = changes.data ?? [];
  const criticalOpen = openChanges.some((c) => c.severity === "critical");
  const unreadAlerts = (alerts.data ?? []).filter((a) => a.status === "new");
  const data = dashboard.data;
  const agentSeen = live?.agent_last_seen ?? data?.agent_last_seen ?? null;
  const agentOnline = agentSeen ? now - new Date(agentSeen).getTime() < 5 * 60 * 1000 : false;

  const verifyNow = () =>
    startRun.mutate(undefined, {
      onSuccess: () => toast("Verification started", "Results appear here as soon as the run finishes."),
      onError: (error) => toast("Could not start verification", error.message),
    });

  const commands = useMemo<Command[]>(
    () => [
      ...openChanges.map((c) => ({
        group: "Changes waiting for review", label: c.name, hint: c.title, severity: c.severity, mono: true,
        run: () => navigate(`/review/${c.id}`),
      })),
      ...PAGES.map((p, i) => ({ group: "Go to", label: p.label, hint: `Alt ${i + 1}`, icon: p.icon, run: () => navigate(p.path) })),
      { group: "Commands", label: "Verify all files now", hint: "Ctrl Shift V", icon: "verify", run: verifyNow },
      { group: "Commands", label: "Verify audit chain", icon: "lock", run: () => navigate("/audit?verify=1") },
      { group: "Commands", label: "Export audit log as CSV", icon: "download", run: () => window.open("/api/v1/audit/export.csv") },
      { group: "Commands", label: "Switch to dark theme", icon: "palette", run: () => prefs.setTheme("dark") },
      { group: "Commands", label: "Switch to light theme", icon: "palette", run: () => prefs.setTheme("light") },
      { group: "Commands", label: "Toggle compact density", icon: "density", run: () => prefs.setDensity(prefs.density === "compact" ? "comfortable" : "compact") },
      { group: "Commands", label: "Show keyboard shortcuts", hint: "?", icon: "keyboard", run: () => setKeysOpen(true) },
      { group: "Commands", label: "Sign out", icon: "logout", run: () => void logout() },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [openChanges, prefs.density],
  );

  useHotkeys({
    "ctrl+k": () => setPaletteOpen((open) => !open),
    "?": () => setKeysOpen(true),
    "alt+arrowleft": () => navigate(-1),
    "ctrl+shift+v": verifyNow,
    ...Object.fromEntries(PAGES.map((p, i) => [`alt+${i + 1}`, () => navigate(p.path)])),
  });

  return (
    <>
      <header className="titlebar">
        <button className="tbbtn" title="Back (Alt+Left)" aria-label="Back" onClick={() => navigate(-1)} disabled={location.key === "default"}>
          <Icon name="back" />
        </button>
        <img src="/logo-mark.svg" alt="" className="themed-logo" />
        <span className="name">FileVow</span>
        <span className="sp" />
        <button className="search" onClick={() => setPaletteOpen(true)} aria-label="Search and commands (Ctrl+K)">
          <Icon name="search" />
          <span className="ellip">Search or run a command</span>
          <kbd>Ctrl K</kbd>
        </button>
        <span className="sp" />
        <button className="tbbtn" title="Help" aria-label="Help" onClick={() => navigate("/help")}>
          <Icon name="info" />
        </button>
        <button className="tbbtn" title="Notifications" aria-label="Notifications" onClick={() => setFlyoutOpen((o) => !o)}>
          <Icon name="bell" />
          {unreadAlerts.length > 0 && <span className="dot" />}
        </button>
        <button className="tbbtn" title="Sign out" aria-label="Sign out" onClick={() => void logout()} style={{ marginRight: 8 }}>
          <Icon name="logout" />
        </button>
      </header>

      <div className="shell">
        <nav aria-label="Main">
          <div className="account">
            <div className="avatar"><img src="/logo-mark-reversed.svg" alt="" /></div>
            <div>
              <b>{user?.username}</b>
              <span>
                <i className="live" aria-hidden="true" style={agentOnline ? undefined : { background: "var(--fv-critical)", animation: "none" }} />
                {user?.role} · agent {agentOnline ? "running" : "offline"}
              </span>
            </div>
          </div>
          {PAGES.slice(0, 6).map((page, index) => (
            <NavLink key={page.path} to={page.path} end={page.path === "/"} className={({ isActive }) => `navitem ${isActive ? "sel" : ""}`}>
              <Icon name={page.icon} />
              <span className="lbl">{page.label}</span>
              {page.path === "/review" && openChanges.length > 0 && (
                <span className={`count ${criticalOpen ? "" : "amber"}`}>{openChanges.length}</span>
              )}
              <kbd className="hint">Alt {index + 1}</kbd>
            </NavLink>
          ))}
          <div className="grow" />
          <NavLink to="/settings" className={({ isActive }) => `navitem ${isActive ? "sel" : ""}`}>
            <Icon name="settings" />
            <span className="lbl">Settings</span>
            <kbd className="hint">Alt 7</kbd>
          </NavLink>
          <NavLink to="/help" className={({ isActive }) => `navitem ${isActive ? "sel" : ""}`}>
            <Icon name="info" />
            <span className="lbl">Help</span>
            <kbd className="hint">Alt 8</kbd>
          </NavLink>
        </nav>
        <main id="main">{children}</main>
      </div>

      <footer className="statusbar" aria-label="Status">
        <span className={`it ${agentOnline ? "" : "bad"}`}>
          <i className="live" aria-hidden="true" style={agentOnline ? undefined : { background: "var(--fv-critical)", animation: "none" }} />
          Agent {agentOnline ? "running" : `offline · last seen ${timeAgo(agentSeen, now)}`}
        </span>
        {data?.last_run && (
          <span className="it click" onClick={() => navigate("/runs")}>
            Last run {clockTime(data.last_run.started_at)} · {((data.last_run.duration_ms ?? 0) / 1000).toFixed(1)} s
          </span>
        )}
        {data?.next_run_at && <span className="it">Next in {countdown(data.next_run_at, now)}</span>}
        {data?.key_id && (
          <span className="it click opt" onClick={() => navigate("/settings")}>
            <Icon name="key" />Key {data.key_id.slice(0, 8)}
          </span>
        )}
        {data && (
          <span className={`it click opt ${data.audit_intact ? "ok" : "bad"}`} onClick={() => navigate("/audit")}>
            <Icon name="lock" />Audit chain {data.audit_intact ? "intact" : "BROKEN"}
          </span>
        )}
        <span className="sp" />
        <span className="it click" onClick={() => setPaletteOpen(true)}><kbd>Ctrl K</kbd> Commands</span>
        <span className="it click" onClick={() => setKeysOpen(true)}><kbd>?</kbd> Shortcuts</span>
      </footer>

      {flyoutOpen && (
        <div className="flyout on" role="dialog" aria-label="Notifications">
          <div className="fh">
            Notifications<span className="sp" />
            <button className="link" onClick={() => setFlyoutOpen(false)}>Close</button>
          </div>
          <div className="fl">
            {(alerts.data ?? []).length === 0 && <div className="empty" style={{ padding: 24 }}>No notifications</div>}
            {(alerts.data ?? []).map((alert) => (
              <div key={alert.id} className={`nitem ${alert.status === "new" ? "unread" : ""}`}
                onClick={async () => {
                  setFlyoutOpen(false);
                  if (alert.status === "new") await api.post(`/alerts/${alert.id}/ack`).catch(() => undefined);
                  navigate(alert.change_event_id ? `/review/${alert.change_event_id}` : "/runs");
                }}>
                <SeverityIcon severity={alert.severity} />
                <div><b style={{ fontWeight: 600 }}>{alert.title}</b><small>{alert.message.split("\n")[0]}</small></div>
                <time>{timeAgo(alert.created_at, now)}</time>
              </div>
            ))}
          </div>
        </div>
      )}

      <CommandPalette open={paletteOpen} commands={commands} onClose={() => setPaletteOpen(false)} />
      <ShortcutsDialog open={keysOpen} onClose={() => setKeysOpen(false)} />
    </>
  );
}
