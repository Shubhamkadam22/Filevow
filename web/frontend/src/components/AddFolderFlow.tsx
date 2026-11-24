import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { MonitoredPath, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Dialog } from "./Dialog";
import { FolderBrowser } from "./FolderBrowser";
import { Icon } from "./Icon";
import { useToast } from "./Toast";

interface Props {
  open: boolean;
  hasSigningKey: boolean;
  onClose: () => void;
  onNeedKey: () => void;
}

/** Choose a folder or file (Browse…), then protect it in one confirmation. */
export function AddFolderFlow({ open, hasSigningKey, onClose, onNeedKey }: Props) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [browsing, setBrowsing] = useState(false);
  const [path, setPath] = useState("");
  const [severity, setSeverity] = useState<Severity>("high");
  const [exclude, setExclude] = useState("*.log, *.tmp, ~$*");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const close = () => {
    setPath(""); setPassword(""); setTotp(""); setPassphrase(""); setError(null);
    onClose();
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!path.trim()) return setError("Choose a folder or file with Browse… or type its path.");
    const cloud = Boolean(user?.is_cloud);
    if (!cloud && !password) return setError("Enter your account password.");
    if (!passphrase) return setError(cloud ? "Enter your passphrase." : "Enter your signing-key passphrase.");
    setBusy(true);
    setError(null);
    // E-mail-code accounts have no password: their passphrase confirms it's them.
    const proof = { password: cloud ? passphrase : password, totp_code: totp || null };
    try {
      const added = await api.post<MonitoredPath>("/paths", {
        ...proof, path: path.trim(), severity, exclude: exclude.split(",").map((p) => p.trim()).filter(Boolean),
      });
      const result = await api.post<{ created: number; mirrored: number }>(`/paths/${added.id}/baseline`, {
        ...proof, key_passphrase: passphrase,
      });
      toast("Protected", `${result.created} file${result.created === 1 ? " is" : "s are"} now watched, signed and backed up.`);
      await queryClient.invalidateQueries();
      close();
    } catch (err) {
      await queryClient.invalidateQueries(); // the folder may have been added even if signing failed
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  if (open && !hasSigningKey) {
    return (
      <Dialog open title="First, create your signing key" onClose={close}
        footer={<><button className="btn primary" onClick={() => { close(); onNeedKey(); }}>Create signing key</button><button className="btn" onClick={close}>Cancel</button></>}>
        <p>Protecting files needs your personal signing key. It takes a few seconds to create.</p>
      </Dialog>
    );
  }

  return (
    <>
      <Dialog open={open && !browsing} onClose={close} title="Protect a folder or file" width={560}
        footer={<><button className="btn primary" type="submit" form="add-form" disabled={busy}>{busy ? <span className="spinner" /> : "Protect"}</button><button className="btn" onClick={close}>Cancel</button></>}>
        <form id="add-form" onSubmit={submit} noValidate>
          <p>FileVow takes a fingerprint and an encrypted backup copy of everything you choose, then checks it every
            15 minutes and whenever it changes.</p>
          <div className="field">
            <label htmlFor="add-path">Folder or file</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input id="add-path" placeholder="C:\Users\you\Documents" value={path} onChange={(e) => setPath(e.target.value)} />
              <button type="button" className="btn" onClick={() => setBrowsing(true)}><Icon name="folder" />Browse…</button>
            </div>
          </div>
          <div className="split-form">
            <div className="field">
              <label htmlFor="add-sev">How serious is a change here?</label>
              <select id="add-sev" className="sel" style={{ width: "100%" }} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
                <option value="critical">Critical: notify me right away</option>
                <option value="high">High (recommended)</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="add-ex">Skip files matching</label>
              <input id="add-ex" value={exclude} onChange={(e) => setExclude(e.target.value)} />
            </div>
          </div>
          <p style={{ margin: "4px 0 8px", fontWeight: 600 }}>Confirm it's you</p>
          {user?.is_cloud ? (
            <div className="field"><label htmlFor="add-kp">Your passphrase</label>
              <input id="add-kp" type="password" autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></div>
          ) : (
            <div className="split-form">
              <div className="field"><label htmlFor="add-pw">Account password</label>
                <input id="add-pw" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
              <div className="field"><label htmlFor="add-kp">Signing-key passphrase</label>
                <input id="add-kp" type="password" autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></div>
            </div>
          )}
          {user?.mfa_enabled && (
            <div className="field"><label htmlFor="add-totp">Authenticator code</label>
              <input id="add-totp" inputMode="numeric" value={totp} onChange={(e) => setTotp(e.target.value.replace(/\D/g, "").slice(0, 6))} /></div>
          )}
          {error && <div className="form-error" role="alert">{error}</div>}
        </form>
      </Dialog>
      <FolderBrowser open={open && browsing} onClose={() => setBrowsing(false)}
        onSelect={(selected) => { setPath(selected); setBrowsing(false); }} />
    </>
  );
}
