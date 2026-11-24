import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Dialog } from "./Dialog";
import { Icon } from "./Icon";

/** First-run step: create the user's own signing key (their "seal" for approving files). */
export function SigningKeyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [keyId, setKeyId] = useState<string | null>(null);

  const reset = () => {
    setPassword(""); setTotp(""); setPassphrase(""); setRepeat(""); setError(null); setKeyId(null);
  };
  const close = () => { reset(); onClose(); };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (passphrase.length < 12) return setError("Use a signing-key passphrase of at least 12 characters.");
    if (passphrase !== repeat) return setError("The two passphrases don't match.");
    if (!password) return setError("Enter your account password to confirm it's you.");
    setBusy(true);
    setError(null);
    try {
      const key = await api.post<{ key_id: string }>("/workspace/signing-key", {
        password, totp_code: totp || null, key_passphrase: passphrase,
      });
      setKeyId(key.key_id);
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the key");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={keyId ? "Your signing key is ready" : "Create your signing key"} width={540}
      footer={keyId ? (
        <>
          <a className="btn primary" href="/api/v1/workspace/signing-key/backup"><Icon name="download" />Download backup</a>
          <button className="btn" onClick={close}>Done</button>
        </>
      ) : (
        <>
          <button className="btn primary" type="submit" form="key-form" disabled={busy}>{busy ? <span className="spinner" /> : "Create key"}</button>
          <button className="btn" onClick={close}>Cancel</button>
        </>
      )}>
      {keyId ? (
        <>
          <p>Key <span className="mono">{keyId}</span> now protects your workspace. You'll type its passphrase whenever you
            protect a new folder or approve a change.</p>
          <div className="infobar warn"><Icon name="warn" /><div className="grow">
            <b>Don't lose the passphrase.</b>Nobody, not even an administrator, can recover it. Keep the backup file on a USB drive;
            it stays encrypted with your passphrase.</div></div>
        </>
      ) : (
        <form id="key-form" onSubmit={submit} noValidate>
          <p>Your signing key is like a personal seal. FileVow uses it to sign the fingerprint of every file you protect, so
            nobody can quietly change a file <i>and</i> its record. It's locked with a passphrase that only you know.</p>
          <div className="split-form">
            <div className="field"><label htmlFor="kp">New key passphrase</label>
              <input id="kp" type="password" autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} /></div>
            <div className="field"><label htmlFor="kp2">Repeat passphrase</label>
              <input id="kp2" type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} /></div>
          </div>
          <p className="subtle" style={{ marginTop: -4 }}>Use something different from your account password, at least 12 characters.</p>
          <div className="field"><label htmlFor="ap">Your account password (to confirm it's you)</label>
            <input id="ap" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
          {user?.mfa_enabled && (
            <div className="field"><label htmlFor="at">Authenticator code</label>
              <input id="at" inputMode="numeric" value={totp} onChange={(e) => setTotp(e.target.value.replace(/\D/g, "").slice(0, 6))} /></div>
          )}
          {error && <div className="form-error" role="alert">{error}</div>}
        </form>
      )}
    </Dialog>
  );
}
