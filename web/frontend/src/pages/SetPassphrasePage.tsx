import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Icon } from "../components/Icon";
import { PasswordInput } from "../components/PasswordInput";

/**
 * Last step of creating an account that signs in with e-mail codes: choose the passphrase.
 * It locks the account's signing key and confirms important actions (restoring, accepting,
 * removing files). It stays on this PC, so nobody can reset it.
 */
export function SetPassphrasePage() {
  const { user, logout } = useAuth();
  const queryClient = useQueryClient();
  const [passphrase, setPassphrase] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [needsSignIn, setNeedsSignIn] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (passphrase.length < 12) return setError("Use at least 12 characters. A short sentence works well, like “my cat sleeps on the router”.");
    if (passphrase !== repeat) return setError("The two passphrases don't match.");
    setBusy(true);
    try {
      await api.post("/workspace/signing-key", { key_passphrase: passphrase });
      setPassphrase("");
      setRepeat("");
      setDone(true);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Could not save the passphrase";
      setNeedsSignIn(/sign in again/i.test(message));
      setError(message);
    } finally {
      setBusy(false);
    }
  };

  const finish = () => void queryClient.invalidateQueries();

  if (done) {
    return (
      <div className="login-wrap">
        <div className="login-card">
          <div className="db">
            <div className="brand"><img src="/logo-mark.svg" alt="" className="themed-logo" /><b>FileVow</b></div>
            <h1>You're all set, {user?.username}</h1>
            <p>Your passphrase is saved and your account is ready. Next, choose the folders and files you want to protect.</p>
            <div className="infobar warn"><Icon name="warn" /><div className="grow">
              <b>Keep a backup.</b> Download your encrypted key file and keep it on a USB drive. It's useless without your passphrase.
            </div></div>
          </div>
          <div className="df" style={{ gridTemplateColumns: "1fr", gap: 10 }}>
            <a className="btn full" href="/api/v1/workspace/signing-key/backup"><Icon name="download" />Download backup (recommended)</a>
            <button className="btn primary full" onClick={finish}>Start using FileVow</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit} noValidate>
        <div className="db">
          <div className="brand"><img src="/logo-mark.svg" alt="" className="themed-logo" /><b>FileVow</b></div>
          <h1>Set your passphrase</h1>
          <p>
            You'll type it to confirm important actions, like restoring or accepting a file. It also locks your
            personal signing key. It never leaves this PC, so <b>nobody can reset it</b>: pick one you'll remember.
          </p>
          <div className="field">
            <label htmlFor="pp">Passphrase</label>
            <PasswordInput id="pp" autoComplete="new-password" autoFocus value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)} />
            <div className="msg" style={{ display: "block", color: "var(--fv-text-subtle)" }}>
              At least 12 characters. {passphrase.length > 0 && passphrase.length < 12 ? `${12 - passphrase.length} more to go.` : ""}
            </div>
          </div>
          <div className="field">
            <label htmlFor="pp2">Repeat passphrase</label>
            <PasswordInput id="pp2" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
          </div>
          {error && <div className="form-error" role="alert">{error}</div>}
        </div>
        <div className="df" style={{ gridTemplateColumns: "1fr", gap: 10 }}>
          {needsSignIn ? (
            <button className="btn primary full" type="button" onClick={() => void logout()}>Sign in again</button>
          ) : (
            <button className="btn primary full" type="submit" disabled={busy}>
              {busy ? <span className="spinner" /> : "Save passphrase"}
            </button>
          )}
          <p className="subtle" style={{ textAlign: "center", margin: 0 }}>
            Signed in as {user?.email} · <button type="button" className="link" onClick={() => void logout()}>Sign out</button>
          </p>
        </div>
      </form>
    </div>
  );
}
