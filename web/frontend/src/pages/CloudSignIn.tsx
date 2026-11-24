import { useEffect, useState, type FormEvent } from "react";
import type { AuthOptions } from "../api/types";
import { useAuth } from "../auth/AuthContext";

/** Google's "G" mark, as Google's sign-in branding guidelines ask for on the button. */
function GoogleMark() {
  return (
    <svg viewBox="0 0 48 48" width="18" height="18" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.8 2.4 30.3 0 24 0 14.6 0 6.6 5.4 2.7 13.3l7.9 6.1C12.5 13.6 17.8 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.1 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.4c-.5 2.9-2.2 5.3-4.6 6.9l7.4 5.7c4.3-4 6.9-9.9 6.9-17.1z" />
      <path fill="#FBBC05" d="M10.6 28.6c-.5-1.4-.8-3-.8-4.6s.3-3.2.8-4.6l-7.9-6.1C1 16.6 0 20.2 0 24s1 7.4 2.7 10.7l7.9-6.1z" />
      <path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.4-5.7c-2.1 1.4-4.8 2.3-8.5 2.3-6.2 0-11.5-4.1-13.4-9.9l-7.9 6.1C6.6 42.6 14.6 48 24 48z" />
    </svg>
  );
}

/** Sign-in with Google or a one-time e-mail code (Supabase). First sign-in creates the account. */
export function CloudSignIn({ options }: { options: AuthOptions }) {
  const { sendEmailCode, verifyEmailCode } = useAuth();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [codeSent, setCodeSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Errors from the Google round trip come back as ?signin_error=...
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const message = params.get("signin_error");
    if (message) {
      setError(message);
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);

  const firstAccount = !options.has_accounts;

  const send = async (event?: FormEvent) => {
    event?.preventDefault();
    setError(null);
    setNotice(null);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) return setError("Enter your e-mail address.");
    setBusy(true);
    try {
      await sendEmailCode(email.trim());
      setCodeSent(true);
      setCode("");
      setNotice(`We sent a 6-digit code to ${email.trim()}. It's valid for a few minutes.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send the code");
    } finally {
      setBusy(false);
    }
  };

  const verify = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!/^\d{6,10}$/.test(code)) return setError("Enter the code from the e-mail.");
    setBusy(true);
    try {
      await verifyEmailCode(email.trim(), code);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in");
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={codeSent ? verify : send} noValidate>
        <div className="db">
          <div className="brand">
            <img src="/logo-mark.svg" alt="" className="themed-logo" />
            <b>FileVow</b>
          </div>
          <h1>{firstAccount ? "Welcome to FileVow" : "Sign in"}</h1>
          <p>
            {firstAccount
              ? "Sign in to create your account. It gets its own private workspace on this computer."
              : "Sign in to your private workspace. New here? Signing in creates your account."}
          </p>

          {options.google && !codeSent && (
            <>
              <a className="btn full google" href="/api/v1/auth/cloud/google">
                <GoogleMark />Continue with Google
              </a>
              {options.email && <div className="or"><span>or use your e-mail</span></div>}
            </>
          )}

          {options.email && (
            <>
              <div className="field">
                <label htmlFor="email">E-mail address</label>
                <input id="email" type="email" autoComplete="email" value={email} disabled={codeSent}
                  onChange={(e) => setEmail(e.target.value)} placeholder="you@gmail.com" />
              </div>
              {codeSent && (
                <div className="field">
                  <label htmlFor="code">Code from the e-mail</label>
                  <input id="code" inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" autoFocus
                    value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 10))} />
                </div>
              )}
            </>
          )}
          {notice && !error && <div className="form-note" role="status">{notice}</div>}
          {error && <div className="form-error" role="alert">{error}</div>}
        </div>
        {options.email && (
          <div className="df" style={{ gridTemplateColumns: "1fr", gap: 10 }}>
            <button className="btn primary full" type="submit" disabled={busy}>
              {busy ? <span className="spinner" /> : codeSent ? "Sign in" : "Send me a code"}
            </button>
            {codeSent && (
              <p className="subtle" style={{ textAlign: "center", margin: 0 }}>
                <button type="button" className="link" onClick={() => void send()} disabled={busy}>Send a new code</button>
                {" · "}
                <button type="button" className="link" onClick={() => { setCodeSent(false); setNotice(null); setError(null); }}>
                  Use a different e-mail
                </button>
              </p>
            )}
            <p className="subtle" style={{ textAlign: "center", margin: 0, fontSize: 12 }}>
              Only your e-mail address and sign-in dates are stored online. Your files never leave this PC.
            </p>
          </div>
        )}
      </form>
    </div>
  );
}
