import { useEffect, useState, type FormEvent } from "react";
import type { AuthOptions, EmailCodeStart } from "../api/types";
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

/**
 * Passwordless sign-in: the user types their e-mail address (or, on a PC they've used before,
 * their username) and gets a one-time code by e-mail. The first sign-in on a PC also asks for a
 * username, which they can use next time instead of the e-mail address.
 */
export function CloudSignIn({ options }: { options: AuthOptions }) {
  const { sendEmailCode, verifyEmailCode } = useAuth();
  const [login, setLogin] = useState("");
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("");
  const [sent, setSent] = useState<EmailCodeStart | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Errors from an optional Google round trip come back as ?signin_error=...
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
    if (login.trim().length < 3) return setError("Enter your e-mail address or username.");
    setBusy(true);
    try {
      const result = await sendEmailCode(login.trim());
      setSent(result);
      setCode("");
      if (result.new_account) setUsername((current) => current || result.suggested_username || "");
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
    if (sent?.new_account && !/^[a-zA-Z0-9._-]{3,64}$/.test(username.trim())) {
      return setError("Choose a username of 3-64 letters, numbers, dots, dashes or underscores.");
    }
    setBusy(true);
    try {
      await verifyEmailCode(login.trim(), code, sent?.new_account ? username.trim() : undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign in");
      setBusy(false);
    }
  };

  const startOver = () => {
    setSent(null);
    setCode("");
    setError(null);
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={sent ? verify : send} noValidate>
        <div className="db">
          <div className="brand">
            <img src="/logo-mark.svg" alt="" className="themed-logo" />
            <b>FileVow</b>
          </div>
          <h1>{firstAccount ? "Welcome to FileVow" : sent?.new_account ? "Create your account" : "Sign in"}</h1>
          <p>
            {sent
              ? `We sent a 6-digit code to ${sent.email_hint}. It's valid for 10 minutes.`
              : firstAccount
                ? "Enter your e-mail address. We'll send you a code to create your account, no password needed."
                : "Enter your username or e-mail address and we'll e-mail you a sign-in code. New here? Use your e-mail address."}
          </p>

          {options.google && !sent && (
            <>
              <a className="btn full google" href="/api/v1/auth/cloud/google">
                <GoogleMark />Continue with Google
              </a>
              <div className="or"><span>or use your e-mail</span></div>
            </>
          )}

          <div className="field">
            <label htmlFor="login">{firstAccount ? "E-mail address" : "Username or e-mail"}</label>
            <input id="login" autoComplete="username" value={login} disabled={Boolean(sent)} autoFocus
              onChange={(e) => setLogin(e.target.value)} placeholder={firstAccount ? "you@gmail.com" : "yourname or you@gmail.com"} />
          </div>

          {sent && (
            <div className="field">
              <label htmlFor="code">Code from the e-mail</label>
              <input id="code" inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" autoFocus
                value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 10))} />
            </div>
          )}

          {sent?.new_account && (
            <div className="field">
              <label htmlFor="username">Choose a username</label>
              <input id="username" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
              <div className="msg" style={{ display: "block", color: "var(--fv-text-subtle)" }}>
                Next time you can sign in with this instead of your e-mail.
              </div>
            </div>
          )}

          {error && <div className="form-error" role="alert">{error}</div>}
        </div>
        <div className="df" style={{ gridTemplateColumns: "1fr", gap: 10 }}>
          <button className="btn primary full" type="submit" disabled={busy}>
            {busy ? <span className="spinner" /> : sent ? (sent.new_account ? "Create account" : "Sign in") : "Send me a code"}
          </button>
          {sent && (
            <p className="subtle" style={{ textAlign: "center", margin: 0 }}>
              <button type="button" className="link" onClick={() => void send()} disabled={busy}>Send a new code</button>
              {" · "}
              <button type="button" className="link" onClick={startOver}>Use a different e-mail</button>
            </p>
          )}
          <p className="subtle" style={{ textAlign: "center", margin: 0, fontSize: 12 }}>
            Only your e-mail address and sign-in dates are stored online. Your files never leave this PC.
          </p>
        </div>
      </form>
    </div>
  );
}
