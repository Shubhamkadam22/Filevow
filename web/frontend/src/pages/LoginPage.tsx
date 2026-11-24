import { useEffect, useState, type FormEvent } from "react";
import { ApiError, api } from "../api/client";
import type { AuthOptions } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CloudSignIn } from "./CloudSignIn";
import { PasswordInput } from "../components/PasswordInput";

type Mode = "signin" | "signup";

export function LoginPage() {
  const { login, register } = useAuth();
  const [options, setOptions] = useState<AuthOptions | null>(null);
  const [mode, setMode] = useState<Mode>("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get<AuthOptions>("/auth/options").then((o) => {
      setOptions(o);
      if (!o.has_accounts) setMode("signup"); // fresh installation: create the first account
    }).catch(() => undefined);
  }, []);

  const switchMode = (next: Mode) => {
    setMode(next);
    setError(null);
    setNeedsCode(false);
    setPassword("");
    setRepeat("");
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!username || !password) return setError("Enter a username and password.");
    if (mode === "signup") {
      if (password.length < 12) return setError("Use a password of at least 12 characters. A short sentence works well.");
      if (password !== repeat) return setError("The two passwords don't match.");
    }
    setBusy(true);
    try {
      if (mode === "signup") await register(username, password);
      else await login(username, password, needsCode ? code : undefined);
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_required") setNeedsCode(true);
      else setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  const signup = mode === "signup";
  const firstAccount = options !== null && !options.has_accounts;

  if (options === null) return <div className="login-wrap"><span className="spinner" aria-label="Loading" /></div>;
  if (options.cloud) return <CloudSignIn options={options} />;

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit} noValidate>
        <div className="db">
          <div className="brand">
            <img src="/logo-mark.svg" alt="" className="themed-logo" />
            <b>FileVow</b>
          </div>
          <h1>{signup ? (firstAccount ? "Welcome to FileVow" : "Create your account") : "Sign in"}</h1>
          <p>
            {signup
              ? firstAccount
                ? "Create the first account on this computer. It also becomes the administrator."
                : "Your account gets its own private workspace. Nobody else can see your folders."
              : "Sign in to your private workspace."}
          </p>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)}
              disabled={needsCode} autoFocus />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <PasswordInput id="password" autoComplete={signup ? "new-password" : "current-password"}
              value={password} onChange={(e) => setPassword(e.target.value)} disabled={needsCode} />
          </div>
          {signup && (
            <div className="field">
              <label htmlFor="repeat">Repeat password</label>
              <PasswordInput id="repeat" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
            </div>
          )}
          {needsCode && (
            <div className="field">
              <label htmlFor="code">Authenticator code</label>
              <input id="code" inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code or a recovery code"
                value={code} onChange={(e) => setCode(e.target.value.trim())} autoFocus />
            </div>
          )}
          {error && <div className="form-error" role="alert">{error}</div>}
        </div>
        <div className="df" style={{ gridTemplateColumns: "1fr", gap: 10 }}>
          <button className="btn primary full" type="submit" disabled={busy}>
            {busy ? <span className="spinner" /> : signup ? "Create account" : needsCode ? "Verify" : "Sign in"}
          </button>
          {options?.allow_registration && !firstAccount && (
            <p className="subtle" style={{ textAlign: "center", margin: 0 }}>
              {signup ? "Already have an account? " : "New here? "}
              <button type="button" className="link" onClick={() => switchMode(signup ? "signin" : "signup")}>
                {signup ? "Sign in" : "Create an account"}
              </button>
            </p>
          )}
        </div>
      </form>
    </div>
  );
}
