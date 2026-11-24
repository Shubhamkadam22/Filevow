import { useState, type FormEvent, type ReactNode } from "react";
import { useWorkspace } from "../api/queries";
import { useAuth } from "../auth/AuthContext";
import { Dialog } from "./Dialog";

export interface StepUpValues {
  password: string;
  totpCode: string;
  keyPassphrase: string;
  reason: string;
}

interface StepUpDialogProps {
  open: boolean;
  title?: string;
  description: string;
  summary?: ReactNode;
  confirmLabel: string;
  needsKey?: boolean;
  needsReason?: boolean;
  busy?: boolean;
  error?: string | null;
  onCancel: () => void;
  onConfirm: (values: StepUpValues) => void;
}

const EMPTY: StepUpValues = { password: "", totpCode: "", keyPassphrase: "", reason: "" };

/**
 * "Confirm it's you": fresh password, authenticator code and, when signing, the key passphrase.
 * Cloud accounts (Google / e-mail code) have no FileVow password: their signing-key passphrase
 * is the proof, so they type one secret. Before they have a key, a recent sign-in counts.
 */
export function StepUpDialog(props: StepUpDialogProps) {
  const { user } = useAuth();
  const workspace = useWorkspace();
  const [values, setValues] = useState<StepUpValues>(EMPTY);
  const [touched, setTouched] = useState(false);
  const needsTotp = Boolean(user?.mfa_enabled);
  const cloud = Boolean(user?.is_cloud);
  const hasKey = Boolean(workspace.data?.has_signing_key);
  const { needsReason = true } = props;
  const askSecret = !cloud || hasKey;
  const needsKey = Boolean(props.needsKey) && !cloud; // cloud: the one passphrase field covers both

  const missing = {
    password: askSecret && !values.password,
    totpCode: needsTotp && !/^\d{6}$/.test(values.totpCode),
    keyPassphrase: needsKey && !values.keyPassphrase,
    reason: needsReason && values.reason.trim().length < 3,
  };

  const close = () => {
    setValues(EMPTY);
    setTouched(false);
    props.onCancel();
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (Object.values(missing).some(Boolean)) return;
    props.onConfirm(cloud ? { ...values, keyPassphrase: values.password } : values);
    setValues((v) => ({ ...v, password: "", totpCode: "", keyPassphrase: "" }));
  };

  const field = (name: keyof StepUpValues, label: string, message: string, input: ReactNode) => (
    <div className={`field ${touched && missing[name] ? "err" : ""}`}>
      <label htmlFor={`su-${name}`}>{label}</label>
      {input}
      <div className="msg">{message}</div>
    </div>
  );

  const set = (name: keyof StepUpValues) => (event: { target: { value: string } }) =>
    setValues((v) => ({ ...v, [name]: name === "totpCode" ? event.target.value.replace(/\D/g, "").slice(0, 6) : event.target.value }));

  return (
    <Dialog
      open={props.open}
      onClose={close}
      title={
        <>
          <img src="/logo-mark.svg" alt="" className="themed-logo" />
          {props.title ?? "Confirm it's you"}
        </>
      }
      footer={
        <>
          <button className="btn primary" type="submit" form="step-up-form" disabled={props.busy}>
            {props.busy ? <span className="spinner" /> : props.confirmLabel}
          </button>
          <button className="btn" type="button" onClick={close}>
            Cancel
          </button>
        </>
      }
    >
      <form id="step-up-form" onSubmit={submit} noValidate>
        <p>{props.description}</p>
        {props.summary && <div className="summary">{props.summary}</div>}
        {askSecret && (cloud
          ? field("password", "Signing-key passphrase", "Your signing-key passphrase confirms it's you.",
            <input id="su-password" type="password" autoComplete="off" value={values.password} onChange={set("password")} />)
          : field("password", "Password", "Enter your password.",
            <input id="su-password" type="password" autoComplete="current-password" value={values.password} onChange={set("password")} />))}
        {needsTotp &&
          field("totpCode", "Authenticator code", "Enter the 6-digit code from your authenticator app.",
            <input id="su-totpCode" inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" value={values.totpCode} onChange={set("totpCode")} />)}
        {needsKey &&
          field("keyPassphrase", "Signing-key passphrase", "The passphrase unlocks your baseline signing key.",
            <input id="su-keyPassphrase" type="password" autoComplete="off" value={values.keyPassphrase} onChange={set("keyPassphrase")} />)}
        {needsReason &&
          field("reason", "Reason (saved in the audit log)", "A reason is required for every decision.",
            <input id="su-reason" placeholder="e.g. I updated this file myself" value={values.reason} onChange={set("reason")} />)}
        {props.error && <div className="form-error" role="alert">{props.error}</div>}
      </form>
    </Dialog>
  );
}
