import { useState } from "react";
import { useWorkspace } from "../api/queries";
import { AddFolderFlow } from "./AddFolderFlow";
import { Icon } from "./Icon";
import { SigningKeyDialog } from "./SigningKeyDialog";

/** "Finish setting up" checklist in Settings, until the workspace is set up (or hidden). */
export function SetupGuide() {
  const { data } = useWorkspace();
  const [keyOpen, setKeyOpen] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [hidden, setHidden] = useState(() => {
    try {
      return localStorage.getItem("fv-setup-hidden") === "1";
    } catch {
      return false;
    }
  });

  if (!data) return null;
  const essentialsDone = data.has_signing_key && data.protected_files > 0;
  if (essentialsDone && (hidden || (data.mfa_enabled && data.channels > 0))) return dialogs();

  const allSteps = [
    {
      done: data.has_signing_key,
      title: "Create your signing key",
      text: "Your personal seal. It signs the fingerprint of every file you protect.",
      action: <button className="btn primary" onClick={() => setKeyOpen(true)}>Create key</button>,
    },
    {
      done: data.protected_files > 0,
      title: "Choose what to protect",
      text: "Pick a folder or file with Browse…: Documents, a project, your website…",
      action: <button className={`btn ${data.has_signing_key ? "primary" : ""}`} onClick={() => setAddOpen(true)}><Icon name="plus" />Add folder or file</button>,
    },
    {
      done: data.mfa_enabled,
      title: "Turn on two-step verification (recommended)",
      text: "A 6-digit code from your phone adds a second lock to your account.",
      action: <button className="btn" onClick={() => document.getElementById("account-settings")?.scrollIntoView({ behavior: "smooth" })}>Set up</button>,
    },
    {
      done: data.channels > 0,
      title: "Get alerts outside the app (optional)",
      text: "Email, Slack, Teams or a Windows notification when something changes.",
      action: <button className="btn" onClick={() => document.getElementById("notification-settings")?.scrollIntoView({ behavior: "smooth" })}>Add channel</button>,
    },
  ];

  const steps = allSteps.filter((step, index) => index !== 0 || !step.done);

  function dialogs() {
    return (
      <>
        <SigningKeyDialog open={keyOpen} onClose={() => setKeyOpen(false)} />
        <AddFolderFlow open={addOpen} hasSigningKey={Boolean(data?.has_signing_key)} onClose={() => setAddOpen(false)} onNeedKey={() => setKeyOpen(true)} />
      </>
    );
  }

  return (
    <>
      <div className="card setup">
        <h2>{essentialsDone ? "Recommended" : "Finish setting up"}</h2>
        <p>{essentialsDone
          ? "Your files are protected. These optional steps make your account safer."
          : "A few steps to set up your private workspace. Only you can see the folders you add here."}</p>
        <div className="steps">
          {steps.map((step, index) => (
            <div className={`step ${step.done ? "done" : ""}`} key={step.title}>
              <span className="num">{step.done ? <Icon name="check" /> : index + 1}</span>
              <div><b>{step.title}</b><span>{step.text}</span></div>
              {!step.done && step.action}
            </div>
          ))}
        </div>
        {essentialsDone && (
          <button className="link" style={{ marginTop: 10, fontSize: 13 }}
            onClick={() => { try { localStorage.setItem("fv-setup-hidden", "1"); } catch { /* ignore */ } setHidden(true); }}>
            Hide this guide
          </button>
        )}
      </div>
      {dialogs()}
    </>
  );
}
