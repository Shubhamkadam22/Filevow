import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { usePaths, useWorkspace } from "../api/queries";
import type { MonitoredPath, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { AddFolderFlow } from "../components/AddFolderFlow";
import { Icon } from "../components/Icon";
import { SigningKeyDialog } from "../components/SigningKeyDialog";
import { StepUpDialog, type StepUpValues } from "../components/StepUpDialog";
import { useToast } from "../components/Toast";

type Pending =
  | { kind: "update"; target: MonitoredPath; changes: Partial<{ severity: Severity; enabled: boolean }> }
  | { kind: "baseline"; target: MonitoredPath };

export function FoldersPage() {
  const { data: paths = [], isLoading } = usePaths();
  const workspace = useWorkspace();
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const toast = useToast();
  const [adding, setAdding] = useState(false);
  const [keyOpen, setKeyOpen] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const canEdit = can("user");

  const confirm = async (values: StepUpValues) => {
    if (!pending) return;
    const proof = { password: values.password, totp_code: values.totpCode || null };
    setBusy(true);
    setError(null);
    try {
      if (pending.kind === "update") {
        await api.patch(`/paths/${pending.target.id}`, { ...proof, ...pending.changes });
        toast("Folder updated");
      } else {
        const result = await api.post<{ created: number; already_protected: number }>(`/paths/${pending.target.id}/baseline`, {
          ...proof,
          key_passphrase: values.keyPassphrase,
        });
        toast("Up to date", `${result.created} new file${result.created === 1 ? "" : "s"} protected, ${result.already_protected} already protected.`);
      }
      setPending(null);
      await queryClient.invalidateQueries();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="page on">
      <h1 className="ptitle">
        Monitored folders<span className="sp" />
        {canEdit && <button className="btn primary" onClick={() => setAdding(true)}><Icon name="plus" />Add folder or file</button>}
      </h1>
      <p className="muted" style={{ marginTop: -8 }}>
        Everything listed here is checked every 15 minutes and within seconds of a change. Only you can see this list.
      </p>
      {isLoading && <div className="page-loading"><span className="spinner" /></div>}
      {!isLoading && paths.length === 0 && (
        <div className="empty">
          <div className="ic"><Icon name="folder" /></div>
          <b>Nothing is protected yet</b>
          Click “Add folder or file”, then Browse… to choose what to protect.
        </div>
      )}
      {paths.map((path) => (
        <div className="row" key={path.id}>
          <Icon name={path.is_directory ? "folder" : "file"} />
          <div className="txt">
            <b className="mono" style={{ fontSize: 13.5 }}>{path.path}</b>
            <span>
              {path.protected_files.toLocaleString()} protected file{path.protected_files === 1 ? "" : "s"}
              {path.recursive && path.is_directory ? " · includes subfolders" : ""}
              {path.exclude_patterns.length ? ` · skips ${path.exclude_patterns.join(", ")}` : ""}
              {path.protected_files === 0 ? " · not protected yet: click “Protect new files”" : ""}
            </span>
          </div>
          {canEdit && path.is_directory && (
            <button className="btn" onClick={() => setPending({ kind: "baseline", target: path })}
              title="Sign and back up files added since the folder was protected">
              <Icon name="key" />Protect new files
            </button>
          )}
          <select className="sel" value={path.severity} disabled={!canEdit} aria-label="Severity"
            onChange={(e) => setPending({ kind: "update", target: path, changes: { severity: e.target.value as Severity } })}>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <label className="toggle" title={path.enabled ? "Monitoring on" : "Monitoring paused"}>
            <input type="checkbox" checked={path.enabled} disabled={!canEdit} aria-label="Monitoring enabled"
              onChange={(e) => setPending({ kind: "update", target: path, changes: { enabled: e.target.checked } })} />
          </label>
        </div>
      ))}

      <AddFolderFlow open={adding} hasSigningKey={Boolean(workspace.data?.has_signing_key)}
        onClose={() => setAdding(false)} onNeedKey={() => setKeyOpen(true)} />
      <SigningKeyDialog open={keyOpen} onClose={() => setKeyOpen(false)} />

      <StepUpDialog
        open={pending !== null}
        description={
          pending?.kind === "baseline"
            ? "Files added to this folder since it was protected will be fingerprinted, backed up and signed with your key."
            : "Change how this folder is monitored."
        }
        confirmLabel={pending?.kind === "baseline" ? "Protect new files" : "Save"}
        needsKey={pending?.kind === "baseline"}
        needsReason={false}
        busy={busy}
        error={error}
        onCancel={() => { setPending(null); setError(null); }}
        onConfirm={confirm}
      />
    </section>
  );
}
