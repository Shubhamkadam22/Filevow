import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import type { Change, ChangeDetail } from "../api/types";
import { useChange, useChanges, useDecision, type DecisionKind } from "../api/queries";
import { useAuth } from "../auth/AuthContext";
import { CopyButton, copyText } from "../components/CopyButton";
import { Dialog } from "../components/Dialog";
import { DiffView } from "../components/DiffView";
import { Icon, SeverityIcon } from "../components/Icon";
import { StepUpDialog, type StepUpValues } from "../components/StepUpDialog";
import { useToast } from "../components/Toast";
import { useHotkeys } from "../hooks/useHotkeys";
import { useNow } from "../hooks/useLiveEvents";
import { bytes, clockTime, severityLabel, severityOrder, shortHash, timeAgo } from "../lib/format";

type SeverityFilter = "all" | "critical" | "high" | "medium";
type Grouping = "severity" | "folder" | "none";
interface PendingDecision {
  kind: DecisionKind;
  changes: Change[];
}

const DOT: Record<string, string> = { critical: "var(--fv-critical)", high: "var(--fv-pending)", medium: "var(--fv-link)" };

export function ReviewPage() {
  const params = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { can } = useAuth();
  const now = useNow(5000);
  const { data: changes = [], isLoading } = useChanges("open");
  const decision = useDecision();

  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [query, setQuery] = useState("");
  const [grouping, setGrouping] = useState<Grouping>("severity");
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const [pending, setPending] = useState<PendingDecision | null>(null);
  const [error, setError] = useState<string | null>(null);
  const filterInput = useRef<HTMLInputElement>(null);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase().replaceAll("\\", "/");
    return changes
      .filter((c) => (severity === "all" || c.severity === severity) && (!q || c.file_path.includes(q) || c.title.toLowerCase().includes(q)))
      .sort((a, b) =>
        grouping === "folder"
          ? a.folder.localeCompare(b.folder) || b.detected_at.localeCompare(a.detected_at)
          : grouping === "severity"
            ? (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) || b.detected_at.localeCompare(a.detected_at)
            : b.detected_at.localeCompare(a.detected_at),
      );
  }, [changes, severity, query, grouping]);

  const selectedId = params.id ? Number(params.id) : (visible[0]?.id ?? null);
  const selectedIndex = visible.findIndex((c) => c.id === selectedId);
  const detail = useChange(selectedId);

  useEffect(() => {
    setChecked((current) => new Set([...current].filter((id) => changes.some((c) => c.id === id))));
  }, [changes]);

  const select = (id: number | undefined) => id !== undefined && navigate(`/review/${id}`, { replace: true });
  const step = (delta: number) => select(visible[Math.max(0, Math.min(visible.length - 1, selectedIndex + delta))]?.id);
  const current = changes.find((c) => c.id === selectedId);

  const begin = (kind: DecisionKind, targets: Change[]) => {
    if (targets.length === 0) return;
    setError(null);
    setPending({ kind, changes: targets });
  };

  const submit = (values: StepUpValues) => {
    if (!pending) return;
    const ids = pending.changes.map((c) => c.id);
    const nextId = visible.filter((c) => !ids.includes(c.id))[Math.max(0, selectedIndex)]?.id;
    decision.mutate(
      {
        kind: pending.kind,
        ids,
        reason: values.reason,
        proof: { password: values.password, totp_code: values.totpCode || null },
        keyPassphrase: values.keyPassphrase,
        expectedSha256: pending.changes.length === 1 ? pending.changes[0]?.observed_sha256 : undefined,
      },
      {
        onSuccess: ({ decisions, skipped }) => {
          setPending(null);
          setChecked(new Set());
          const skippedCount = Object.keys(skipped).length;
          toast(
            decisions.length > 1 ? `${decisions.length} changes ${pending.kind === "accept" ? "accepted" : "restored"}` : decisions[0]?.message ?? "Done",
            skippedCount ? `${skippedCount} skipped: ${Object.values(skipped)[0]}` : undefined,
          );
          if (nextId) navigate(`/review/${nextId}`, { replace: true });
          else navigate("/review", { replace: true });
        },
        onError: (err) => setError(err.message),
      },
    );
  };

  const toggleCheck = (id: number) =>
    setChecked((set) => {
      const next = new Set(set);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  useHotkeys({
    j: () => step(1),
    arrowdown: () => step(1),
    k: () => step(-1),
    arrowup: () => step(-1),
    "/": () => filterInput.current?.focus(),
    x: () => selectedId !== null && toggleCheck(selectedId),
    a: () => current?.can_accept && can("user") && begin("accept", [current]),
    r: () => current?.can_restore && can("user") && begin("restore", [current]),
    f: () => current && can("analyst") && begin("reject", [current]),
    e: () => current && can("analyst") && begin("escalate", [current]),
    c: () => current?.observed_sha256 && copyText(current.observed_sha256).then(() => toast("Copied", current.observed_sha256 ?? "")),
  });

  const checkedChanges = changes.filter((c) => checked.has(c.id));
  const restorable = checkedChanges.filter((c) => c.can_restore);
  const counts = (s: SeverityFilter) => changes.filter((c) => s === "all" || c.severity === s).length;

  let lastGroup = "";
  return (
    <section className="page full on" id="p-review">
      <div className="master">
        <div className="mh">
          <h1 className="ptitle">Review changes</h1>
          <div className="infield">
            <Icon name="search" />
            <input ref={filterInput} className="txtin" placeholder="Filter by file or folder" aria-label="Filter changes"
              value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Escape" && e.currentTarget.blur()} />
            <kbd>/</kbd>
          </div>
          <div className="chips" role="group" aria-label="Severity filter">
            {(["all", "critical", "high", "medium"] as SeverityFilter[]).map((s) => (
              <button key={s} className={`chip ${severity === s ? "on" : ""}`} aria-pressed={severity === s} onClick={() => setSeverity(s)}>
                {s !== "all" && <i className="d" style={{ background: DOT[s] }} />}
                {s === "all" ? "All" : severityLabel[s]}<b>{counts(s)}</b>
              </button>
            ))}
          </div>
          <select className="sel" value={grouping} onChange={(e) => setGrouping(e.target.value as Grouping)} style={{ width: "100%" }} aria-label="Group by">
            <option value="severity">Group by severity</option>
            <option value="folder">Group by folder</option>
            <option value="none">No grouping (newest first)</option>
          </select>
        </div>

        <div className={`bulk ${checked.size ? "on" : ""}`} role="region" aria-label="Bulk actions">
          <b>{checked.size} selected</b>
          <span className="sp" />
          {can("user") && (
            <>
              <button className="btn primary" onClick={() => begin("accept", checkedChanges.filter((c) => c.can_accept))}>Accept</button>
              <button className="btn" disabled={!restorable.length} onClick={() => begin("restore", restorable)}>
                {restorable.length && restorable.length < checked.size ? `Restore ${restorable.length}` : "Restore"}
              </button>
            </>
          )}
          <button className="btn subtle" onClick={() => setChecked(new Set())}>Clear</button>
        </div>

        <div className="list" role="listbox" aria-label="Pending changes">
          {isLoading && <div className="page-loading"><span className="spinner" /></div>}
          {!isLoading && changes.length === 0 && (
            <div className="empty"><div className="ic"><Icon name="ok" /></div><b>You're all caught up</b>No changes are waiting for review.</div>
          )}
          {!isLoading && changes.length > 0 && visible.length === 0 && (
            <div className="empty" style={{ paddingTop: 28 }}><b>No matches</b>Try a different filter.</div>
          )}
          {visible.map((change) => {
            const group = grouping === "severity" ? severityLabel[change.severity] ?? change.severity : grouping === "folder" ? change.folder : "";
            const header = group && group !== lastGroup ? (
              <div className="lgroup">{group}<span className="subtle">{visible.filter((c) => (grouping === "severity" ? severityLabel[c.severity] : c.folder) === group).length}</span></div>
            ) : null;
            lastGroup = group;
            const isSelected = change.id === selectedId;
            return (
              <div key={change.id}>
                {header}
                <div className={`lrow ${isSelected ? "sel" : ""}`} role="option" aria-selected={isSelected} tabIndex={isSelected ? 0 : -1}
                  onClick={() => select(change.id)}>
                  <input type="checkbox" checked={checked.has(change.id)} aria-label={`Select ${change.name}`}
                    onClick={(e) => e.stopPropagation()} onChange={() => toggleCheck(change.id)} />
                  <SeverityIcon severity={change.severity} />
                  <div className="t"><b>{change.name}</b><span>{change.title} · {change.folder}</span></div>
                  <time title={clockTime(change.detected_at)}>{timeAgo(change.detected_at, now).replace(" ago", "")}</time>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="detail">
        <div className="inner">
          {selectedId === null || !detail.data ? (
            changes.length === 0 ? (
              <div className="empty"><div className="ic"><Icon name="ok" /></div><b>Every file matches its approved version</b>New changes appear here as soon as they are detected.</div>
            ) : (
              <div className="page-loading"><span className="spinner" /></div>
            )
          ) : (
            <ChangePanel
              change={detail.data}
              position={`${selectedIndex + 1} of ${visible.length}`}
              canPrev={selectedIndex > 0}
              canNext={selectedIndex < visible.length - 1}
              onStep={step}
              onDecide={(kind) => begin(kind, [detail.data])}
              canAdmin={can("user")}
              canAnalyst={can("analyst")}
            />
          )}
        </div>
      </div>

      {pending && (pending.kind === "reject" || pending.kind === "escalate") ? (
        <ReasonDialog kind={pending.kind} change={pending.changes[0]} busy={decision.isPending} error={error}
          onCancel={() => setPending(null)} onConfirm={(reason) => submit({ password: "", totpCode: "", keyPassphrase: "", reason })} />
      ) : (
        <StepUpDialog
          open={pending !== null}
          description={
            pending?.kind === "accept"
              ? "You're about to approve new content. FileVow will sign it with your baseline key."
              : pending?.kind === "quarantine"
                ? "FileVow keeps an encrypted evidence copy, then removes the file."
                : "FileVow saves the current file as evidence, then puts back the approved copy from the encrypted vault."
          }
          summary={pending && <DecisionSummary pending={pending} />}
          confirmLabel={`${pending?.kind === "accept" ? "Accept" : pending?.kind === "quarantine" ? "Quarantine" : "Restore"}${pending && pending.changes.length > 1 ? ` ${pending.changes.length}` : ""}`}
          needsKey={pending?.kind === "accept"}
          busy={decision.isPending}
          error={error}
          onCancel={() => setPending(null)}
          onConfirm={submit}
        />
      )}
    </section>
  );
}

function DecisionSummary({ pending }: { pending: PendingDecision }) {
  const [only] = pending.changes;
  if (pending.changes.length > 1 || !only) {
    return (
      <>
        <div><span>{pending.changes.length} files</span><span>{pending.kind === "accept" ? "each gets a new signed version" : "each is restored, evidence kept"}</span></div>
        <ul>{pending.changes.map((c) => <li key={c.id} className="mono">{c.name}</li>)}</ul>
      </>
    );
  }
  return (
    <>
      <div><span>File</span><span className="mono">{only.name}</span></div>
      {pending.kind === "accept" && <div><span>Version</span><span>{only.approved_version ? `v${only.approved_version} → v${only.approved_version + 1}` : "new → v1"}</span></div>}
      {pending.kind === "restore" && <div><span>Restore to</span><span>approved version {only.approved_version}</span></div>}
      <div><span>{pending.kind === "accept" ? "New SHA-256" : "Evidence copy"}</span><span className="mono">{shortHash(only.observed_sha256)}</span></div>
    </>
  );
}

function ReasonDialog({ kind, change, busy, error, onCancel, onConfirm }: {
  kind: "reject" | "escalate";
  change?: Change;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  const [touched, setTouched] = useState(false);
  const invalid = reason.trim().length < 3;
  return (
    <Dialog open title={kind === "reject" ? "Mark as false positive" : "Escalate"} onClose={onCancel}
      footer={
        <>
          <button className="btn primary" form="reason-form" type="submit" disabled={busy}>{busy ? <span className="spinner" /> : kind === "reject" ? "Mark as false positive" : "Escalate"}</button>
          <button className="btn" onClick={onCancel}>Cancel</button>
        </>
      }>
      <form id="reason-form" onSubmit={(e) => { e.preventDefault(); setTouched(true); if (!invalid) onConfirm(reason.trim()); }}>
        <p>
          {kind === "reject"
            ? `The approved version of ${change?.name} stays as it is. If the file still differs, it will be detected again on the next run.`
            : `The security team is notified about ${change?.name}. The change stays open.`}
        </p>
        <div className={`field ${touched && invalid ? "err" : ""}`}>
          <label htmlFor="reason">Reason (saved in the audit log)</label>
          <input id="reason" value={reason} onChange={(e) => setReason(e.target.value)} />
          <div className="msg">A reason is required for every decision.</div>
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
      </form>
    </Dialog>
  );
}

function LayerTile({ name, ok, sub, fail, na = "Not checked" }: { name: string; ok: boolean | null; sub: string; fail: string; na?: string }) {
  const state = ok === true ? "pass" : ok === false ? "fail" : "na";
  return (
    <div className={`lc ${state}`}>
      <Icon name={ok === true ? "ok" : ok === false ? "err" : "minus"} />
      <div><b>{name}</b><span>{ok === true ? sub : ok === false ? fail : na}</span></div>
    </div>
  );
}

function ChangePanel({ change, position, canPrev, canNext, onStep, onDecide, canAdmin, canAnalyst }: {
  change: ChangeDetail;
  position: string;
  canPrev: boolean;
  canNext: boolean;
  onStep: (delta: number) => void;
  onDecide: (kind: DecisionKind) => void;
  canAdmin: boolean;
  canAnalyst: boolean;
}) {
  const [mode, setMode] = useState<"split" | "unified">("split");
  const [onlyChanges, setOnlyChanges] = useState(false);
  const info = {
    critical: ["crit", "err", "The integrity record was altered or cannot be trusted.", "The approved copy is safe in the encrypted vault. Restoring repairs the record from the signed history."],
    high: ["warn", "warn", change.event_type === "UNKNOWN_FILE_CREATED" ? "A file appeared that was never approved." : "This file changed since it was approved.",
      change.event_type === "UNKNOWN_FILE_CREATED" ? "Approve it to start protecting it, or quarantine it if nobody expected it." : "Compare it with the approved copy, then accept it if expected or restore the approved version."],
    medium: ["info", "info", "Only the file's metadata changed.", "The content still matches. Check whether the new permissions were intended."],
    low: ["info", "info", "Something needs a look.", "Review the details below."],
  }[change.severity];

  return (
    <>
      <div className="dhead">
        <div className="t">
          <h1>{change.name}</h1>
          <div className="path"><span className="mono" style={{ fontSize: 12 }}>{change.file_path}</span><CopyButton text={change.file_path} label="Copy path" /></div>
        </div>
        <span className={`pill ${change.severity === "critical" ? "crit" : change.severity === "high" ? "high" : "med"}`}>
          <Icon name={change.severity === "critical" ? "err" : "warn"} />{severityLabel[change.severity]}
        </span>
      </div>

      <div className="toolbar" role="toolbar" aria-label="Decision">
        {canAdmin && change.can_accept && (
          <button className="btn primary" title="Accept (A)" onClick={() => onDecide("accept")}>
            <Icon name="check" />{change.approved_version ? "Accept" : "Approve and protect"}<kbd>A</kbd>
          </button>
        )}
        {canAdmin && change.can_restore && (
          <button className="btn" title="Restore approved version (R)" onClick={() => onDecide("restore")}>
            <Icon name="undo" />Restore v{change.approved_version}<kbd>R</kbd>
          </button>
        )}
        {canAdmin && change.can_quarantine && (
          <button className="btn" onClick={() => onDecide("quarantine")}><Icon name="trash" />Quarantine</button>
        )}
        {canAnalyst && (
          <>
            <button className="btn" title="Mark as false positive (F)" onClick={() => onDecide("reject")}><Icon name="flag" />False positive<kbd>F</kbd></button>
            <button className="btn danger" title="Escalate (E)" onClick={() => onDecide("escalate")}><Icon name="escalate" />Escalate<kbd>E</kbd></button>
          </>
        )}
        {!canAnalyst && <span className="subtle">You have view-only access.</span>}
        <span className="nav-group">
          <span className="subtle">{position}</span>
          <button className="btn icon subtle" title="Previous (K)" aria-label="Previous change" disabled={!canPrev} onClick={() => onStep(-1)}><Icon name="up" /></button>
          <button className="btn icon subtle" title="Next (J)" aria-label="Next change" disabled={!canNext} onClick={() => onStep(1)}><Icon name="down" /></button>
        </span>
      </div>

      {info && <div className={`infobar ${info[0]}`}><Icon name={info[1] ?? "info"} /><div className="grow"><b>{info[2]}</b>{info[3]}</div></div>}
      {change.review_status === "escalated" && <div className="infobar warn"><Icon name="escalate" /><div className="grow"><b>Escalated.</b>{change.review_reason}</div></div>}

      <div className="lchecks">
        {(() => {
          const na = change.approved_version ? "Not checked" : "Not applicable";
          return (
            <>
              <LayerTile name="Signature" ok={change.layers.signature} sub="RSA record genuine" fail="Record does not verify" na={change.approved_version ? na : "No signed record yet"} />
              <LayerTile name="Mirror copy" ok={change.layers.mirror} sub="Encrypted copy intact" fail="Copy damaged" na={na} />
              <LayerTile name="Content" ok={change.layers.content} sub="SHA-256 matches" fail="SHA-256 differs" na={change.approved_version ? na : "No approved version"} />
              <LayerTile name="Metadata" ok={change.layers.metadata} sub="Owner and ACL match" fail="Permissions differ" na={na} />
            </>
          );
        })()}
      </div>

      <div className="kv">
        <div className="h">Property</div><div className="h">Approved{change.approved_version ? ` · version ${change.approved_version}` : ""}</div><div className="h">Now on disk</div>
        <div className="k">SHA-256</div>
        <div className="mono hash">{change.expected_sha256 ? <span><b>{change.expected_sha256.slice(0, 8)}</b>{change.expected_sha256.slice(8)}</span> : "—"}</div>
        <div className={`mono hash ${change.expected_sha256 !== change.observed_sha256 ? "bad" : ""}`}>
          {change.observed_sha256 ? <><span><b>{change.observed_sha256.slice(0, 8)}</b>{change.observed_sha256.slice(8)}</span><CopyButton text={change.observed_sha256} label="Copy hash (C)" /></> : "—"}
        </div>
        <div className="k">Size</div><div>{bytes(change.expected_size)}</div>
        <div className={change.expected_size !== change.observed_size ? "bad" : ""}>{change.event_type === "FILE_DELETED" ? "deleted" : bytes(change.observed_size)}</div>
        {Object.entries(change.metadata_changes).map(([name, [before, after]]) => (
          <MetadataRow key={name} name={name} before={before} after={after} />
        ))}
        <div className="k">Detected</div><div className="muted">—</div>
        <div>{clockTime(change.detected_at)} · {timeAgo(change.detected_at)}{change.occurrence_count > 1 ? ` · seen ${change.occurrence_count}×` : ""}{change.run_id ? ` · run #${change.run_id}` : ""}</div>
      </div>

      <div className="diffbar">
        <h2>Content comparison</h2>
        {change.diff && <span className="stat"><span className="a">+{change.diff.added}</span> <span className="r">−{change.diff.removed}</span></span>}
        <span className="sp" />
        {change.diff && (
          <>
            <label className="toggle" style={{ fontSize: 13 }}><span className="muted">Only changes</span><input type="checkbox" checked={onlyChanges} onChange={(e) => setOnlyChanges(e.target.checked)} /></label>
            <div className="seg" role="group" aria-label="Diff layout">
              <button className={mode === "split" ? "on" : ""} onClick={() => setMode("split")}>Side by side</button>
              <button className={mode === "unified" ? "on" : ""} onClick={() => setMode("unified")}>Unified</button>
            </div>
          </>
        )}
      </div>
      {change.diff ? (
        <DiffView lines={change.diff.lines} mode={mode} onlyChanges={onlyChanges}
          approvedLabel={change.approved_version ? `Approved version ${change.approved_version} · from the mirror vault` : "No approved version"} />
      ) : (
        <div className="diff"><div className="metachg"><Icon name="info" /> {change.diff_note}</div></div>
      )}
      <p className="subtle dfoot">Accepting creates a new signed version and needs your password, an authenticator code and the signing-key passphrase. Restoring first saves the current file as evidence.</p>
    </>
  );
}

function MetadataRow({ name, before, after }: { name: string; before: string | null | undefined; after: string | null | undefined }) {
  const label = name === "access_list" ? "Access list" : name.charAt(0).toUpperCase() + name.slice(1);
  return (
    <>
      <div className="k">{label}</div>
      <div>{before ?? "—"}</div>
      <div className="bad">{after ?? "—"}</div>
    </>
  );
}
