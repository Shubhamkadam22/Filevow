import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useChanges, useDashboard, useStartRun, useWorkspace } from "../api/queries";
import { AddFolderFlow } from "../components/AddFolderFlow";
import { Icon, SeverityIcon } from "../components/Icon";
import { SigningKeyDialog } from "../components/SigningKeyDialog";
import { useToast } from "../components/Toast";
import { useNow } from "../hooks/useLiveEvents";
import { clockTime, countdown, humanAction, severityOrder, timeAgo } from "../lib/format";

export function HomePage() {
  const { data, isLoading } = useDashboard();
  const changes = useChanges("open");
  const startRun = useStartRun();
  const navigate = useNavigate();
  const toast = useToast();
  const now = useNow();
  const workspace = useWorkspace();
  const [adding, setAdding] = useState(false);
  const [keyOpen, setKeyOpen] = useState(false);

  if (isLoading || !data) return <div className="page-loading"><span className="spinner" /></div>;

  const open = [...(changes.data ?? [])].sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
  const critical = data.open_by_severity.critical ?? 0;
  const healthy = data.open_changes === 0;
  const { layers } = data;
  const runs = data.runs_24h;

  return (
    <section className="page on">
      <h1 className="ptitle">Home</h1>
      <div className={`card hero ${healthy ? "ok" : "warn"}`}>
        <div className="badge-ic"><Icon name={healthy ? "ok" : "warn"} /></div>
        <div>
          <h1>{healthy ? (data.protected_files ? "Your files are protected" : "Ready when you are") : "Action needed"}</h1>
          <p>
            {healthy
              ? data.protected_files
                ? `All ${data.protected_files.toLocaleString()} files match their signed, approved versions.`
                : "Nothing is protected yet. Add a folder or file to start."
              : `${critical ? `${critical} critical issue${critical > 1 ? "s" : ""} and ` : ""}${data.open_changes - critical} change${data.open_changes - critical === 1 ? "" : "s"} waiting for your review.`}
          </p>
          <div className="facts">
            <span><Icon name="clock" />Last check <b>{data.last_run ? timeAgo(data.last_run.started_at, now) : "not yet"}</b></span>
            <span><Icon name="verify" />Next check in <b>{countdown(data.next_run_at, now)}</b></span>
            <span><Icon name="heart" />Agent <b>{data.agent_online ? `seen ${timeAgo(data.agent_last_seen, now)}` : "offline"}</b></span>
          </div>
        </div>
        <div className="acts">
          <button className="btn" disabled={startRun.isPending}
            onClick={() => startRun.mutate(undefined, { onSuccess: () => toast("Verification started", "Results appear in a moment.") })}>
            <Icon name="verify" />Verify now
          </button>
          {!healthy && <button className="btn primary" onClick={() => navigate("/review")}>Review changes</button>}
          {healthy && !data.protected_files && (
            <button className="btn primary" onClick={() => setAdding(true)}><Icon name="plus" />Add folder or file</button>
          )}
        </div>
      </div>

      <h2 className="sec">Verification layers</h2>
      <div className="grid3">
        <LayerCard icon="hash" title="File contents" caption="SHA-256 fingerprints match" ok={layers.content_ok} total={layers.total} failText="files differ" />
        <LayerCard icon="key" title="Signatures" caption="RSA-3072 records verified" ok={layers.signatures_ok} total={layers.total} failText="records not genuine" />
        <LayerCard icon="lock" title="Mirror vault" caption="Encrypted copies intact" ok={layers.mirror_ok} total={layers.total} failText="copies damaged" />
      </div>

      <div className="card spark" style={{ marginTop: 8 }}>
        <div className="hd">
          <b>Last 24 hours</b>
          <span className="subtle">
            · {runs.length} run{runs.length === 1 ? "" : "s"} · {runs.filter((r) => r.issue_count > 0).length} with issues
          </span>
          <span className="sp" />
          <span className="subtle">Each bar is one verification run</span>
        </div>
        <div className="bars" role="img" aria-label="Verification runs in the last 24 hours">
          {runs.length === 0 && <span className="subtle">No runs yet. The agent runs a check every 15 minutes.</span>}
          {runs.map((run) => (
            <i key={run.id} className={run.issue_count > 0 ? "bad" : ""} title={`Run #${run.id} · ${clockTime(run.started_at)} · ${run.issue_count} issues`} />
          ))}
        </div>
      </div>

      <div className="two">
        <div>
          <h2 className="sec">Needs attention<span className="sp" /><Link to="/review" className="link">Open review queue</Link></h2>
          {open.length === 0 ? (
            <div className="row"><Icon name="ok" className="sev ok" /><div className="txt"><b>Nothing needs your attention</b><span>Every protected file matches its signed, approved version</span></div></div>
          ) : (
            <>
              {open.slice(0, 4).map((change) => (
                <div key={change.id} className="row click" role="link" tabIndex={0}
                  onClick={() => navigate(`/review/${change.id}`)} onKeyDown={(e) => e.key === "Enter" && navigate(`/review/${change.id}`)}>
                  <SeverityIcon severity={change.severity} />
                  <div className="txt">
                    <b>{change.title} — <span className="mono" style={{ display: "inline", fontSize: 13 }}>{change.name}</span></b>
                    <span>{change.folder}</span>
                  </div>
                  <span className="meta" title={new Date(change.detected_at).toLocaleString()}>{timeAgo(change.detected_at, now)}</span>
                  <Icon name="chev" className="chev" />
                </div>
              ))}
              {open.length > 4 && (
                <div className="row click" style={{ minHeight: 44 }} onClick={() => navigate("/review")}>
                  <Icon name="review" /><div className="txt"><b>{open.length - 4} more waiting</b></div><Icon name="chev" className="chev" />
                </div>
              )}
            </>
          )}
        </div>
        <div>
          <h2 className="sec">Recent activity<span className="sp" /><Link to="/audit" className="link">Audit log</Link></h2>
          <div className="card timeline">
            {data.activity.length === 0 && <div className="subtle" style={{ padding: 12 }}>No activity yet.</div>}
            {data.activity.map((entry, index) => (
              <div className="tl" key={`${entry.created_at}-${index}`}>
                <i className={`d ${entry.action.includes("ACCEPT") || entry.action.includes("RESTORE") ? "ok" : entry.action.includes("DETECTED") || entry.action.includes("FAILED") ? "crit" : entry.action.startsWith("LOGIN") ? "info" : ""}`} />
                <div>{humanAction(entry.action)}<small>{entry.summary}{entry.summary ? " · " : ""}{entry.actor}</small></div>
                <time title={new Date(entry.created_at).toLocaleString()}>{timeAgo(entry.created_at, now)}</time>
              </div>
            ))}
          </div>
        </div>
      </div>
      <AddFolderFlow open={adding} hasSigningKey={Boolean(workspace.data?.has_signing_key)}
        onClose={() => setAdding(false)} onNeedKey={() => setKeyOpen(true)} />
      <SigningKeyDialog open={keyOpen} onClose={() => setKeyOpen(false)} />
    </section>
  );
}

function LayerCard(props: { icon: string; title: string; caption: string; ok: number; total: number; failText: string }) {
  const failing = props.total - props.ok;
  return (
    <div className="card layer">
      <div className="top"><Icon name={props.icon} />{props.title}</div>
      <div className="n">{props.ok.toLocaleString()} / {props.total.toLocaleString()}</div>
      <div className="subtle">{props.caption}</div>
      <div className={`st ${failing ? "bad" : ""}`}>
        <Icon name={failing ? "warn" : "ok"} />
        <span>{failing ? `${failing} ${props.failText}` : "All verified"}</span>
      </div>
    </div>
  );
}
