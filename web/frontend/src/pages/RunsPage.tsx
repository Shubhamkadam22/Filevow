import { useState } from "react";
import { useRun, useRuns, useStartRun, useSystem } from "../api/queries";
import { useAuth } from "../auth/AuthContext";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import { clockTime, fullDate, timeAgo } from "../lib/format";

export function RunsPage() {
  const { data: runs = [], isLoading } = useRuns();
  const system = useSystem();
  const startRun = useStartRun();
  const toast = useToast();
  const { can } = useAuth();
  const [openId, setOpenId] = useState<number | null>(null);

  const chartRuns = [...runs].reverse().slice(-24);
  const durations = chartRuns.map((r) => (r.duration_ms ?? 0) / 1000);
  const max = Math.max(1, ...durations);
  const points = chartRuns.map((run, i) => [chartRuns.length > 1 ? (i * 600) / (chartRuns.length - 1) : 300, 82 - ((run.duration_ms ?? 0) / 1000 / max) * 70, run.issue_count] as const);

  return (
    <section className="page on">
      <h1 className="ptitle">
        Verification history<span className="sp" />
        {can("analyst") && (
          <button className="btn" disabled={startRun.isPending} onClick={() => startRun.mutate(undefined, { onSuccess: () => toast("Verification started") })}>
            <Icon name="verify" />Verify now
          </button>
        )}
      </h1>
      <div className="row">
        <Icon name="clock" />
        <div className="txt">
          <b>Schedule</b>
          <span>Every {system.data?.verification_interval_minutes ?? 15} minutes, plus at start-up and within seconds of a change. Each report is signed with the agent key.</span>
        </div>
      </div>
      {chartRuns.length > 1 && (
        <div className="card chart">
          <div style={{ display: "flex", gap: 10, alignItems: "baseline" }}><b style={{ fontWeight: 600 }}>Run duration</b><span className="subtle">last {chartRuns.length} runs · up to {max.toFixed(1)} s</span></div>
          <svg viewBox="0 0 600 90" preserveAspectRatio="none" role="img" aria-label="Run duration chart">
            <polyline points={points.map(([x, y]) => `${x},${y}`).join(" ")} fill="none" stroke="var(--accent)" strokeWidth={2} vectorEffect="non-scaling-stroke" />
            {points.map(([x, y, issues], i) => <circle key={i} cx={x} cy={y} r={2.5} fill={issues ? "var(--fv-critical)" : "var(--accent)"} />)}
          </svg>
        </div>
      )}
      <h2 className="sec">Recent runs</h2>
      <div className="table runs">
        <div className="tr th"><div>Run</div><div>Started</div><div>Result</div><div>Files</div><div>Duration</div><div>Report</div></div>
        {isLoading && <div className="page-loading"><span className="spinner" /></div>}
        {!isLoading && runs.length === 0 && <div className="empty" style={{ padding: 28 }}>No verification runs yet.</div>}
        {runs.map((run) => (
          <div key={run.id} className="tr click" onClick={() => setOpenId(run.id)}>
            <div className="mono">#{run.id}</div>
            <div className="muted">{clockTime(run.started_at)} · {timeAgo(run.started_at)} · {run.run_type}</div>
            <div>
              {run.issue_count ? <span className="pill crit"><Icon name="warn" />{run.issue_count} issue{run.issue_count > 1 ? "s" : ""}</span>
                : <span className="pill ok"><Icon name="check" />No changes</span>}
            </div>
            <div>{run.files_checked.toLocaleString()}</div>
            <div className="muted">{((run.duration_ms ?? 0) / 1000).toFixed(1)} s</div>
            <div className="muted" style={{ display: "flex", alignItems: "center", gap: 6 }}>
              {run.signed ? <><Icon name="check" />Signed</> : "Not signed"}
            </div>
          </div>
        ))}
      </div>
      <RunDialog id={openId} onClose={() => setOpenId(null)} />
    </section>
  );
}

function RunDialog({ id, onClose }: { id: number | null; onClose: () => void }) {
  const { data } = useRun(id);
  return (
    <Dialog open={id !== null} onClose={onClose} width={640} title={`Run #${id ?? ""}`}
      footer={<button className="btn" onClick={onClose} style={{ gridColumn: "1 / -1" }}>Close</button>}>
      {!data ? <div className="page-loading"><span className="spinner" /></div> : (
        <>
          <div className="summary">
            <div><span>Started</span><span>{fullDate(data.started_at)}</span></div>
            <div><span>Files checked</span><span>{data.files_checked.toLocaleString()} · {data.ok_count.toLocaleString()} OK</span></div>
            <div><span>Report signature</span><span>{data.signature_valid === null ? "Not signed" : data.signature_valid ? "Valid (agent key)" : "INVALID"}</span></div>
            <div><span>Results SHA-256</span><span className="mono">{data.results_sha256?.slice(0, 24) ?? "—"}…</span></div>
          </div>
          {data.issues.length === 0 ? <p>No issues were found in this run.</p> : (
            <div className="table" style={{ maxHeight: 260, overflowY: "auto" }}>
              {data.issues.map((issue) => (
                <div className="tr" key={issue.file_path + issue.outcome} style={{ gridTemplateColumns: "200px 1fr" }}>
                  <div><span className="pill crit">{issue.outcome}</span></div>
                  <div className="mono ellip" title={issue.file_path}>{issue.file_path}</div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </Dialog>
  );
}
