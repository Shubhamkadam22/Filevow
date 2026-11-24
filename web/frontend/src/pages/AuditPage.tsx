import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAudit, useVerifyChain } from "../api/queries";
import { useAuth } from "../auth/AuthContext";
import { Icon } from "../components/Icon";
import { humanAction, timeAgo } from "../lib/format";

function describe(details: Record<string, unknown> | null): string {
  if (!details) return "";
  const parts = ["file", "path", "username", "reason", "outcome", "files", "issues"]
    .filter((key) => details[key] !== undefined && details[key] !== null)
    .map((key) => (key === "file" ? String(details[key]).split("/").pop() : `${key === "reason" ? "“" : ""}${details[key]}${key === "reason" ? "”" : ""}`));
  return parts.join(" · ");
}

export function AuditPage() {
  const { can } = useAuth();
  const [group, setGroup] = useState("");
  const [params] = useSearchParams();
  const { data: entries = [], isLoading, error } = useAudit(group);
  const verify = useVerifyChain();

  useEffect(() => {
    if (params.get("verify") === "1" && can("analyst")) verify.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!can("analyst")) {
    return (
      <section className="page on">
        <h1 className="ptitle">Audit log</h1>
        <div className="infobar info"><Icon name="info" /><div className="grow">The audit log is available to analysts and administrators.</div></div>
      </section>
    );
  }

  const report = verify.data;
  return (
    <section className="page on">
      <h1 className="ptitle">Audit log</h1>
      <div className="cmdbar">
        <button className="btn" disabled={verify.isPending} onClick={() => verify.mutate()}>
          {verify.isPending ? <span className="spinner" /> : <Icon name="lock" />}Verify chain
        </button>
        <select className="sel" value={group} onChange={(e) => setGroup(e.target.value)} aria-label="Filter actions">
          <option value="">All actions</option>
          <option value="change">Change decisions</option>
          <option value="auth">Sign-ins and accounts</option>
          <option value="admin">Administration</option>
          <option value="system">Verification runs</option>
        </select>
        <span className="sp" />
        <a className="btn" href="/api/v1/audit/export.csv"><Icon name="download" />Export CSV</a>
      </div>
      {report && (report.intact && report.checkpoint_problems.length === 0 ? (
        <div className="infobar ok"><Icon name="ok" /><div className="grow"><b>Audit chain intact.</b>{report.entries_checked.toLocaleString()} entries checked · every signed checkpoint verifies.</div></div>
      ) : (
        <div className="infobar crit"><Icon name="err" /><div className="grow">
          <b>Audit log tampering detected.</b>
          {report.intact ? report.checkpoint_problems.join(" · ") : `Entry ${report.first_broken_id}: ${report.reason}`}
        </div></div>
      ))}
      {error && <div className="infobar crit"><Icon name="err" /><div className="grow">{error.message}</div></div>}
      <div className="table audit">
        <div className="tr th"><div>Time</div><div>Action</div><div>Details</div><div>By</div><div>Entry hash</div></div>
        {isLoading && <div className="page-loading"><span className="spinner" /></div>}
        {entries.map((entry) => (
          <div className="tr" key={entry.id}>
            <div className="muted" title={new Date(entry.created_at).toLocaleString()}>{timeAgo(entry.created_at)}</div>
            <div>{humanAction(entry.action)}</div>
            <div className="ellip" title={JSON.stringify(entry.details ?? {})}>{describe(entry.details) || entry.ip_address || "—"}</div>
            <div>{entry.actor}</div>
            <div className="mono">{entry.entry_hash.slice(0, 8)}…</div>
          </div>
        ))}
      </div>
    </section>
  );
}
