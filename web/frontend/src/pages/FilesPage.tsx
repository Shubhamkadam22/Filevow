import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useFile, useFiles } from "../api/queries";
import { CopyButton } from "../components/CopyButton";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { bytes, fullDate, shortHash, timeAgo } from "../lib/format";

export function FilesPage() {
  const [query, setQuery] = useState("");
  const [state, setState] = useState("");
  const [openId, setOpenId] = useState<number | null>(null);
  const { data: files = [], isLoading } = useFiles(query, state);
  const navigate = useNavigate();

  return (
    <section className="page on">
      <h1 className="ptitle">Protected files</h1>
      <div className="cmdbar">
        <div className="infield" style={{ width: 340 }}>
          <Icon name="search" />
          <input className="txtin" placeholder="Filter files" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Filter files" />
        </div>
        <select className="sel" value={state} onChange={(e) => setState(e.target.value)} aria-label="Status">
          <option value="">All statuses</option>
          <option value="ok">Verified</option>
          <option value="review">Needs review</option>
          <option value="deleted">Deleted (accepted)</option>
        </select>
        <span className="sp" />
        <span className="subtle">{files.length} shown</span>
      </div>
      <div className="table files">
        <div className="tr th"><div>File</div><div>Status</div><div>SHA-256</div><div>Verified</div><div /></div>
        {isLoading && <div className="page-loading"><span className="spinner" /></div>}
        {!isLoading && files.length === 0 && <div className="empty" style={{ padding: 28 }}>No files match.</div>}
        {files.map((file) => (
          <div key={file.id} className="tr click" onClick={() => setOpenId(file.id)}>
            <div className="mono ellip" title={file.file_path}>{file.file_path}</div>
            <div>
              {file.status === "active" && <span className="pill ok"><Icon name="check" />Verified</span>}
              {file.status === "pending_review" && (
                <button className="pill high" style={{ border: 0, cursor: "pointer" }}
                  onClick={(e) => { e.stopPropagation(); if (file.open_change_id) navigate(`/review/${file.open_change_id}`); }}>
                  <Icon name="warn" />Needs review
                </button>
              )}
              {file.status === "deleted" && <span className="pill med">Deleted</span>}
            </div>
            <div className="mono">{shortHash(file.sha256)}</div>
            <div className="muted">{timeAgo(file.last_verified_at)}</div>
            <div><CopyButton text={file.file_path} label="Copy path" /></div>
          </div>
        ))}
      </div>
      <FileDialog id={openId} onClose={() => setOpenId(null)} />
    </section>
  );
}

function FileDialog({ id, onClose }: { id: number | null; onClose: () => void }) {
  const { data } = useFile(id);
  return (
    <Dialog open={id !== null} onClose={onClose} width={720} title={data?.name ?? "File"}
      footer={<button className="btn" onClick={onClose} style={{ gridColumn: "1 / -1" }}>Close</button>}>
      {!data ? <div className="page-loading"><span className="spinner" /></div> : (
        <>
          <div className="summary">
            <div><span>Path</span><span className="mono">{data.file_path}</span></div>
            <div><span>SHA-256</span><span className="mono">{shortHash(data.sha256)} <CopyButton text={data.sha256} label="Copy hash" /></span></div>
            <div><span>Size · permissions · owner</span><span>{bytes(data.file_size)} · {data.permissions ?? "—"} · {data.owner ?? "—"}</span></div>
            <div><span>Signed</span><span>{fullDate(data.signed_at)} · key {data.key_id}</span></div>
            <div><span>Mirror copy</span><span>{data.mirrored ? "Encrypted copy in the vault" : "Not mirrored"}</span></div>
          </div>
          <h2 className="sec" style={{ marginTop: 0 }}>Version history</h2>
          <div className="table versions">
            <div className="tr th"><div>Version</div><div>Approved</div><div>By</div><div>Reason</div><div>SHA-256</div></div>
            {data.versions.map((v) => (
              <div className="tr" key={v.version}>
                <div className="mono">v{v.version}</div>
                <div className="muted">{fullDate(v.created_at)}</div>
                <div>{v.approved_by ?? "System"}</div>
                <div className="ellip" title={v.approval_reason ?? ""}>{v.approval_reason ?? "—"}</div>
                <div className="mono">{shortHash(v.sha256)}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </Dialog>
  );
}
