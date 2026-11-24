import { useEffect, useState } from "react";
import { useFsList, usePlaces } from "../api/queries";
import type { FsEntry } from "../api/types";
import { bytes } from "../lib/format";
import { Dialog } from "./Dialog";
import { Icon } from "./Icon";

interface FolderBrowserProps {
  open: boolean;
  onClose: () => void;
  onSelect: (path: string, kind: "folder" | "file") => void;
  allowFiles?: boolean;
}

/** A file dialog for picking what to protect, like the Windows "Browse for folder" window. */
export function FolderBrowser({ open, onClose, onSelect, allowFiles = true }: FolderBrowserProps) {
  const places = usePlaces(open);
  const [path, setPath] = useState<string | null>(null);
  const [picked, setPicked] = useState<FsEntry | null>(null);
  const listing = useFsList(path, open);

  useEffect(() => {
    if (open && path === null && places.data?.[0]) setPath(places.data[0].path); // start on the Desktop
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, places.data]);

  const go = (target: string | null) => {
    setPath(target);
    setPicked(null);
  };

  const entries = (listing.data?.entries ?? []).filter((e) => allowFiles || e.kind !== "file");
  const selection = picked ?? (path ? { name: path, path, kind: "folder" as const, size: null } : null);

  return (
    <Dialog open={open} onClose={onClose} width={760} title="Choose a folder or file to protect"
      footer={
        <>
          <button className="btn primary" disabled={!selection}
            onClick={() => selection && onSelect(selection.path, selection.kind === "file" ? "file" : "folder")}>
            {selection?.kind === "file" ? "Protect this file" : "Protect this folder"}
          </button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </>
      }>
      <div className="browser">
        <aside className="browser-places" aria-label="Places">
          {(places.data ?? []).map((place) => (
            <button key={place.path} className={`place ${path === place.path ? "on" : ""}`} onClick={() => go(place.path)}>
              <Icon name={place.icon} />{place.label}
            </button>
          ))}
          <button className={`place ${path === null ? "on" : ""}`} onClick={() => go(null)}><Icon name="folder" />This PC</button>
        </aside>
        <section className="browser-main">
          <div className="browser-bar">
            <button className="btn icon subtle" aria-label="Up one folder" title="Up one folder"
              disabled={!listing.data?.path} onClick={() => go(listing.data?.parent ?? null)}>
              <Icon name="up" />
            </button>
            <span className="mono ellip" title={path ?? "This PC"}>{path ?? "This PC"}</span>
          </div>
          <div className="browser-list" role="listbox" aria-label="Folder contents">
            {listing.isLoading && <div className="page-loading"><span className="spinner" /></div>}
            {listing.error && <div className="form-error" style={{ padding: 12 }}>{listing.error.message}</div>}
            {!listing.isLoading && !listing.error && entries.length === 0 && (
              <div className="empty" style={{ padding: 24 }}>This folder is empty.</div>
            )}
            {entries.map((entry) => (
              <div key={entry.path} role="option" aria-selected={picked?.path === entry.path}
                className={`browser-row ${picked?.path === entry.path ? "sel" : ""}`}
                onClick={() => (entry.kind === "file" ? setPicked(entry) : go(entry.path))}
                onDoubleClick={() => entry.kind === "file" && onSelect(entry.path, "file")}>
                <Icon name={entry.kind === "file" ? "file" : "folder"} />
                <span className="ellip">{entry.name}</span>
                <span className="subtle">{entry.kind === "file" ? bytes(entry.size) : entry.kind === "drive" ? "Drive" : ""}</span>
              </div>
            ))}
            {listing.data?.truncated && <div className="subtle" style={{ padding: 8 }}>Showing the first 500 items.</div>}
          </div>
          <p className="subtle" style={{ margin: "8px 0 0" }}>
            Click a folder to open it, or a file to select it. “Protect this folder” protects everything inside the folder
            you are looking at.
          </p>
        </section>
      </div>
    </Dialog>
  );
}
