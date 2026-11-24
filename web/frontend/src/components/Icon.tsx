// One SVG sprite for the whole app; <Icon name="home" /> references a symbol in it.

const PATHS: Record<string, string> = {
  home: "M3.5 9 10 3.5 16.5 9v7a.5.5 0 0 1-.5.5h-3.5v-5h-5v5H4a.5.5 0 0 1-.5-.5Z",
  review: "M7.5 3.5h5v2h-5zM6.5 4.5H5.5a1 1 0 0 0-1 1V16a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1V5.5a1 1 0 0 0-1-1h-1M7.5 11.2l1.8 1.8 3.4-3.8",
  file: "M5.5 2.5h6l3.5 3.5v10.5a1 1 0 0 1-1 1H5.5a1 1 0 0 1-1-1v-13a1 1 0 0 1 1-1ZM11.5 2.5V6H15",
  folder: "M2.5 5.5a1 1 0 0 1 1-1h4l1.5 1.5h7.5a1 1 0 0 1 1 1V15a1 1 0 0 1-1 1h-13a1 1 0 0 1-1-1Z",
  verify: "M16 10a6 6 0 1 1-1.76-4.24M16 3.8v3.4h-3.4",
  audit: "M6 3.5h8.5a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H6A1.5 1.5 0 0 1 4.5 15V5A1.5 1.5 0 0 1 6 3.5ZM7.5 7.5h5M7.5 10.5h5M7.5 13.5h3",
  settings: "M10 7.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5ZM10 2.5v2M10 15.5v2M2.5 10h2M15.5 10h2M4.7 4.7l1.4 1.4M13.9 13.9l1.4 1.4M4.7 15.3l1.4-1.4M13.9 6.1l1.4-1.4",
  search: "M8.8 3.5a5.3 5.3 0 1 1 0 10.6 5.3 5.3 0 0 1 0-10.6ZM12.7 12.7l4 4",
  chev: "m8 5 5 5-5 5",
  eye: "M1.8 10S4.7 4.5 10 4.5 18.2 10 18.2 10 15.3 15.5 10 15.5 1.8 10 1.8 10ZM10 7.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5Z",
  "eye-off": "M1.8 10S4.7 4.5 10 4.5c1.4 0 2.6.4 3.7.9M18.2 10s-1 1.9-2.9 3.4M7.7 15.1c.7.3 1.5.4 2.3.4 5.3 0 8.2-5.5 8.2-5.5M8.3 11.7a2.5 2.5 0 0 1 3.4-3.4M3 17 17 3",
  back: "M16 10H4.5M9 5l-5 5 5 5",
  up: "m5 12.5 5-5 5 5",
  down: "m5 7.5 5 5 5-5",
  ok: "M10 3a7 7 0 1 1 0 14 7 7 0 0 1 0-14ZM7 10.2l2 2 4-4.4",
  warn: "M8.7 3.8a1.5 1.5 0 0 1 2.6 0l5.6 10a1.5 1.5 0 0 1-1.3 2.2H4.4a1.5 1.5 0 0 1-1.3-2.2ZM10 8v3.5M10 13.9v.1",
  err: "M10 3a7 7 0 1 1 0 14 7 7 0 0 1 0-14ZM7.6 7.6l4.8 4.8M12.4 7.6l-4.8 4.8",
  info: "M10 3a7 7 0 1 1 0 14 7 7 0 0 1 0-14ZM10 9v4.5M10 6.6v.1",
  minus: "M10 3a7 7 0 1 1 0 14 7 7 0 0 1 0-14ZM7 10h6",
  hash: "M7.5 3.5 6 16.5M14 3.5l-1.5 13M4 7.5h12.5M3.5 12.5H16",
  key: "M6.5 7a3 3 0 1 1 0 6 3 3 0 0 1 0-6ZM9.5 10h7.5M14.5 10v2.5M17 10v2",
  copy: "M8.5 7h6.5a1.5 1.5 0 0 1 1.5 1.5V15a1.5 1.5 0 0 1-1.5 1.5H8.5A1.5 1.5 0 0 1 7 15V8.5A1.5 1.5 0 0 1 8.5 7ZM13 7V4.5a1 1 0 0 0-1-1H4.5a1 1 0 0 0-1 1V12a1 1 0 0 0 1 1H7",
  bell: "M5.5 13.5V9a4.5 4.5 0 0 1 9 0v4.5l1.5 1.5H4ZM8.5 17h3",
  lock: "M6 8.5h8a1.5 1.5 0 0 1 1.5 1.5v5a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 15v-5A1.5 1.5 0 0 1 6 8.5ZM7 8.5V6.5a3 3 0 0 1 6 0v2",
  plus: "M10 4v12M4 10h12",
  undo: "M7 5.5 4 8.5l3 3M4 8.5h8a4 4 0 0 1 0 8h-2",
  check: "m4.5 10.5 3.5 3.5 7.5-8",
  flag: "M5 17V3.5M5 4h9l-2 3.5 2 3.5H5",
  escalate: "M10 16V4M5 9l5-5 5 5",
  trash: "M4 6h12M8 6V4.5h4V6M6 6l.7 10h6.6L14 6",
  palette: "M10 3a7 7 0 1 0 0 14c1 0 1.5-.6 1.5-1.4 0-1.2-1-1.6-1-2.6 0-.8.7-1.5 1.5-1.5h1.5A3.5 3.5 0 0 0 17 8c0-2.8-3.1-5-7-5Z",
  density: "M3.5 5h13M3.5 10h13M3.5 15h13",
  keyboard: "M4 5h12a1.5 1.5 0 0 1 1.5 1.5v7A1.5 1.5 0 0 1 16 15H4a1.5 1.5 0 0 1-1.5-1.5v-7A1.5 1.5 0 0 1 4 5ZM5.5 8h1M8.5 8h1M11.5 8h1M6.5 12h7",
  download: "M10 3.5v9M6 9l4 4 4-4M4 16.5h12",
  clock: "M10 3a7 7 0 1 1 0 14 7 7 0 0 1 0-14ZM10 6v4l2.5 2",
  heart: "M2.5 10h3l2-4 3 8 2-4h5",
  user: "M10 3.5a3 3 0 1 1 0 6 3 3 0 0 1 0-6ZM4 17c.8-3 3.2-4.5 6-4.5s5.2 1.5 6 4.5",
  logout: "M8 4.5H5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h3M12 13.5 15.5 10 12 6.5M15.5 10H8",
  x: "m5.5 5.5 9 9M14.5 5.5l-9 9",
  min: "M0 5h10",
  max: "M2 .5h6A1.5 1.5 0 0 1 9.5 2v6A1.5 1.5 0 0 1 8 9.5H2A1.5 1.5 0 0 1 .5 8V2A1.5 1.5 0 0 1 2 .5Z",
  close: "m0 0 10 10M10 0 0 10",
};

const SMALL = new Set(["min", "max", "close"]);

export function IconSprite() {
  return (
    <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden="true">
      {Object.entries(PATHS).map(([name, d]) => (
        <symbol key={name} id={`i-${name}`} viewBox={SMALL.has(name) ? "0 0 10 10" : "0 0 20 20"}>
          <path d={d} />
        </symbol>
      ))}
    </svg>
  );
}

export function Icon({ name, className = "", title }: { name: string; className?: string; title?: string }) {
  return (
    <svg className={`i ${className}`.trim()} aria-hidden={title ? undefined : true} role={title ? "img" : undefined}>
      {title ? <title>{title}</title> : null}
      <use href={`#i-${name}`} />
    </svg>
  );
}

const SEVERITY_ICON: Record<string, string> = { critical: "err", high: "warn", medium: "info", low: "info" };
const SEVERITY_CLASS: Record<string, string> = { critical: "crit", high: "high", medium: "med", low: "med" };

export function SeverityIcon({ severity }: { severity: string }) {
  return <Icon name={SEVERITY_ICON[severity] ?? "info"} className={`sev ${SEVERITY_CLASS[severity] ?? "med"}`} />;
}
