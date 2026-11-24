export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const seconds = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds} s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

export const clockTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—";

export const fullDate = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");

export const shortHash = (sha: string | null | undefined) => (sha ? `${sha.slice(0, 8)}…${sha.slice(-4)}` : "—");

export function bytes(size: number | null | undefined): string {
  if (size === null || size === undefined) return "—";
  if (size < 1024) return `${size.toLocaleString()} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

export function countdown(targetIso: string | null | undefined, now = Date.now()): string {
  if (!targetIso) return "—";
  const left = Math.max(0, new Date(targetIso).getTime() - now);
  const minutes = Math.floor(left / 60000);
  const seconds = Math.floor(left / 1000) % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

export const severityLabel: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
export const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
export const severityClass: Record<string, string> = { critical: "crit", high: "high", medium: "med", low: "med" };

export function humanAction(action: string): string {
  return action.charAt(0) + action.slice(1).toLowerCase().replaceAll("_", " ");
}
