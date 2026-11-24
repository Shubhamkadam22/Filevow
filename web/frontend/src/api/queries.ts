// TanStack Query hooks: every server read the UI needs, with shared cache keys.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type {
  Alert,
  AuditEntry,
  ChainReport,
  Change,
  ChangeDetail,
  Channel,
  Dashboard,
  Decision,
  FileDetail,
  MonitoredPath,
  ProtectedFile,
  RunDetail,
  RunSummary,
  SigningKey,
  StepUp,
  FsListing,
  FsPlace,
  SystemInfo,
  User,
  Workspace,
} from "./types";

export const keys = {
  dashboard: ["dashboard"] as const,
  changes: (state: string) => ["changes", state] as const,
  change: (id: number) => ["change", id] as const,
  paths: ["paths"] as const,
  files: (q: string, state: string) => ["files", q, state] as const,
  file: (id: number) => ["file", id] as const,
  runs: ["runs"] as const,
  run: (id: number) => ["run", id] as const,
  alerts: ["alerts"] as const,
  audit: (group: string) => ["audit", group] as const,
  users: ["users"] as const,
  keys: ["keys"] as const,
  channels: ["channels"] as const,
  system: ["system"] as const,
  workspace: ["workspace"] as const,
  fs: (path: string | null) => ["fs", path] as const,
  places: ["places"] as const,
};

export const useDashboard = () => useQuery({ queryKey: keys.dashboard, queryFn: () => api.get<Dashboard>("/dashboard") });
export const useChanges = (state = "open") =>
  useQuery({ queryKey: keys.changes(state), queryFn: () => api.get<Change[]>(`/changes?state=${state}`) });
export const useChange = (id: number | null) =>
  useQuery({ queryKey: keys.change(id ?? 0), queryFn: () => api.get<ChangeDetail>(`/changes/${id}`), enabled: id !== null });
export const usePaths = () => useQuery({ queryKey: keys.paths, queryFn: () => api.get<MonitoredPath[]>("/paths") });
export const useFiles = (q: string, state: string) =>
  useQuery({
    queryKey: keys.files(q, state),
    queryFn: () => api.get<ProtectedFile[]>(`/files?${new URLSearchParams({ ...(q ? { q } : {}), ...(state ? { state } : {}) })}`),
  });
export const useFile = (id: number | null) =>
  useQuery({ queryKey: keys.file(id ?? 0), queryFn: () => api.get<FileDetail>(`/files/${id}`), enabled: id !== null });
export const useRuns = () => useQuery({ queryKey: keys.runs, queryFn: () => api.get<RunSummary[]>("/runs?limit=48") });
export const useRun = (id: number | null) =>
  useQuery({ queryKey: keys.run(id ?? 0), queryFn: () => api.get<RunDetail>(`/runs/${id}`), enabled: id !== null });
export const useAlerts = () => useQuery({ queryKey: keys.alerts, queryFn: () => api.get<Alert[]>("/alerts?state=all&limit=50") });
export const useAudit = (group: string) =>
  useQuery({ queryKey: keys.audit(group), queryFn: () => api.get<AuditEntry[]>(`/audit?limit=200${group ? `&group=${group}` : ""}`) });
export const useUsers = (enabled: boolean) => useQuery({ queryKey: keys.users, queryFn: () => api.get<User[]>("/users"), enabled });
export const useKeys = () => useQuery({ queryKey: keys.keys, queryFn: () => api.get<SigningKey[]>("/keys") });
export const useChannels = (enabled: boolean) =>
  useQuery({ queryKey: keys.channels, queryFn: () => api.get<Channel[]>("/channels"), enabled });
export const useSystem = () => useQuery({ queryKey: keys.system, queryFn: () => api.get<SystemInfo>("/system") });

export const useWorkspace = () => useQuery({ queryKey: keys.workspace, queryFn: () => api.get<Workspace>("/workspace") });
export const useFsList = (path: string | null, enabled: boolean) =>
  useQuery({
    queryKey: keys.fs(path),
    queryFn: () => api.get<FsListing>(`/fs/list${path ? `?path=${encodeURIComponent(path)}` : ""}`),
    enabled,
  });
export const usePlaces = (enabled: boolean) =>
  useQuery({ queryKey: keys.places, queryFn: () => api.get<FsPlace[]>("/fs/places"), enabled, staleTime: 60_000 });

export function useVerifyChain() {
  return useMutation({ mutationFn: () => api.get<ChainReport>("/audit/verify") });
}

export function useStartRun() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<{ status: string }>("/runs"),
    onSuccess: () => setTimeout(() => client.invalidateQueries(), 1500),
  });
}

export type DecisionKind = "accept" | "restore" | "quarantine" | "reject" | "escalate";

export interface DecisionInput {
  kind: DecisionKind;
  ids: number[];
  reason: string;
  proof?: StepUp;
  keyPassphrase?: string;
  expectedSha256?: string | null;
}

export function useDecision() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: async ({ kind, ids, reason, proof, keyPassphrase, expectedSha256 }: DecisionInput) => {
      if (ids.length > 1) {
        const result = await api.post<{ results: Decision[]; skipped: Record<string, string> }>("/changes/bulk", {
          ...proof,
          action: kind,
          ids,
          reason,
          key_passphrase: keyPassphrase,
        });
        return { decisions: result.results, skipped: result.skipped };
      }
      const [id] = ids;
      const body =
        kind === "reject" || kind === "escalate"
          ? { reason }
          : { ...proof, reason, ...(kind === "accept" ? { key_passphrase: keyPassphrase, expected_sha256: expectedSha256 ?? undefined } : {}) };
      const decision = await api.post<Decision>(`/changes/${id}/${kind}`, body);
      return { decisions: [decision], skipped: {} as Record<string, string> };
    },
    onSuccess: () => client.invalidateQueries(),
  });
}
