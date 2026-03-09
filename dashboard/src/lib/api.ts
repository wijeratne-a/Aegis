import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type { RegisterPolicyInput } from "./schemas";
import type { PotReceipt, RegisterResponse } from "./types";
import type { UserRole } from "./auth";

async function registerPolicy(payload: RegisterPolicyInput): Promise<RegisterResponse> {
  const res = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    credentials: "include",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export function useRegisterPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: registerPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policy"] });
    },
  });
}

type ReceiptListResponse = {
  receipts: Array<{ received_at: string; value: PotReceipt }>;
  total?: number;
  nextOffset?: number;
};

export function useReceipts(options?: {
  parentTaskId?: string | null;
  policyCommitment?: string | null;
  since?: string | null;
  until?: string | null;
  enabled?: boolean;
}) {
  return useQuery({
    queryKey: ["receipts", options?.parentTaskId ?? "all", options?.policyCommitment ?? "", options?.since ?? "", options?.until ?? ""],
    enabled: options?.enabled !== false,
    queryFn: async () => {
      const params = new URLSearchParams();
      if (options?.parentTaskId) params.set("parent_task_id", options.parentTaskId);
      if (options?.policyCommitment) params.set("policy_commitment", options.policyCommitment);
      if (options?.since) params.set("since", options.since);
      if (options?.until) params.set("until", options.until);
      const res = await fetch(`/api/receipts?${params}`, { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `HTTP ${res.status}`);
      }
      const data = (await res.json()) as ReceiptListResponse;
      return data.receipts ?? [];
    },
    refetchInterval: 5000,
  });
}

type SessionResponse = {
  user: { username: string; role: UserRole; org_id: string; auth_source: "demo" | "oidc" } | null;
};

type AgentListResponse = { agents: import("./types").Agent[] };

export function useAgents() {
  return useQuery({
    queryKey: ["agents"],
    queryFn: async () => {
      const res = await fetch("/api/agents", { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `HTTP ${res.status}`);
      }
      const data = (await res.json()) as AgentListResponse;
      return data.agents ?? [];
    },
    refetchInterval: 30000,
  });
}

type AlertListResponse = {
  alerts: Array<{
    id: string;
    incident_id?: string;
    event: string;
    policy_commitment: string;
    domain: string;
    reason: string;
    timestamp_ns: number;
    received_at: string;
    severity: string;
  }>;
  total: number;
  nextOffset?: number;
};

export function useAlerts(options?: { domain?: string }) {
  return useQuery({
    queryKey: ["alerts", options?.domain],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (options?.domain) params.set("domain", options.domain);
      const res = await fetch(`/api/alerts?${params}`, { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `HTTP ${res.status}`);
      }
      return res.json() as Promise<AlertListResponse>;
    },
    refetchInterval: 10000,
  });
}

type PolicyHistoryResponse = {
  history: Array<{
    policy_commitment: string;
    policy_storage_key: string;
    org_id: string;
    created_at: string;
  }>;
  nextOffset?: number;
};

export function usePolicyHistory() {
  return useQuery({
    queryKey: ["policy-history"],
    queryFn: async () => {
      const res = await fetch("/api/policy/history", { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? `HTTP ${res.status}`);
      }
      return res.json() as Promise<PolicyHistoryResponse>;
    },
    refetchInterval: 60000,
  });
}

export function useSession() {
  return useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      const res = await fetch("/api/auth/me", { credentials: "include" });
      if (!res.ok) return null;
      const data = (await res.json()) as SessionResponse;
      return data.user;
    },
    staleTime: 60_000,
  });
}

type IncidentResponse = {
  id: string;
  incident_id: string;
  event: string;
  policy_commitment: string;
  domain: string;
  reason: string;
  timestamp_ns: number;
  received_at: string;
  severity: string;
};

export function useIncident(incidentId: string | null) {
  return useQuery({
    queryKey: ["incident", incidentId],
    queryFn: async () => {
      if (!incidentId) return null;
      const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`, {
        credentials: "include",
      });
      if (!res.ok) {
        if (res.status === 404) return null;
        throw new Error("Failed to load incident");
      }
      return res.json() as Promise<IncidentResponse>;
    },
    enabled: !!incidentId,
  });
}
