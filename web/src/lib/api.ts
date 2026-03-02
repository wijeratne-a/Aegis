import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import type { RegisterPolicyInput, VerifyRequestInput } from "./schemas";
import type { RegisterResponse, VerifyResponse } from "./types";

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

async function verifyTrace(payload: VerifyRequestInput): Promise<VerifyResponse> {
  const res = await fetch("/api/verify", {
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

export function useVerifyTrace() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: verifyTrace,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["verifications"] });
    },
  });
}

/** Placeholder for "live feed" - in a real app this would poll or use WebSockets */
export function useVerifications() {
  return useQuery({
    queryKey: ["verifications"],
    queryFn: async () => [] as VerifyResponse[],
    refetchInterval: 5000,
  });
}
