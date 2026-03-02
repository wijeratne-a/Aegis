/** TypeScript interfaces mirroring verifier/src/schema.rs */

export interface AgentMetadata {
  domain: string;
  version: string;
}

export interface TraceEntry {
  action: string;
  target: string;
  amount?: number;
  table?: string;
  details?: Record<string, unknown>;
}

export interface PublicValues {
  max_spend?: number;
  restricted_endpoints?: string[];
}

export interface VerifyRequest {
  agent_metadata: AgentMetadata;
  policy_commitment: string;
  execution_trace: TraceEntry[];
  public_values: PublicValues;
}

export interface PotReceipt {
  policy_commitment: string;
  trace_hash: string;
  timestamp_ns: number;
  signature: string;
  public_key: string;
}

export interface VerifyResponse {
  valid: boolean;
  reason?: string;
  proof?: PotReceipt;
}

export interface RegisterResponse {
  policy_commitment: string;
}

/** Policy payload sent to /v1/register - wraps public_values */
export interface RegisterPolicyPayload {
  public_values: PublicValues;
}
