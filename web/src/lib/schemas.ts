import { z } from "zod";

/** Max lengths to prevent abuse; aligned with verifier expectations. */
const MAX_STRING = 4096;
const MAX_ARRAY = 256;

/** Zod schemas matching verifier/src/schema.rs for runtime validation */

export const agentMetadataSchema = z.object({
  domain: z.string().min(1).max(MAX_STRING),
  version: z.string().min(1).max(MAX_STRING),
});

export const traceEntrySchema = z.object({
  action: z.string().min(1).max(MAX_STRING),
  target: z.string().min(1).max(MAX_STRING),
  amount: z.number().optional(),
  table: z.string().max(MAX_STRING).optional(),
  details: z.record(z.unknown()).optional(),
});

export const publicValuesSchema = z.object({
  max_spend: z.number().positive().optional(),
  restricted_endpoints: z.array(z.string().max(MAX_STRING)).max(MAX_ARRAY).optional(),
});

export const verifyRequestSchema = z.object({
  agent_metadata: agentMetadataSchema,
  policy_commitment: z.string().min(1).max(MAX_STRING),
  execution_trace: z.array(traceEntrySchema).max(MAX_ARRAY),
  public_values: publicValuesSchema,
});

export const potReceiptSchema = z.object({
  policy_commitment: z.string(),
  trace_hash: z.string(),
  timestamp_ns: z.number(),
  signature: z.string(),
  public_key: z.string(),
});

export const verifyResponseSchema = z.object({
  valid: z.boolean(),
  reason: z.string().optional(),
  proof: potReceiptSchema.optional(),
});

export const registerResponseSchema = z.object({
  policy_commitment: z.string(),
});

/** Schema for the policy payload sent to /v1/register */
export const registerPolicySchema = z.object({
  public_values: publicValuesSchema,
});

export type AgentMetadataInput = z.infer<typeof agentMetadataSchema>;
export type TraceEntryInput = z.infer<typeof traceEntrySchema>;
export type PublicValuesInput = z.infer<typeof publicValuesSchema>;
export type VerifyRequestInput = z.infer<typeof verifyRequestSchema>;
export type RegisterPolicyInput = z.infer<typeof registerPolicySchema>;
