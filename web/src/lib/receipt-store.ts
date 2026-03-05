import { createHash } from "crypto";

export type StoredReceipt = {
  received_at: string;
  org_id: string;
  value: unknown;
};

const receipts: StoredReceipt[] = [];
const MAX_RECEIPTS = 1000;

export function pushReceipt(orgId: string, value: unknown): void {
  receipts.unshift({
    received_at: new Date().toISOString(),
    org_id: orgId,
    value,
  });
  if (receipts.length > MAX_RECEIPTS) {
    receipts.length = MAX_RECEIPTS;
  }
}

export function listReceiptsByOrg(orgId: string): StoredReceipt[] {
  return receipts.filter((r) => r.org_id === orgId);
}

function normalizeForHash(payload: unknown): string {
  if (Array.isArray(payload)) {
    return `[${payload.map((v) => normalizeForHash(v)).join(",")}]`;
  }
  if (payload && typeof payload === "object") {
    const entries = Object.entries(payload as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${normalizeForHash(v)}`).join(",")}}`;
  }
  return JSON.stringify(payload);
}

export function computeExportHash(payload: unknown): string {
  const normalized = normalizeForHash(payload);
  return createHash("sha256").update(normalized).digest("hex");
}
