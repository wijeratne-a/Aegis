# Catenar Trust Model

## Trace WAL and Checkpoint Integrity

The proxy writes a BLAKE3 hash chain to the trace WAL (`proxy-trace.jsonl`). A checkpoint file (`{wal}.chain_checkpoint`) stores the last chain hash for fast startup.

**Trust requirement:** The WAL directory and checkpoint file must be **integrity-protected**. A local attacker with write access to these files can append a forged entry with a valid chain hash (the algorithm is deterministic and documented). The verifier will accept such entries as part of the chain.

If the trace WAL cannot be written (e.g. disk full), the proxy continues but the affected request is not in the verifiable audit trail.

**Mitigations:**
- Restrict filesystem permissions (e.g. WAL directory not world-writable; checkpoint mode 0600).
- Run the proxy in a container or sandbox that limits write access to the WAL path.
- For high-assurance deployments, consider checkpoint signing or append-only storage.

## Swarm Lineage and parent_task_id

When Agent A calls Agent B, trace entries can include `parent_task_id` to represent the parent agent's receipt ID. The dashboard Receipts page supports lineage filtering via `GET /api/receipts?parent_task_id=X`.

**Trust level:** `parent_task_id` and trace context from agents are **best-effort** and are not cryptographically bound to prior receipts. A malicious or compromised agent can forge `parent_task_id` values and inject false lineage into the dashboard. The verifier does not validate that a claimed parent receipt exists or was issued to the claimed caller. Dashboard lineage views and receipt `parent_task_ids` should be treated as advisory unless your deployment adds verifier-side validation of parent receipts.

For **high-assurance deployments**, bind parent-child relationships in signed receipts (e.g. parent receipt ID signed by the verifier and included in the child's proof) or use verifier-issued tokens for lineage attestation.

## Verifier API Authentication

**Production requirement:** Set `VERIFIER_API_KEY` for all production deployments. The verifier's protected routes (`/v1/register`, `/v1/verify`, `/v1/agent/register`, `/v1/agents`) use this key via Bearer token or `x-api-key` header. When `VERIFIER_API_KEY` is not set, the verifier API is unauthenticated.

**Strict mode:** Set `VERIFIER_REQUIRE_API_KEY=1` (or `true`) to refuse startup when `VERIFIER_API_KEY` is unset. Use this for production deployments where the verifier must never run unauthenticated.

| Env var | Purpose |
|---------|---------|
| `VERIFIER_API_KEY` | Shared secret for API authentication (Bearer or x-api-key) |
| `VERIFIER_REQUIRE_API_KEY` | When `1` or `true`, startup fails if `VERIFIER_API_KEY` is not set |

## Proxy Policy API

**Optional:** Set `PROXY_POLICY_API_KEY` on the proxy to require authentication for policy management (`GET`/`POST /policy`, `POST /policy/reload`). When set, callers must send `X-Catenar-Policy-Key` or `Authorization: Bearer <key>` with the same value. The dashboard sends this header when `PROXY_POLICY_API_KEY` is configured, so both proxy and dashboard must use the same value.
