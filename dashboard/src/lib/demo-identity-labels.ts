/** Demo-only mapping from agent_id to human-readable labels for auditor display. */

export interface DemoAgentLabel {
  displayName: string;
  role: string;
  tierOrTeam: string;
}

const DEMO_AGENT_LABELS: Record<string, DemoAgentLabel> = {
  "agent-alice-demo": {
    displayName: "Alice",
    role: "Customer Support",
    tierOrTeam: "Tier 2 | Revenue Ops",
  },
};

export function getHumanContext(agentId: string | null | undefined): DemoAgentLabel | null {
  if (!agentId || typeof agentId !== "string") return null;
  return DEMO_AGENT_LABELS[agentId] ?? null;
}

/** Fallback: format raw agent_id for display (e.g. "agent-alice-demo" -> "Agent Alice Demo") */
export function formatAgentIdFallback(agentId: string): string {
  return agentId.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
