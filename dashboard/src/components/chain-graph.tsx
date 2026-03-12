"use client";

import { useMemo } from "react";
import { sanitizeForDisplay } from "@/lib/sanitize";
import type { PotReceipt } from "@/lib/types";

type ReceiptEntry = { received_at: string; value: PotReceipt };

const NODE_WIDTH = 140;
const NODE_HEIGHT = 48;
const HORIZONTAL_GAP = 24;
const VERTICAL_GAP = 40;

function truncateId(id: string, len = 8): string {
  if (id.length <= len) return id;
  return `${id.slice(0, len)}…`;
}

function buildGraph(receipts: ReceiptEntry[]): {
  nodes: Array<{ id: string; receipt: PotReceipt; x: number; y: number }>;
  edges: Array<{ from: string; to: string }>;
} {
  const idToReceipt = new Map<string, PotReceipt>();
  for (const { value } of receipts) {
    idToReceipt.set(value.receipt_id, value);
  }

  const edges: Array<{ from: string; to: string }> = [];
  for (const { value } of receipts) {
    const parents = value.parent_task_ids ?? [];
    for (const pid of parents) {
      edges.push({ from: pid, to: value.receipt_id });
    }
  }

  // Level-order layout: roots first, then children
  const levels: string[][] = [];
  const visited = new Set<string>();
  const inDegree = new Map<string, number>();

  for (const id of idToReceipt.keys()) {
    inDegree.set(id, 0);
  }
  for (const { from, to } of edges) {
    inDegree.set(to, (inDegree.get(to) ?? 0) + 1);
  }

  const roots = [...idToReceipt.keys()].filter((id) => (inDegree.get(id) ?? 0) === 0);
  if (roots.length === 0 && idToReceipt.size > 0) {
    roots.push([...idToReceipt.keys()][0]);
  }

  const queue = [...roots];
  while (queue.length > 0) {
    const level: string[] = [];
    const levelSize = queue.length;
    for (let i = 0; i < levelSize; i++) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      level.push(id);
      for (const { from, to } of edges) {
        if (from === id && !visited.has(to)) {
          queue.push(to);
        }
      }
    }
    if (level.length > 0) levels.push(level);
  }

  const orphans = [...idToReceipt.keys()].filter((id) => !visited.has(id));
  if (orphans.length > 0) levels.push(orphans);

  const nodes: Array<{ id: string; receipt: PotReceipt; x: number; y: number }> = [];
  const baseWidth = 400;
  for (let row = 0; row < levels.length; row++) {
    const level = levels[row];
    const totalWidth = level.length * NODE_WIDTH + Math.max(0, level.length - 1) * HORIZONTAL_GAP;
    const startX = (baseWidth - totalWidth) / 2 + NODE_WIDTH / 2 + HORIZONTAL_GAP / 2;
    for (let col = 0; col < level.length; col++) {
      const id = level[col];
      const receipt = idToReceipt.get(id);
      if (!receipt) continue;
      nodes.push({
        id,
        receipt,
        x: startX + col * (NODE_WIDTH + HORIZONTAL_GAP),
        y: 24 + row * (NODE_HEIGHT + VERTICAL_GAP),
      });
    }
  }

  return { nodes, edges };
}

export function ChainGraph({
  receipts,
  className,
}: {
  receipts: ReceiptEntry[];
  className?: string;
}) {
  const { nodes, edges } = useMemo(() => buildGraph(receipts), [receipts]);

  const idToNode = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    for (const n of nodes) m.set(n.id, { x: n.x, y: n.y });
    return m;
  }, [nodes]);

  const width = useMemo(() => {
    let w = 0;
    for (const n of nodes) {
      w = Math.max(w, n.x + NODE_WIDTH / 2 + 20);
    }
    return Math.max(400, w);
  }, [nodes]);

  const height = useMemo(() => {
    if (nodes.length === 0) return 120;
    let maxY = 0;
    for (const n of nodes) maxY = Math.max(maxY, n.y);
    return maxY + NODE_HEIGHT + 24;
  }, [nodes]);

  if (nodes.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No receipts to display in lineage graph.</p>
    );
  }

  return (
    <div className={className}>
      <p className="mb-2 text-xs text-muted-foreground">
        Lineage is best-effort; parent_task_id is not cryptographically validated.
      </p>
      <div className="overflow-x-auto rounded-lg border border-border/50 bg-muted/10 p-4">
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          className="mx-auto"
        >
          <defs>
            <marker
              id="arrowhead"
              markerWidth="10"
              markerHeight="7"
              refX="9"
              refY="3.5"
              orient="auto"
            >
              <polygon points="0 0, 10 3.5, 0 7" fill="currentColor" className="text-muted-foreground" />
            </marker>
          </defs>
          {edges.map(({ from: fromId, to: toId }) => {
            const fromNode = idToNode.get(fromId);
            const toNode = idToNode.get(toId);
            if (!fromNode || !toNode) return null;
            const dx = toNode.x - fromNode.x;
            const dy = toNode.y - fromNode.y;
            const len = Math.hypot(dx, dy) || 1;
            const ux = dx / len;
            const uy = dy / len;
            const pad = 4;
            const x1 = fromNode.x + ux * (NODE_WIDTH / 2 + pad);
            const y1 = fromNode.y + uy * (NODE_HEIGHT / 2 + pad);
            const x2 = toNode.x - ux * (NODE_WIDTH / 2 + pad);
            const y2 = toNode.y - uy * (NODE_HEIGHT / 2 + pad);
            const midX = (x1 + x2) / 2;
            const midY = (y1 + y2) / 2;
            const path = `M ${x1} ${y1} Q ${midX + uy * 20} ${midY - ux * 20} ${x2} ${y2}`;
            return (
              <path
                key={`${fromId}-${toId}`}
                d={path}
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                className="text-muted-foreground/60"
                markerEnd="url(#arrowhead)"
              />
            );
          })}
          {nodes.map(({ id, receipt, x, y }) => (
            <g key={id} transform={`translate(${x}, ${y})`}>
              <rect
                width={NODE_WIDTH}
                height={NODE_HEIGHT}
                x={-NODE_WIDTH / 2}
                y={-NODE_HEIGHT / 2}
                rx="6"
                className="fill-background stroke-border stroke"
              />
              <title>{`${receipt.receipt_id}${receipt.trace_hash ? `\ntrace_hash: ${receipt.trace_hash.slice(0, 16)}…` : ""}`}</title>
              <text
                x="0"
                y="-4"
                textAnchor="middle"
                className="fill-foreground text-xs font-mono"
              >
                {sanitizeForDisplay(truncateId(receipt.receipt_id, 12))}
              </text>
              {receipt.trace_hash && (
                <text
                  x="0"
                  y="8"
                  textAnchor="middle"
                  className="fill-muted-foreground text-[10px] font-mono"
                >
                  {sanitizeForDisplay(truncateId(receipt.trace_hash, 10))}
                </text>
              )}
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
