import test from "node:test";
import assert from "node:assert/strict";
import { computeExportHash } from "@/lib/receipt-store";

test("computeExportHash is stable for key ordering", () => {
  const a = computeExportHash({ b: 1, a: 2, nested: { y: 2, x: 1 } });
  const b = computeExportHash({ nested: { x: 1, y: 2 }, a: 2, b: 1 });
  assert.equal(a, b);
});
