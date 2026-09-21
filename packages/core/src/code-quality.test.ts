import assert from "node:assert/strict";
import test from "node:test";
import { correlateQualitySignals } from "./code-quality.js";

test("correlates block and function clone evidence for the same locations", () => {
  const signals = correlateQualitySignals([
    { kind: "duplicate-code", path: "a.ts", line: 1, title: "block", detail: "", score: 2, relatedLocations: [{ path: "b.ts", line: 2 }] },
    { kind: "duplicate-function", path: "b.ts", line: 2, title: "function", detail: "", score: 2, relatedLocations: [{ path: "a.ts", line: 1 }] }
  ]);
  assert.equal(signals.length, 1);
  assert.deepEqual(signals[0]?.evidenceKinds, ["duplicate-code", "duplicate-function"]);
});
