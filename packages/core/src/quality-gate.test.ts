import assert from "node:assert/strict";
import test from "node:test";
import { evaluateQualityGate } from "./quality-gate.js";

test("keeps quality advisory until an explicit threshold is configured", () => {
  const signals = [{ kind: "high-complexity" as const, path: "src/a.ts", line: 1, title: "a", detail: "", score: 10 }];
  assert.equal(evaluateQualityGate(signals).configured, false);
  assert.equal(evaluateQualityGate(signals, { maxComplexitySignals: 0 }).passed, false);
  assert.equal(evaluateQualityGate(signals, { maxComplexitySignals: 1 }).passed, true);
});
