import assert from "node:assert/strict";
import test from "node:test";
import { evaluateGate, type Finding } from "./index.js";

const finding = (severity: Finding["severity"]): Finding => ({ id: severity, analyzer: "a", ruleId: "r", category: "security", severity, title: "x", message: "x", evidence: [] });

test("fails only findings at or above the configured severity", () => {
  const result = evaluateGate([finding("medium"), finding("high")], "high");
  assert.equal(result.passed, false);
  assert.deepEqual(result.violations.map((item) => item.id), ["high"]);
});
