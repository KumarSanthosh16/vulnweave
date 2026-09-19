import assert from "node:assert/strict";
import test from "node:test";
import { applySuppressions, type Finding } from "./index.js";

const finding: Finding = { id: "f", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "high", title: "Fixture", message: "Fixture", fingerprint: "stable-fingerprint", evidence: [] };

test("keeps an active suppression visible while excluding it from gate candidates", () => {
  const result = applySuppressions([finding], [{ fingerprint: "stable-fingerprint", reason: "Tracked exception", owner: "security@example.test", expiresOn: "2026-12-31" }], new Date("2026-09-19T00:00:00Z"));
  assert.equal(result.activeFindings.length, 0);
  assert.equal(result.suppressed[0]?.findingId, "f");
});

test("expires suppressions automatically", () => {
  const result = applySuppressions([finding], [{ fingerprint: "stable-fingerprint", reason: "Old exception", owner: "security@example.test", expiresOn: "2026-01-01" }], new Date("2026-09-19T00:00:00Z"));
  assert.equal(result.activeFindings.length, 1);
  assert.equal(result.expired.length, 1);
});
