import assert from "node:assert/strict";
import test from "node:test";
import { assertValidFinding, type Finding } from "./schemas.js";

test("validates a normalized finding", () => {
  const finding: Finding = { id: "a:1", analyzer: "a", ruleId: "1", category: "security", severity: "high", title: "Issue", message: "Details", evidence: [] };
  assert.equal(assertValidFinding(finding), finding);
});

test("rejects invalid severities", () => {
  const invalid = { id: "a", analyzer: "a", ruleId: "x", category: "security", severity: "urgent", title: "x", message: "x", evidence: [] } as unknown as Finding;
  assert.throws(() => assertValidFinding(invalid), /Unknown severity/);
});
