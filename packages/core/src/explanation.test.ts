import assert from "node:assert/strict";
import test from "node:test";
import { formatFindingExplanation, type Finding } from "./index.js";

test("explains a finding from concrete scanner evidence", () => {
  const finding: Finding = { id: "f", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "high", title: "Unsafe call", message: "Avoid this call", location: { path: "src/a.ts", startLine: 3, startColumn: 2 }, evidence: [{ id: "e", kind: "source", summary: "Matched local rule" }] };
  const text = formatFindingExplanation(finding, { findingId: "f", score: 65, tier: "high", reasons: ["high scanner severity"] });
  assert.match(text, /Matched local rule/);
  assert.match(text, /HIGH \(65\)/);
});
