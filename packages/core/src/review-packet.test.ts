import assert from "node:assert/strict";
import test from "node:test";
import { formatReviewPacket, type ScanRecord } from "./index.js";

test("combines changed-code impact, ownership, priority, and remediation", () => {
  const finding = { id: "f", analyzer: "semgrep", ruleId: "r", category: "security" as const, severity: "high" as const, title: "Unsafe call", message: "x", location: { path: "src/a.ts", startLine: 1, startColumn: 1 }, evidence: [] };
  const record: ScanRecord = { schemaVersion: 1, id: "run", startedAt: "", completedAt: "", rootDir: ".", analyzerId: "combined", findings: [finding] };
  const text = formatReviewPacket(record, { reference: "main", changedFiles: ["src/a.ts"], dependentFiles: [], directlyChangedFindings: [finding], importAffectedFindings: [] }, [{ findingId: "f", path: "src/a.ts", owners: ["@team"] }], [{ findingId: "f", action: "Replace unsafe call.", verification: "Run tests.", rationale: "rule" }], [{ findingId: "f", score: 65, tier: "high", reasons: [] }]);
  assert.match(text, /DIRECT/);
  assert.match(text, /@team/);
  assert.match(text, /Replace unsafe call/);
});
