import assert from "node:assert/strict";
import test from "node:test";
import { assignFindingOwners, ownersForPath, parseCodeOwners, type Finding } from "./index.js";

test("uses the last matching CODEOWNERS rule for local finding routing", () => {
  const rules = parseCodeOwners("* @platform\n/packages/ @backend\n/packages/core/** @core-team\n");
  assert.deepEqual(ownersForPath("packages/core/src/index.ts", rules), ["@core-team"]);
  assert.deepEqual(ownersForPath("README.md", rules), ["@platform"]);
  const findings: Finding[] = [{ id: "f", analyzer: "semgrep", ruleId: "r", category: "security", severity: "high", title: "issue", message: "x", location: { path: "packages/core/src/index.ts", startLine: 1, startColumn: 1 }, evidence: [] }];
  assert.deepEqual(assignFindingOwners(findings, rules), [{ findingId: "f", path: "packages/core/src/index.ts", owners: ["@core-team"] }]);
});
