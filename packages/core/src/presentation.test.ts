import assert from "node:assert/strict";
import test from "node:test";
import { filterFindings, formatFindingsTable, type Finding } from "./index.js";

const findings: Finding[] = [
  { id: "1", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "high", title: "Dangerous call", message: "x", location: { path: "src/a.ts", startLine: 4, startColumn: 1 }, evidence: [] },
  { id: "2", analyzer: "osv", ruleId: "GHSA-test", category: "dependency", severity: "medium", title: "Dependency issue", message: "x", evidence: [] }
];

test("filters findings without changing their schema", () => {
  assert.deepEqual(filterFindings(findings, { analyzer: "osv" }).map((finding) => finding.id), ["2"]);
});

test("renders a table with finding location", () => {
  assert.match(formatFindingsTable(findings), /src\/a\.ts:4/);
  assert.equal(formatFindingsTable([]), "No findings match the selected filters.");
});
