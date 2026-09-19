import assert from "node:assert/strict";
import test from "node:test";
import { analyzeChangeImpact, findingsInChangeScope, rankFileHotspots, type CodeSymbol, type Finding } from "./index.js";

test("ranks locally imported files as higher change-impact hotspots", () => {
  const symbols: CodeSymbol[] = [{ id: "s", path: "src/shared.ts", name: "shared", kind: "function", line: 1, column: 1, endLine: 2, endColumn: 1 }];
  const hotspots = rankFileHotspots(symbols, [{ from: "src/a.ts", to: "src/shared.ts", source: "./shared" }, { from: "src/b.ts", to: "src/shared.ts", source: "./shared" }]);
  assert.equal(hotspots[0]?.score, 21);
});

test("traces import dependents of a changed file and their source findings", () => {
  const findings: Finding[] = [
    { id: "changed", analyzer: "semgrep", ruleId: "r", category: "security", severity: "high", title: "changed", message: "x", location: { path: "src/shared.ts", startLine: 1, startColumn: 1 }, evidence: [] },
    { id: "dependent", analyzer: "semgrep", ruleId: "r", category: "security", severity: "medium", title: "dependent", message: "x", location: { path: "src/api.ts", startLine: 1, startColumn: 1 }, evidence: [] }
  ];
  const impact = analyzeChangeImpact(findings, ["src/shared.ts"], [{ from: "src/api.ts", to: "src/shared.ts", source: "./shared" }], "main");
  assert.deepEqual(impact.dependentFiles, ["src/api.ts"]);
  assert.deepEqual(impact.directlyChangedFindings.map((finding) => finding.id), ["changed"]);
  assert.deepEqual(impact.importAffectedFindings.map((finding) => finding.id), ["dependent"]);
  assert.deepEqual(findingsInChangeScope(impact).map((finding) => finding.id), ["changed", "dependent"]);
});
