import assert from "node:assert/strict";
import test from "node:test";
import { rankFindings, type Finding } from "./index.js";

test("ranks linked secret evidence above a plain medium finding", () => {
  const findings: Finding[] = [
    { id: "medium", analyzer: "a", ruleId: "m", category: "security", severity: "medium", title: "m", message: "m", evidence: [] },
    { id: "secret", analyzer: "a", ruleId: "s", category: "secret", severity: "high", title: "s", message: "s", evidence: [] }
  ];
  const ranked = rankFindings(findings, [{ findingId: "secret", symbolId: "symbol:one" }]);
  assert.deepEqual(ranked.map((assessment) => assessment.findingId), ["secret", "medium"]);
  assert.equal(ranked[0]?.score, 90);
  assert.match(ranked[0]?.reasons.join(" ") ?? "", /concrete code symbol/);
});

test("adds an explicit score boost for a changed source file", () => {
  const finding: Finding = { id: "changed", analyzer: "a", ruleId: "x", category: "security", severity: "medium", title: "x", message: "x", location: { path: "src/a.ts", startLine: 1, startColumn: 1 }, evidence: [] };
  const [assessment] = rankFindings([finding], [], ["src/a.ts"]);
  assert.equal(assessment?.score, 55);
  assert.match(assessment?.reasons.join(" ") ?? "", /changed file/);
});

test("adds a bounded boost for a locally imported finding file", () => {
  const finding: Finding = { id: "shared", analyzer: "a", ruleId: "x", category: "security", severity: "medium", title: "x", message: "x", location: { path: "src/shared.ts", startLine: 1, startColumn: 1 }, evidence: [] };
  const [assessment] = rankFindings([finding], [], [], [{ from: "src/a.ts", to: "src/shared.ts", source: "./shared" }, { from: "src/b.ts", to: "src/shared.ts", source: "./shared" }]);
  assert.equal(assessment?.score, 44);
});

test("prioritizes a dependency finding only when its package has static import evidence", () => {
  const finding: Finding = { id: "dependency", analyzer: "osv", ruleId: "GHSA-example", category: "dependency", severity: "medium", title: "package issue", message: "x", metadata: { package: "lodash" }, evidence: [] };
  const [assessment] = rankFindings([finding], [], [], [], [{ findingId: "dependency", packageName: "lodash", status: "referenced", usages: [{ packageName: "lodash", path: "src/app.ts", line: 1, column: 20, source: "lodash/fp" }] }]);
  assert.equal(assessment?.score, 57);
  assert.match(assessment?.reasons.join(" ") ?? "", /statically imported/);
});
