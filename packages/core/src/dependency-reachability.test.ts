import assert from "node:assert/strict";
import test from "node:test";
import { assessDependencyReachability, formatDependencyReachability, type Finding } from "./index.js";

test("maps dependency findings to package import evidence without claiming runtime reachability", () => {
  const findings: Finding[] = [
    { id: "used", analyzer: "osv", ruleId: "A", category: "dependency", severity: "high", title: "used", message: "x", metadata: { package: "lodash" }, evidence: [] },
    { id: "unseen", analyzer: "osv", ruleId: "B", category: "dependency", severity: "high", title: "unseen", message: "x", metadata: { package: "unused" }, evidence: [] }
  ];
  const assessments = assessDependencyReachability(findings, [{ packageName: "lodash", path: "src/app.ts", line: 2, column: 1, source: "lodash/fp" }]);
  assert.deepEqual(assessments.map((assessment) => [assessment.findingId, assessment.status]), [["used", "referenced"], ["unseen", "not-observed"]]);
  assert.match(formatDependencyReachability(assessments), /not runtime proof/);
});
