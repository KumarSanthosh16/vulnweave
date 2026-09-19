import assert from "node:assert/strict";
import test from "node:test";
import { evaluateAnalyzerHealth, formatAnalyzerHealth, type AnalyzerRunStatus } from "./index.js";

const runs: AnalyzerRunStatus[] = [
  { analyzerId: "semgrep", displayName: "Semgrep", status: "completed", findings: [] },
  { analyzerId: "trivy", displayName: "Trivy", status: "unavailable", findings: [] },
  { analyzerId: "osv", displayName: "OSV", status: "failed", findings: [], error: "scan error" }
];

test("requires all selected analyzers only when configured", () => {
  assert.equal(evaluateAnalyzerHealth(runs).passed, true);
  const required = evaluateAnalyzerHealth(runs, true);
  assert.equal(required.passed, false);
  assert.match(formatAnalyzerHealth(required), /unavailable trivy/);
  assert.match(formatAnalyzerHealth(required), /failed osv/);
});
