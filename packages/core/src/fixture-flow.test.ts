import assert from "node:assert/strict";
import test from "node:test";
import { buildEvidenceGraph, correlateFindings, evaluateGate, formatScanSummary, rankFindings, toSarif, type Finding, type ScanRecord } from "./index.js";

const fixtureRoot = "fixtures/intentional-findings";
const semgrepFinding: Finding = {
  id: "semgrep:eval", analyzer: "semgrep", ruleId: "vulnweave.javascript.no-eval", category: "security", severity: "high",
  title: "Avoid eval", message: "Fixture source match", location: { path: `${fixtureRoot}/src/eval-demo.ts`, startLine: 3, startColumn: 10 },
  evidence: [{ id: "semgrep:eval", kind: "source", summary: "Semgrep matched fixture source." }]
};
const osvFinding: Finding = {
  id: "osv:GHSA-fixture", analyzer: "osv", ruleId: "GHSA-fixture", category: "dependency", severity: "medium",
  title: "Fixture dependency advisory", message: "Fixture OSV observation", metadata: { package: "fixture-package", aliases: "CVE-2026-9999" },
  evidence: [{ id: "osv:fixture", kind: "dependency", summary: "OSV fixture evidence", metadata: { package: "fixture-package", version: "1.0.0" } }]
};
const trivyFinding: Finding = {
  id: "trivy:CVE-2026-9999", analyzer: "trivy", ruleId: "CVE-2026-9999", category: "dependency", severity: "high",
  title: "Fixture dependency advisory", message: "Fixture Trivy observation", metadata: { package: "fixture-package" },
  evidence: [{ id: "trivy:fixture", kind: "dependency", summary: "Trivy fixture evidence", metadata: { package: "fixture-package", version: "1.0.0" } }]
};

test("fixture flow retains evidence while exercising correlation, graph, priority, SARIF, and gate", () => {
  const correlation = correlateFindings([semgrepFinding, osvFinding, trivyFinding]);
  assert.equal(correlation.findings.length, 2);
  const record: ScanRecord = {
    schemaVersion: 1, id: "fixture", startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:00:01Z",
    rootDir: ".", analyzerId: "combined", findings: correlation.findings, sourceFindingCount: correlation.sourceFindingCount
  };
  const graph = buildEvidenceGraph(record);
  const priorities = rankFindings(record.findings, []);
  const sarif = toSarif(record.findings);
  const gate = evaluateGate(record.findings, "high");

  assert.match(formatScanSummary(record), /Correlation: 3 scanner observations → 2 canonical issues/);
  assert.equal(graph.nodes.filter((node) => node.kind === "finding").length, 2);
  assert.equal(graph.nodes.filter((node) => node.kind === "dependency").length, 1);
  assert.equal(priorities.length, 2);
  assert.equal((sarif.runs[0] as { results: unknown[] }).results.length, 2);
  assert.equal(gate.violations.length, 2);
  assert.equal(record.findings.find((finding) => finding.analyzer === "osv+trivy")?.evidence.length, 2);
});
