import assert from "node:assert/strict";
import test from "node:test";
import { buildEvidenceGraph, type ScanRecord } from "./index.js";

test("links a finding to its file and evidence", () => {
  const record: ScanRecord = { schemaVersion: 1, id: "scan", startedAt: "", completedAt: "", rootDir: ".", analyzerId: "test", findings: [{ id: "f", analyzer: "semgrep", ruleId: "r", category: "security", severity: "high", title: "Issue", message: "x", location: { path: "src/a.ts", startLine: 1, startColumn: 1 }, evidence: [{ id: "e", kind: "source", summary: "match" }] }] };
  const graph = buildEvidenceGraph(record);
  assert.equal(graph.nodes.length, 3);
  assert.deepEqual(graph.edges.map((edge) => edge.relation).sort(), ["has_evidence", "located_in"]);
});

test("connects an affected dependency to files with static import evidence", () => {
  const record: ScanRecord = { schemaVersion: 1, id: "scan", startedAt: "", completedAt: "", rootDir: ".", analyzerId: "test", findings: [{ id: "f", analyzer: "osv", ruleId: "GHSA", category: "dependency", severity: "high", title: "Dependency issue", message: "x", metadata: { package: "example", version: "1.0.0" }, evidence: [{ id: "e", kind: "dependency", summary: "example", metadata: { package: "example", version: "1.0.0" } }] }], dependencyReachability: [{ findingId: "f", packageName: "example", status: "referenced", usages: [{ packageName: "example", path: "src/app.ts", line: 1, column: 1, source: "example" }] }] };
  const graph = buildEvidenceGraph(record);
  assert.ok(graph.edges.some((edge) => edge.from === "dependency:example@1.0.0" && edge.to === "file:src/app.ts" && edge.relation === "statically_imported_by"));
});
