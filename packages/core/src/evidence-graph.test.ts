import assert from "node:assert/strict";
import test from "node:test";
import { buildEvidenceGraph, type ScanRecord } from "./index.js";

test("links a finding to its file and evidence", () => {
  const record: ScanRecord = { schemaVersion: 1, id: "scan", startedAt: "", completedAt: "", rootDir: ".", analyzerId: "test", findings: [{ id: "f", analyzer: "semgrep", ruleId: "r", category: "security", severity: "high", title: "Issue", message: "x", location: { path: "src/a.ts", startLine: 1, startColumn: 1 }, evidence: [{ id: "e", kind: "source", summary: "match" }] }] };
  const graph = buildEvidenceGraph(record);
  assert.equal(graph.nodes.length, 3);
  assert.deepEqual(graph.edges.map((edge) => edge.relation).sort(), ["has_evidence", "located_in"]);
});
