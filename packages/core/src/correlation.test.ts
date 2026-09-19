import assert from "node:assert/strict";
import test from "node:test";
import { correlateFindings } from "./correlation.js";
import type { Finding } from "./schemas.js";

function dependencyFinding(analyzer: string, ruleId: string, aliases = ""): Finding {
  return {
    id: `${analyzer}:${ruleId}`, analyzer, ruleId, category: "dependency", severity: analyzer === "trivy" ? "high" : "medium",
    title: "Example package vulnerability", message: "Example advisory", evidence: [{ id: `${analyzer}:evidence`, kind: "dependency", summary: "Scanner evidence" }],
    metadata: { package: "example", aliases }
  };
}

test("correlates OSV aliases with Trivy advisories while retaining both evidence sources", () => {
  const result = correlateFindings([
    dependencyFinding("osv", "GHSA-example", "CVE-2026-1234"),
    dependencyFinding("trivy", "CVE-2026-1234")
  ]);
  assert.equal(result.sourceFindingCount, 2);
  assert.equal(result.findings.length, 1);
  assert.equal(result.correlatedGroupCount, 1);
  assert.equal(result.findings[0]?.analyzer, "osv+trivy");
  assert.equal(result.findings[0]?.ruleId, "CVE-2026-1234");
  assert.equal(result.findings[0]?.severity, "high");
  assert.deepEqual(result.findings[0]?.evidence.map((item) => item.metadata?.analyzer).sort(), ["osv", "trivy"]);
});

test("does not correlate unrelated dependency advisories", () => {
  const result = correlateFindings([dependencyFinding("osv", "GHSA-one"), dependencyFinding("trivy", "CVE-2026-1234")]);
  assert.equal(result.findings.length, 2);
  assert.equal(result.correlatedGroupCount, 0);
});
