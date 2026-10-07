import assert from "node:assert/strict";
import test from "node:test";
import { toGitHubStepSummary, type ScanRecord } from "./index.js";

test("renders a GitHub-ready remediation summary without trusting finding text as table syntax", () => {
  const record: ScanRecord = {
    schemaVersion: 1, id: "run", startedAt: "", completedAt: "", rootDir: ".", analyzerId: "combined",
    findings: [{ id: "active", analyzer: "osv", ruleId: "GHSA", category: "dependency", severity: "high", title: "package | issue", message: "x", evidence: [] }],
    gate: { evaluated: 1, violations: [], passed: true },
    analyzerHealth: { required: true, evaluated: 4, unavailable: [], failed: [], passed: true },
    remediationPlan: [{ findingId: "active", severity: "high", status: "active", owners: ["@platform"], title: "package | issue", action: "Upgrade safely.", verification: "Test.", upgrade: { packageName: "example", targetVersion: "1.2.0", status: "upgrade-available" } }]
  };
  const summary = toGitHubStepSummary(record);
  assert.match(summary, /## VulnWeave remediation summary/);
  assert.match(summary, /package \\| issue/);
  assert.match(summary, /Upgrade example to 1\.2\.0/);
  assert.match(summary, /Full repository scan/);
});
