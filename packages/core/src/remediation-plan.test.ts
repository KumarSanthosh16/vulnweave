import assert from "node:assert/strict";
import test from "node:test";
import { buildRemediationPlan, formatRemediationPlan, type Finding } from "./index.js";

test("builds one explicit queue from remediation, ownership, upgrades, and accepted risks", () => {
  const findings: Finding[] = [
    { id: "active", analyzer: "osv", ruleId: "GHSA-active", category: "dependency", severity: "high", title: "Active package issue", message: "x", location: { path: "requirements.txt", startLine: 3, startColumn: 1 }, evidence: [] },
    { id: "accepted", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "critical", title: "Reviewed exception", message: "x", evidence: [] }
  ];
  const plan = buildRemediationPlan(
    findings,
    [{ findingId: "active", action: "Upgrade the package.", verification: "Run tests." }, { findingId: "accepted", action: "Fix it.", verification: "Scan again." }],
    [{ findingId: "active", path: "requirements.txt", owners: ["@platform"] }],
    [{ findingId: "active", packageName: "example", installedVersion: "1.0.0", targetVersion: "1.1.0", status: "upgrade-available", staticImportCount: 0, severity: "high", advisoryIds: ["GHSA-active"], recommendedChange: "Upgrade." }],
    [{ findingId: "accepted", fingerprint: "stable", reason: "Fix is scheduled", owner: "security@example.test", expiresOn: "2027-01-01" }]
  );
  assert.deepEqual(plan.map((item) => [item.findingId, item.status, item.owners]), [["accepted", "accepted-risk", []], ["active", "active", ["@platform"]]]);
  assert.equal(plan[1]?.upgrade?.targetVersion, "1.1.0");
  assert.match(formatRemediationPlan(plan), /ACCEPTED UNTIL 2027-01-01/);
  assert.match(formatRemediationPlan(plan), /Upgrade example to 1.1.0/);
});
