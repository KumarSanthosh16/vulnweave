import assert from "node:assert/strict";
import test from "node:test";
import { buildRemediationAdvice, formatRemediationTable, type Finding } from "./index.js";

test("offers dependency upgrades only as advisory next steps", () => {
  const finding: Finding = { id: "dependency", analyzer: "trivy", ruleId: "CVE-test", category: "dependency", severity: "high", title: "affected package", message: "x", metadata: { package: "example", version: "1.0.0", fixedVersion: "1.0.1" }, evidence: [] };
  const advice = buildRemediationAdvice([finding], [{ findingId: "dependency", packageName: "example", status: "referenced", usages: [{ packageName: "example", path: "src/app.ts", line: 2, column: 1, source: "example" }] }]);
  assert.match(advice[0]?.action ?? "", /example from 1\.0\.0 to 1\.0\.1/);
  assert.match(advice[0]?.rationale ?? "", /Static imports/);
  assert.match(formatRemediationTable([finding], advice), /NEXT ACTION/);
});

test("uses manifest-aware guidance for Python requirements", () => {
  const finding: Finding = { id: "python-dependency", analyzer: "osv", ruleId: "GHSA-test", category: "dependency", severity: "high", title: "affected Python package", message: "x", metadata: { package: "example-python", version: "1.0.0", fixedVersion: "1.0.1", sourcePath: "requirements.txt", ecosystem: "PyPI" }, evidence: [] };
  const [advice] = buildRemediationAdvice([finding]);
  assert.match(advice?.action ?? "", /requirement declaration to 1\.0\.1 or later/);
  assert.match(advice?.action ?? "", /recreate the environment or lockfile/);
});

test("does not expose detected secret values in guidance", () => {
  const finding: Finding = { id: "secret", analyzer: "gitleaks", ruleId: "generic", category: "secret", severity: "high", title: "Secret", message: "x", evidence: [] };
  const [advice] = buildRemediationAdvice([finding]);
  assert.match(advice?.action ?? "", /revoke or rotate/i);
  assert.match(advice?.rationale ?? "", /does not retain/i);
});
