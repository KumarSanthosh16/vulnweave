import assert from "node:assert/strict";
import test from "node:test";
import { buildDependencyUpgradePlan, formatDependencyUpgradePlan, type Finding } from "./index.js";

test("plans only scanner-reported dependency upgrades without changing packages", () => {
  const finding: Finding = { id: "f", analyzer: "trivy", ruleId: "CVE", category: "dependency", severity: "high", title: "issue", message: "x", metadata: { package: "example", version: "1.0.0", fixedVersion: "1.2.0", sourcePath: "requirements.txt", ecosystem: "PyPI" }, evidence: [] };
  const [plan] = buildDependencyUpgradePlan([finding], [{ findingId: "f", packageName: "example", status: "referenced", usages: [{ packageName: "example", path: "src/app.ts", line: 1, column: 1, source: "example" }] }]);
  assert.deepEqual(plan, { findingId: "f", packageName: "example", installedVersion: "1.0.0", targetVersion: "1.2.0", status: "upgrade-available", staticImportCount: 1, severity: "high", advisoryIds: ["CVE"], sourcePath: "requirements.txt", ecosystem: "PyPI", recommendedChange: "Update example in requirements.txt to 1.2.0 or later, then recreate the environment or lockfile." });
  assert.match(formatDependencyUpgradePlan([plan!]), /no files are changed/);
  assert.match(formatDependencyUpgradePlan([plan!]), /recreate the environment or lockfile/);
});

test("directs Poetry findings to pyproject rather than a generated lockfile", () => {
  const finding: Finding = { id: "poetry", analyzer: "osv", ruleId: "GHSA", category: "dependency", severity: "high", title: "issue", message: "x", metadata: { package: "example", version: "1.0.0", fixedVersion: "1.2.0", sourcePath: "services/api/poetry.lock", ecosystem: "PyPI" }, evidence: [] };
  const [plan] = buildDependencyUpgradePlan([finding]);
  assert.match(plan?.recommendedChange ?? "", /services\/api\/pyproject\.toml/);
  assert.match(plan?.recommendedChange ?? "", /poetry lock/);
  assert.doesNotMatch(plan?.recommendedChange ?? "", /Update example in services\/api\/poetry\.lock/);
});
