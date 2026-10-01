import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { buildDependencyUpgradePlan, correlateFindings, type Finding } from "./index.js";

interface BenchmarkFixture {
  findings: Finding[];
  expected: { sourceObservations: number; canonicalFindings: number; dependencyEvidence: number; fixedVersion: string };
}

test("benchmark preserves Python requirements evidence through correlation and upgrade planning", async () => {
  const path = fileURLToPath(new URL("../../../fixtures/benchmarks/dependency-correlation.json", import.meta.url));
  const fixture = JSON.parse(await readFile(path, "utf8")) as BenchmarkFixture;
  const result = correlateFindings(fixture.findings);
  const dependency = result.findings.find((finding) => finding.category === "dependency");
  const [plan] = buildDependencyUpgradePlan(result.findings);

  assert.equal(result.sourceFindingCount, fixture.expected.sourceObservations);
  assert.equal(result.findings.length, fixture.expected.canonicalFindings);
  assert.equal(dependency?.evidence.length, fixture.expected.dependencyEvidence);
  assert.equal(plan?.targetVersion, fixture.expected.fixedVersion);
  assert.match(plan?.recommendedChange ?? "", /requirements\.txt/);
  assert.match(plan?.recommendedChange ?? "", /recreate the environment or lockfile/);
});
