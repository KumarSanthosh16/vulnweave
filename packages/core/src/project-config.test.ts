import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadProjectConfig, validateProjectConfig } from "./index.js";

test("loads a versioned YAML project policy with local ownership", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "VulnWeave-config-"));
  try {
    await writeFile(join(rootDir, ".vulnweave.yml"), "schemaVersion: 1\nanalyzer: all\nsemgrepConfig: rules.yml\nfailOn: high\nrequireAnalyzers: true\nowners:\n  - pattern: packages/api/**\n    owners: [\"@platform\"]\n");
    assert.deepEqual(await loadProjectConfig(rootDir), { schemaVersion: 1, analyzer: "all", semgrepConfig: "rules.yml", failOn: "high", requireAnalyzers: true, owners: [{ pattern: "packages/api/**", owners: ["@platform"] }] });
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});

test("keeps the JSON project configuration as a compatible fallback", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "VulnWeave-config-"));
  try {
    await writeFile(join(rootDir, "vulnweave.config.json"), JSON.stringify({ schemaVersion: 1, analyzer: "all" }));
    assert.deepEqual(await loadProjectConfig(rootDir), { schemaVersion: 1, analyzer: "all" });
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});

test("supports a focused list of real analyzers", () => {
  assert.deepEqual(validateProjectConfig({ schemaVersion: 1, analyzers: ["osv", "semgrep"] }), { schemaVersion: 1, analyzers: ["osv", "semgrep"] });
  assert.throws(() => validateProjectConfig({ schemaVersion: 1, analyzer: "all", analyzers: ["osv"] }), /either analyzer or analyzers/);
  assert.throws(() => validateProjectConfig({ schemaVersion: 1, analyzers: ["osv", "osv"] }), /duplicates/);
});

test("rejects an invalid project policy", () => {
  assert.throws(() => validateProjectConfig({ schemaVersion: 1, failOn: "severe" }), /failOn/);
  assert.throws(() => validateProjectConfig({ schemaVersion: 1, owners: [{ pattern: "src/**", owners: [] }] }), /owners/);
});
