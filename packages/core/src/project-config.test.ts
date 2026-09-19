import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadProjectConfig, validateProjectConfig } from "./index.js";

test("loads a versioned project policy", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "VulnWeave-config-"));
  try {
    await writeFile(join(rootDir, "vulnweave.config.json"), JSON.stringify({ schemaVersion: 1, analyzer: "all", semgrepConfig: "rules.yml", failOn: "high", requireAnalyzers: true }));
    assert.deepEqual(await loadProjectConfig(rootDir), { schemaVersion: 1, analyzer: "all", semgrepConfig: "rules.yml", failOn: "high", requireAnalyzers: true });
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});

test("rejects an invalid project policy", () => {
  assert.throws(() => validateProjectConfig({ schemaVersion: 1, failOn: "severe" }), /failOn/);
});
