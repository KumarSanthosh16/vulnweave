import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { initializeProject } from "./onboarding.js";

test("initializes a reviewable starter policy without overwriting existing files", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "vulnweave-init-"));
  const first = await initializeProject(rootDir);
  assert.deepEqual(first.created, [".vulnweave.yml", "vulnweave.baseline.json", "rules/vulnweave-starter.yml"]);
  const starterRules = await readFile(join(rootDir, "rules/vulnweave-starter.yml"), "utf8");
  assert.match(starterRules, /vulnweave\.python\.no-shell-true/);
  assert.match(starterRules, /vulnweave\.python\.insecure-tls-verification/);
  await writeFile(join(rootDir, ".vulnweave.yml"), "schemaVersion: 1\nanalyzer: semgrep\n");
  const second = await initializeProject(rootDir);
  assert.equal(second.existing.includes(".vulnweave.yml"), true);
  assert.equal(await readFile(join(rootDir, ".vulnweave.yml"), "utf8"), "schemaVersion: 1\nanalyzer: semgrep\n");
});

test("keeps a legacy JSON policy authoritative during initialization", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "vulnweave-init-"));
  await writeFile(join(rootDir, "vulnweave.config.json"), "{\"schemaVersion\":1}\n");
  const result = await initializeProject(rootDir);
  assert.equal(result.created.includes(".vulnweave.yml"), false);
  assert.equal(result.existing.includes("vulnweave.config.json"), true);
});
