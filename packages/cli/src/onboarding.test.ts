import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { initializeProject } from "./onboarding.js";

test("initializes a reviewable starter policy without overwriting existing files", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "vulnweave-init-"));
  const first = await initializeProject(rootDir);
  assert.deepEqual(first.created, ["vulnweave.config.json", "vulnweave.baseline.json", "rules/vulnweave-starter.yml"]);
  await writeFile(join(rootDir, "vulnweave.config.json"), "{\"custom\":true}\n");
  const second = await initializeProject(rootDir);
  assert.equal(second.existing.includes("vulnweave.config.json"), true);
  assert.equal(await readFile(join(rootDir, "vulnweave.config.json"), "utf8"), "{\"custom\":true}\n");
});
