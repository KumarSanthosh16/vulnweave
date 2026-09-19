import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadBaselinePolicy, validateBaselinePolicy } from "./index.js";

test("loads a reviewable baseline policy", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "vulnweave-baseline-"));
  await writeFile(join(rootDir, "policy.json"), JSON.stringify({ schemaVersion: 1, failOn: "high", requireAnalyzers: true, suppressions: [{ fingerprint: "stable", reason: "Upgrade is scheduled", owner: "security@example.test", expiresOn: "2026-12-31" }] }));
  assert.deepEqual(await loadBaselinePolicy(rootDir, "policy.json"), { schemaVersion: 1, failOn: "high", requireAnalyzers: true, suppressions: [{ fingerprint: "stable", reason: "Upgrade is scheduled", owner: "security@example.test", expiresOn: "2026-12-31" }] });
});

test("rejects an unowned or unbounded baseline suppression", () => {
  assert.throws(() => validateBaselinePolicy({ schemaVersion: 1, suppressions: [{ fingerprint: "stable", reason: "later" }] }), /requires fingerprint, reason, and owner/);
});
