import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compareScanRecords, formatScanSummary, loadScanRecord, saveScanRecord, type ScanRecord } from "./index.js";

const finding = { id: "a:1", analyzer: "a", ruleId: "one", category: "security" as const, severity: "high" as const, title: "Issue", message: "Issue", fingerprint: "stable", evidence: [] };
const record = (findings: typeof finding[]): ScanRecord => ({ schemaVersion: 1, id: "run", startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:00:01Z", rootDir: ".", analyzerId: "a", findings });

test("compares findings by analyzer and stable fingerprint", () => {
  const next = { ...finding, id: "a:changed-line" };
  const comparison = compareScanRecords(record([next]), record([finding, { ...finding, id: "a:old", fingerprint: "old" }]));
  assert.equal(comparison.unchangedFindings.length, 1);
  assert.equal(comparison.resolvedFindings.length, 1);
  assert.equal(comparison.newFindings.length, 0);
});

test("formats a concise scan summary", () => {
  assert.match(formatScanSummary(record([finding])), /Findings: 1/);
  assert.match(formatScanSummary({ ...record([finding]), sourceFindingCount: 2 }), /Correlation: 2 scanner observations → 1 canonical issues/);
});

test("persists and reloads a scan record locally", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "VulnWeave-test-"));
  try {
    const saved = await saveScanRecord({ startedAt: "2026-01-01T00:00:00Z", rootDir, analyzerId: "a", findings: [finding] });
    const loaded = await loadScanRecord(rootDir, "latest");
    assert.equal(loaded.id, saved.id);
    assert.equal(loaded.findings[0]?.fingerprint, "stable");
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});
