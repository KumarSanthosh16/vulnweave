import assert from "node:assert/strict";
import test from "node:test";
import { buildScanTrend, formatScanTrend, type ScanRecord } from "./index.js";

const record = (id: string, completedAt: string, severity?: "high" | "low"): ScanRecord => ({
  schemaVersion: 1, id, startedAt: completedAt, completedAt, rootDir: ".", analyzerId: "combined",
  findings: severity ? [{ id, analyzer: "semgrep", ruleId: "rule", category: "security", severity, title: id, message: id, fingerprint: id, evidence: [] }] : []
});

test("summarizes security posture across saved scans", () => {
  const trend = buildScanTrend([record("older", "2026-01-01T00:00:00Z", "high"), record("latest", "2026-01-02T00:00:00Z")]);
  assert.equal(trend.posture, "improving");
  assert.equal(trend.points[1]?.resolvedFindings, 1);
  assert.match(formatScanTrend(trend), /Security trend: improving/);
});
