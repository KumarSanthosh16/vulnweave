import assert from "node:assert/strict";
import test from "node:test";
import { toHtmlReport, type ScanRecord } from "./index.js";

test("renders a self-contained report and escapes finding text", () => {
  const record: ScanRecord = { schemaVersion: 1, id: "run", startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:00:01Z", rootDir: ".", analyzerId: "combined", findings: [{ id: "f", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "high", title: "<unsafe>", message: "x", evidence: [] }] };
  const html = toHtmlReport(record);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Security posture/);
  assert.match(html, /Analyzer coverage/);
  assert.match(html, /Generated locally by VulnWeave/);
  assert.match(html, /data:image\/svg\+xml;base64,/);
  assert.match(html, /background:#126059;}/);
  assert.match(html, /--accent:#0FCFB2/);
  assert.match(html, /&lt;unsafe&gt;/);
  assert.doesNotMatch(html, /<unsafe>/);
  assert.doesNotMatch(html, /\$\{escapeHtml/);
});
