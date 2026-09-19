import assert from "node:assert/strict";
import test from "node:test";
import { parseOsvReport } from "./index.js";

test("normalizes package vulnerabilities with dependency evidence", () => {
  const findings = parseOsvReport({ results: [{ source: { path: "pnpm-lock.yaml", type: "lockfile" }, packages: [{ package: { name: "example", version: "1.0.0", ecosystem: "npm" }, vulnerabilities: [{ id: "GHSA-test", summary: "Example issue", aliases: ["CVE-2026-1"], database_specific: { severity: "HIGH" } }] }] }] });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.category, "dependency");
  assert.equal(findings[0]?.severity, "high");
  assert.deepEqual(findings[0]?.evidence[0]?.metadata, { package: "example", version: "1.0.0", sourcePath: "pnpm-lock.yaml" });
});
