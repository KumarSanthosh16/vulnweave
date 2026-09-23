import assert from "node:assert/strict";
import test from "node:test";
import { parseTrivyReport, trivyArguments } from "./index.js";

test("skips nested generated and third-party directories", () => {
  const arguments_ = trivyArguments("/workspace");
  assert.deepEqual(arguments_.slice(-1), ["/workspace"]);
  for (const directory of ["**/node_modules", "**/node_modules/.pnpm", "**/.pnpm-store", "**/dist", "**/.astro", "**/fixtures"]) {
    assert.equal(arguments_.includes(directory), true);
  }
});

test("normalizes Trivy vulnerabilities and misconfigurations without config excerpts", () => {
  const findings = parseTrivyReport({ Results: [{
    Target: "package-lock.json", Type: "npm",
    Vulnerabilities: [{
      VulnerabilityID: "CVE-2026-1234", PkgName: "example", InstalledVersion: "1.0.0", FixedVersion: "1.0.1",
      Title: "Example dependency issue", Severity: "HIGH", PrimaryURL: "https://example.test/CVE-2026-1234"
    }],
    Misconfigurations: [{
      ID: "AVD-TEST-0001", Title: "Example configuration issue", Description: "A setting is unsafe.",
      Severity: "MEDIUM", CauseMetadata: { Resource: "service", StartLine: 8, EndLine: 9 }
    }]
  }] });

  assert.equal(findings.length, 2);
  assert.deepEqual(findings[0]?.metadata, { target: "package-lock.json", targetType: "npm", package: "example", version: "1.0.0", fixedVersion: "1.0.1" });
  assert.equal(findings[0]?.severity, "high");
  assert.equal(findings[1]?.category, "infrastructure");
  assert.deepEqual(findings[1]?.location, { path: "package-lock.json", startLine: 8, startColumn: 1, endLine: 9 });
  assert.equal(findings[1]?.metadata?.sourcePath, "package-lock.json");
  assert.equal("excerpt" in (findings[1]?.evidence[0] ?? {}), false);
});
