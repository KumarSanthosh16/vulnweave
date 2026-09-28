import assert from "node:assert/strict";
import test from "node:test";
import { OsvAnalyzer, parseOsvReport } from "./index.js";

test("normalizes package vulnerabilities with dependency evidence", () => {
  const findings = parseOsvReport({ results: [{ source: { path: "pnpm-lock.yaml", type: "lockfile" }, packages: [{ package: { name: "example", version: "1.0.0", ecosystem: "npm" }, vulnerabilities: [{ id: "GHSA-test", summary: "Example issue", aliases: ["CVE-2026-1"], database_specific: { severity: "HIGH" } }] }] }] });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.category, "dependency");
  assert.equal(findings[0]?.severity, "high");
  assert.deepEqual(findings[0]?.evidence[0]?.metadata, { package: "example", version: "1.0.0", sourcePath: "pnpm-lock.yaml" });
});

test("retains OSV findings when the scanner exits one", async () => {
  const report = { results: [{ source: { path: "pnpm-lock.yaml", type: "lockfile" }, packages: [{ package: { name: "example", version: "1.0.0" }, vulnerabilities: [{ id: "GHSA-test" }] }] }] };
  const analyzer = new OsvAnalyzer(async () => {
    throw Object.assign(new Error("vulnerabilities found"), { code: 1, stdout: JSON.stringify(report) });
  });
  const findings = await analyzer.analyze({ rootDir: "." });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.ruleId, "GHSA-test");
});

test("covers a requirements manifest without a lockfile and requests all advisories", async () => {
  const report = { results: [{ source: { path: "testBE/requirements.txt", type: "manifest" }, packages: [{ package: { name: "python-multipart", version: "0.0.6", ecosystem: "PyPI" }, vulnerabilities: [{ id: "GHSA-2jv5-9r88-3w3p", database_specific: { severity: "HIGH" } }] }] }] };
  let receivedArgs: string[] = [];
  const analyzer = new OsvAnalyzer(async (args) => {
    receivedArgs = args;
    return JSON.stringify(report);
  });
  const findings = await analyzer.analyze({ rootDir: "repo" });
  assert.deepEqual(receivedArgs, ["scan", "source", "--format", "json", "--recursive", "--allow-no-lockfiles", "--all-vulns", "--verbosity", "error", "repo"]);
  assert.equal(findings[0]?.title, "python-multipart@0.0.6 is affected by GHSA-2jv5-9r88-3w3p");
});

test("does not treat an empty OSV response as a clean dependency scan", async () => {
  const analyzer = new OsvAnalyzer(async () => "");
  await assert.rejects(() => analyzer.analyze({ rootDir: "." }), /dependency coverage could not be established/);
});
