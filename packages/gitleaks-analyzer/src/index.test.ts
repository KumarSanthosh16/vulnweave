import assert from "node:assert/strict";
import test from "node:test";
import { gitleaksArguments, parseGitleaksReport } from "./index.js";

test("normalizes Gitleaks output without retaining matched secret text", () => {
  const [finding] = parseGitleaksReport([{
    RuleID: "generic-api-key", Description: "Generic API key", File: "src/config.ts",
    StartLine: 7, StartColumn: 18, EndLine: 7, EndColumn: 42,
    Match: "api_key=super-secret-value", Fingerprint: "abc123", Tags: ["key", "api"]
  }]);
  assert.equal(finding?.category, "secret");
  assert.equal(finding?.severity, "high");
  assert.deepEqual(finding?.location, { path: "src/config.ts", startLine: 7, startColumn: 18, endLine: 7, endColumn: 42 });
  assert.equal(JSON.stringify(finding).includes("super-secret-value"), false);
  assert.deepEqual(finding?.metadata, { tags: "key,api" });
});

test("passes an explicit custom Gitleaks configuration only when configured", () => {
  assert.deepEqual(gitleaksArguments("project", "report.json", "rules/gitleaks.toml"), ["detect", "--no-banner", "--source", "project", "--config", "rules/gitleaks.toml", "--report-format", "json", "--report-path", "report.json"]);
  assert.equal(gitleaksArguments("project", "report.json", undefined).includes("--config"), false);
});
