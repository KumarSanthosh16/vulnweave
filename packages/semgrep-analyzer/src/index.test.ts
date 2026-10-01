import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseSemgrepReport, relativizeFindings } from "./index.js";

test("normalizes a Semgrep result and preserves source location", () => {
  const [finding] = parseSemgrepReport([{
    check_id: "typescript.security.no-eval", path: "src/run.ts",
    start: { line: 9, col: 3 }, end: { line: 9, col: 18 },
    extra: { message: "Avoid eval", severity: "ERROR", fingerprint: "f00", metadata: { cwe: "CWE-95", confidence: "HIGH", nested: ["ignored"] } }
  }]);
  assert.equal(finding?.severity, "high");
  assert.equal(finding?.category, "security");
  assert.deepEqual(finding?.location, { path: "src/run.ts", startLine: 9, startColumn: 3, endLine: 9, endColumn: 18 });
  assert.deepEqual(finding?.metadata, { cwe: "CWE-95", confidence: "HIGH" });
});

test("removes local config prefixes and makes findings portable to the scan root", () => {
  const findings = parseSemgrepReport([{
    check_id: "/workspace/rules/semgrep-starter.yml.vulnweave.javascript.no-eval", path: "/workspace/fixtures/intentional-findings/src/eval-demo.ts",
    start: { line: 3, col: 10 }, end: { line: 3, col: 23 }, extra: { message: "Avoid eval", severity: "ERROR" }
  }], "/workspace/rules/semgrep-starter.yml");
  const [finding] = relativizeFindings(findings, "/workspace/fixtures/intentional-findings");
  assert.equal(finding?.ruleId, "vulnweave.javascript.no-eval");
  assert.equal(finding?.title, "vulnweave.javascript.no-eval");
  assert.equal(finding?.location?.path, "src/eval-demo.ts");
  assert.equal(finding?.evidence?.[0]?.location?.path, "src/eval-demo.ts");
});

test("ships focused Python and Node web-security packs with provenance", async () => {
  const pythonPack = await readFile(new URL("../../../rules/packs/python-web-security.yml", import.meta.url), "utf8");
  const nodePack = await readFile(new URL("../../../rules/packs/node-web-security.yml", import.meta.url), "utf8");
  assert.match(pythonPack, /vulnweave\.python-web-security\.flask-debug-server/);
  assert.match(pythonPack, /vulnweavePack: python-web-security/);
  assert.match(nodePack, /vulnweave\.node-web-security\.express-open-cors/);
  assert.match(nodePack, /vulnweavePack: node-web-security/);
});
