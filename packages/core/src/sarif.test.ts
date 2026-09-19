import assert from "node:assert/strict";
import test from "node:test";
import { toSarif, type Finding } from "./index.js";

test("exports a located finding as SARIF 2.1.0", () => {
  const finding: Finding = { id: "f", analyzer: "semgrep", ruleId: "eval", category: "security", severity: "high", title: "Unsafe eval", message: "Avoid eval", location: { path: "src/a.ts", startLine: 2, startColumn: 3 }, evidence: [] };
  const sarif = toSarif([finding]);
  const run = sarif.runs[0] as { results: Array<{ level: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> };
  assert.equal(run.results[0]?.level, "error");
  assert.equal(run.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri, "src/a.ts");
});
