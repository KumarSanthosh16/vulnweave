import assert from "node:assert/strict";
import test from "node:test";
import { linkFindingsToSymbols, type CodeSymbol, type Finding } from "./index.js";

test("links a finding to the narrowest enclosing symbol", () => {
  const symbols: CodeSymbol[] = [
    { id: "class", path: "src/a.ts", name: "Service", kind: "class", line: 1, column: 1, endLine: 20, endColumn: 1 },
    { id: "method", path: "src/a.ts", name: "run", kind: "method", line: 5, column: 3, endLine: 8, endColumn: 4 }
  ];
  const finding: Finding = { id: "finding", analyzer: "semgrep", ruleId: "x", category: "security", severity: "high", title: "x", message: "x", location: { path: "src/a.ts", startLine: 6, startColumn: 4 }, evidence: [] };
  assert.deepEqual(linkFindingsToSymbols([finding], symbols), [{ findingId: "finding", symbolId: "method" }]);
});
