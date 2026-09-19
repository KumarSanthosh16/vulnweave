import assert from "node:assert/strict";
import test from "node:test";
import { runAnalyzers, type AnalyzerAdapter } from "./index.js";

test("keeps successful findings when another analyzer fails", async () => {
  const good: AnalyzerAdapter = { id: "good", displayName: "Good", async analyze() { return [{ ruleId: "x", category: "security", severity: "low", title: "x", message: "x" }]; } };
  const bad: AnalyzerAdapter = { id: "bad", displayName: "Bad", async analyze() { throw new Error("broken scanner"); } };
  const result = await runAnalyzers([good, bad], { rootDir: "." });
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.analyzers.map((run) => run.status), ["completed", "failed"]);
});
