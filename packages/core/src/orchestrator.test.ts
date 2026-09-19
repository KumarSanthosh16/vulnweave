import assert from "node:assert/strict";
import test from "node:test";
import { AnalysisOrchestrator, type AnalyzerAdapter } from "./index.js";

test("orchestrator normalizes adapter findings and completes", async () => {
  const adapter: AnalyzerAdapter = {
    id: "test", displayName: "Test",
    async analyze() { return [{ ruleId: "demo", category: "security", severity: "low", title: "Demo", message: "A demo finding" }]; }
  };
  const result = await new AnalysisOrchestrator().run(adapter, { rootDir: "." });
  assert.equal(result.state.phase, "completed");
  assert.equal(result.findings[0]?.id, "test:demo:global:1");
});

test("orchestrator records a failed analyzer state", async () => {
  const adapter: AnalyzerAdapter = { id: "broken", displayName: "Broken", async analyze() { throw new Error("tool failed"); } };
  const orchestrator = new AnalysisOrchestrator();
  await assert.rejects(orchestrator.run(adapter, { rootDir: "." }), /tool failed/);
  assert.equal(orchestrator.getState().phase, "failed");
});

test("a cancelled run does not publish late analyzer results", async () => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const adapter: AnalyzerAdapter = {
    id: "slow", displayName: "Slow",
    async analyze() { await pending; return [{ ruleId: "x", category: "quality", severity: "info", title: "x", message: "x" }]; }
  };
  const orchestrator = new AnalysisOrchestrator();
  const resultPromise = orchestrator.run(adapter, { rootDir: "." });
  await new Promise((resolve) => setImmediate(resolve));
  orchestrator.cancel();
  release();
  const result = await resultPromise;
  assert.equal(result.state.phase, "cancelled");
  assert.deepEqual(result.findings, []);
});
