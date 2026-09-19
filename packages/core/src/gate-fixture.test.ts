import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { applySuppressions, evaluateGate, loadBaselinePolicy, type Finding } from "./index.js";

const fixtureRoot = fileURLToPath(new URL("../../../fixtures/gate-policy/", import.meta.url));

test("fixture baseline fails a high finding until an approved unexpired suppression exists", async () => {
  const finding = JSON.parse(await readFile(new URL("../../../fixtures/gate-policy/high-finding.json", import.meta.url), "utf8")) as Finding;
  const defaultBaseline = await loadBaselinePolicy(fixtureRoot);
  const defaultSuppression = applySuppressions([finding], defaultBaseline?.suppressions ?? [], new Date("2026-09-19T00:00:00Z"));
  assert.equal(evaluateGate(defaultSuppression.activeFindings, defaultBaseline?.failOn).passed, false);

  const approvedBaseline = await loadBaselinePolicy(fixtureRoot, "approved-baseline.json");
  const approvedSuppression = applySuppressions([finding], approvedBaseline?.suppressions ?? [], new Date("2026-09-19T00:00:00Z"));
  assert.equal(approvedSuppression.suppressed.length, 1);
  assert.equal(evaluateGate(approvedSuppression.activeFindings, approvedBaseline?.failOn).passed, true);
});
