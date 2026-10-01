import assert from "node:assert/strict";
import test from "node:test";
import { buildFindingBaseline, compareFindingsToBaseline, formatFindingBaseline, validateFindingBaseline, type Finding } from "./index.js";

const existing: Finding = { id: "existing", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "high", title: "Existing", message: "x", fingerprint: "stable-existing", evidence: [] };
const introduced: Finding = { id: "introduced", analyzer: "semgrep", ruleId: "rule", category: "security", severity: "high", title: "Introduced", message: "x", fingerprint: "stable-introduced", evidence: [] };

test("compares a portable finding baseline without suppressing current findings", () => {
  const baseline = buildFindingBaseline([existing]);
  const comparison = compareFindingsToBaseline([existing, introduced], baseline);
  assert.deepEqual(baseline, { schemaVersion: 1, fingerprints: ["semgrep:stable-existing"] });
  assert.deepEqual(comparison.newFindings.map((finding) => finding.id), ["introduced"]);
  assert.deepEqual(comparison.unchangedFindings.map((finding) => finding.id), ["existing"]);
  assert.equal(formatFindingBaseline(baseline).includes("stable-existing"), true);
});

test("rejects malformed finding baselines", () => {
  assert.throws(() => validateFindingBaseline({ schemaVersion: 1, fingerprints: [""] }), /non-empty/);
});
