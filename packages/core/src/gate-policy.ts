import type { Finding, Severity } from "./schemas.js";

export interface GateResult { failOn?: Severity; evaluated: number; violations: Finding[]; passed: boolean; }

const severityOrder: Severity[] = ["info", "low", "medium", "high", "critical"];

/** Evaluates a chosen set of findings; callers decide whether it is all or only new findings. */
export function evaluateGate(findings: Finding[], failOn?: Severity): GateResult {
  if (!failOn) return { evaluated: findings.length, violations: [], passed: true };
  const minimum = severityOrder.indexOf(failOn);
  const violations = findings.filter((finding) => severityOrder.indexOf(finding.severity) >= minimum);
  return { failOn, evaluated: findings.length, violations, passed: violations.length === 0 };
}

export function formatGateResult(result: GateResult, baselineUsed: boolean, changedCodeScope = false): string {
  if (!result.failOn) return "Gate: not configured";
  const scope = baselineUsed
    ? changedCodeScope ? "new findings in changed-code scope since baseline" : "new findings since baseline"
    : changedCodeScope ? "findings in changed-code scope" : "all findings";
  return result.passed
    ? `Gate: passed — no ${scope} at or above ${result.failOn}`
    : `Gate: failed — ${result.violations.length} ${scope} at or above ${result.failOn}`;
}
