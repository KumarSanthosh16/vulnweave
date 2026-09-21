import type { QualitySignal, QualitySignalKind } from "./code-quality.js";

export interface QualityGatePolicy {
  maxComplexitySignals?: number;
  maxDuplicateCodeSignals?: number;
  maxUnreferencedFiles?: number;
}

export interface QualityGateResult { configured: boolean; passed: boolean; violations: string[]; }

const limits: Array<[keyof QualityGatePolicy, QualitySignalKind, string]> = [
  ["maxComplexitySignals", "high-complexity", "complexity signals"],
  ["maxDuplicateCodeSignals", "duplicate-code", "duplicate-code signals"],
  ["maxUnreferencedFiles", "unreferenced-file", "unreferenced files"]
];

/** Evaluates only an explicitly configured quality policy; it never changes security severity. */
export function evaluateQualityGate(signals: QualitySignal[], policy?: QualityGatePolicy): QualityGateResult {
  if (!policy || Object.keys(policy).length === 0) return { configured: false, passed: true, violations: [] };
  const violations = limits.flatMap(([key, kind, label]) => {
    const maximum = policy[key];
    const count = signals.filter((signal) => signal.kind === kind).length;
    return maximum !== undefined && count > maximum ? [`${count} ${label} exceeds limit ${maximum}`] : [];
  });
  return { configured: true, passed: violations.length === 0, violations };
}

export function formatQualityGate(result: QualityGateResult): string {
  if (!result.configured) return "Quality gate: not configured";
  return result.passed ? "Quality gate: passed" : `Quality gate: failed — ${result.violations.join("; ")}`;
}
