import type { AnalyzerRunStatus } from "./batch-orchestrator.js";

export interface AnalyzerHealthResult {
  required: boolean;
  evaluated: number;
  unavailable: AnalyzerRunStatus[];
  failed: AnalyzerRunStatus[];
  passed: boolean;
}

/** Separates scanner-operational health from finding severity gates. */
export function evaluateAnalyzerHealth(analyzers: AnalyzerRunStatus[] | undefined, required = false): AnalyzerHealthResult {
  const runs = analyzers ?? [];
  const unavailable = runs.filter((run) => run.status === "unavailable");
  const failed = runs.filter((run) => run.status === "failed");
  return { required, evaluated: runs.length, unavailable, failed, passed: !required || (unavailable.length === 0 && failed.length === 0) };
}

export function formatAnalyzerHealth(result: AnalyzerHealthResult): string {
  if (!result.required) return "Analyzer health: not required";
  if (result.passed) return `Analyzer health: passed — all ${result.evaluated} required analyzers completed`;
  const problems = [
    result.unavailable.length > 0 ? `unavailable ${result.unavailable.map((run) => run.analyzerId).join(", ")}` : "",
    result.failed.length > 0 ? `failed ${result.failed.map((run) => run.analyzerId).join(", ")}` : ""
  ].filter(Boolean);
  return `Analyzer health: failed — ${problems.join(" | ")}`;
}
