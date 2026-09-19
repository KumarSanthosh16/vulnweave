import type { AnalyzerAdapter, AnalysisRequest } from "./adapter.js";
import { AnalysisOrchestrator } from "./orchestrator.js";
import type { Finding } from "./schemas.js";

export interface AnalyzerRunStatus {
  analyzerId: string;
  displayName: string;
  status: "completed" | "unavailable" | "failed";
  findings: Finding[];
  error?: string;
}

export interface AnalysisBatchResult {
  findings: Finding[];
  analyzers: AnalyzerRunStatus[];
}

/** Runs independent local analyzers without allowing one failure to discard other evidence. */
export async function runAnalyzers(adapters: AnalyzerAdapter[], request: AnalysisRequest): Promise<AnalysisBatchResult> {
  const analyzers: AnalyzerRunStatus[] = [];
  for (const adapter of adapters) {
    try {
      if (adapter.isAvailable && !(await adapter.isAvailable(request))) {
        analyzers.push({ analyzerId: adapter.id, displayName: adapter.displayName, status: "unavailable", findings: [], error: "Local analyzer executable was not found." });
        continue;
      }
      // The single-run orchestrator owns normalization and its state transitions.
      const result = await new AnalysisOrchestrator().run(adapter, request);
      analyzers.push({ analyzerId: adapter.id, displayName: adapter.displayName, status: "completed", findings: result.findings });
    } catch (error) {
      analyzers.push({ analyzerId: adapter.id, displayName: adapter.displayName, status: "failed", findings: [], error: error instanceof Error ? error.message : String(error) });
    }
  }
  return { analyzers, findings: analyzers.flatMap((run) => run.findings) };
}
