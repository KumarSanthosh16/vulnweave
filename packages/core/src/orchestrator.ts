import type { AnalyzerAdapter, AnalysisRequest } from "./adapter.js";
import { assertValidFinding, type Finding, type FindingInput } from "./schemas.js";

export type AnalysisPhase = "idle" | "preparing" | "running" | "normalizing" | "completed" | "failed" | "cancelled";

export interface AnalysisState {
  phase: AnalysisPhase;
  analyzerId?: string;
  findings: Finding[];
  error?: string;
}

export interface AnalysisResult {
  state: AnalysisState;
  findings: Finding[];
}

export class AnalysisOrchestrator {
  private state: AnalysisState = { phase: "idle", findings: [] };

  getState(): Readonly<AnalysisState> { return this.state; }

  async run(adapter: AnalyzerAdapter, request: AnalysisRequest): Promise<AnalysisResult> {
    this.transition("preparing", { analyzerId: adapter.id, findings: [] });
    try {
      if (adapter.isAvailable && !(await adapter.isAvailable(request))) {
        throw new Error(`Analyzer '${adapter.id}' is unavailable`);
      }
      this.transition("running");
      const inputs = await adapter.analyze(request);
      if (this.state.phase === "cancelled") return { state: this.state, findings: [] };
      this.transition("normalizing");
      const findings = inputs.map((input, index) => normalizeFinding(adapter.id, input, index));
      this.transition("completed", { findings });
      return { state: this.state, findings };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.transition("failed", { error: message });
      throw error;
    }
  }

  cancel(): void {
    if (this.state.phase === "running" || this.state.phase === "preparing") this.transition("cancelled");
  }

  private transition(phase: AnalysisPhase, patch: Partial<AnalysisState> = {}): void {
    this.state = { ...this.state, ...patch, phase };
  }
}

function normalizeFinding(analyzer: string, input: FindingInput, index: number): Finding {
  const finding: Finding = {
    ...input,
    id: input.id ?? `${analyzer}:${input.ruleId}:${input.location?.path ?? "global"}:${input.location?.startLine ?? index + 1}`,
    analyzer,
    evidence: input.evidence ?? []
  };
  return assertValidFinding(finding);
}
