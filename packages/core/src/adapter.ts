import type { FindingInput } from "./schemas.js";

export interface AnalysisRequest {
  rootDir: string;
  paths?: string[];
  config?: Record<string, unknown>;
}

/**
 * The only contract an analyzer integration implements. Adapters own conversion
 * from tool-specific output (SARIF, JSON, CLI text) into FindingInput.
 */
export interface AnalyzerAdapter {
  readonly id: string;
  readonly displayName: string;
  isAvailable?(request: AnalysisRequest): Promise<boolean>;
  analyze(request: AnalysisRequest): Promise<FindingInput[]>;
}
