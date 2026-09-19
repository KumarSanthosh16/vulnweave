import type { AnalyzerAdapter, AnalysisRequest, FindingInput } from "@vulnweave/core";

/** A deterministic fixture adapter proving the full pipeline without a scanner binary. */
export class MockAnalyzer implements AnalyzerAdapter {
  readonly id = "mock";
  readonly displayName = "Mock analyzer";

  async analyze(_request: AnalysisRequest): Promise<FindingInput[]> {
    return [{
      ruleId: "demo.insecure-log",
      category: "security",
      severity: "medium",
      title: "Potential sensitive value logged",
      message: "Mock result used to validate the integration pipeline.",
      location: { path: "src/example.ts", startLine: 12, startColumn: 3 },
      evidence: [{ id: "mock:source:1", kind: "source", summary: "console.log(token)", excerpt: "console.log(token)" }]
    }];
  }
}
