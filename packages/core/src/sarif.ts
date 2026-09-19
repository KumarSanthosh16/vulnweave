import type { Finding } from "./schemas.js";

export interface SarifLog { version: "2.1.0"; $schema: string; runs: Array<Record<string, unknown>>; }

/** Converts normalized VulnWeave findings into a self-contained SARIF 2.1.0 log. */
export function toSarif(findings: Finding[]): SarifLog {
  const ruleMap = new Map<string, Finding>();
  for (const finding of findings) ruleMap.set(ruleKey(finding), finding);
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "VulnWeave", informationUri: "https://example.invalid/vulnweave", rules: [...ruleMap.values()].map((finding) => ({ id: ruleKey(finding), shortDescription: { text: finding.title }, properties: { analyzer: finding.analyzer, category: finding.category, severity: finding.severity } })) } },
      results: findings.map((finding) => ({
        ruleId: ruleKey(finding),
        level: finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "note",
        message: { text: finding.message },
        partialFingerprints: { vulnweaveFindingId: finding.id },
        ...(finding.location ? { locations: [{ physicalLocation: { artifactLocation: { uri: finding.location.path }, region: { startLine: finding.location.startLine, startColumn: finding.location.startColumn, endLine: finding.location.endLine, endColumn: finding.location.endColumn } } }] } : {})
      }))
    }]
  };
}

function ruleKey(finding: Finding): string { return `${finding.analyzer}/${finding.ruleId}`; }
