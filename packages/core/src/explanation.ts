import type { CodeSymbol, FindingSymbolLink } from "./code-symbols.js";
import type { ImpactAssessment } from "./impact-ranking.js";
import type { DependencyReachability } from "./dependency-reachability.js";
import type { Finding } from "./schemas.js";

export function formatFindingExplanation(finding: Finding, assessment?: ImpactAssessment, symbols: CodeSymbol[] = [], links: FindingSymbolLink[] = [], changedFiles: string[] = [], dependencyReachability: DependencyReachability[] = []): string {
  const symbolId = links.find((link) => link.findingId === finding.id)?.symbolId;
  const symbol = symbols.find((candidate) => candidate.id === symbolId);
  const location = finding.location ? `${finding.location.path}:${finding.location.startLine}:${finding.location.startColumn}` : "No source location provided";
  const lines = [
    `Finding: ${finding.title}`,
    `ID: ${finding.id}`,
    `Severity: ${finding.severity.toUpperCase()} | Category: ${finding.category} | Analyzer: ${finding.analyzer}`,
    `Rule: ${finding.ruleId}`,
    `Location: ${location}`,
    `What was found: ${finding.message}`,
    `Evidence: ${finding.evidence.length === 0 ? "No supplemental evidence supplied." : finding.evidence.map((evidence) => evidence.summary).join(" | ")}`,
    `Code context: ${symbol ? `${symbol.kind} ${symbol.name} (${symbol.path}:${symbol.line})` : "No enclosing indexed symbol."}`,
    `Change context: ${finding.location && changedFiles.includes(finding.location.path) ? "This location is in a changed file." : "No changed-file signal."}`,
    `Dependency reachability: ${describeReachability(dependencyReachability.find((item) => item.findingId === finding.id))}`,
    `Priority: ${assessment ? `${assessment.tier.toUpperCase()} (${assessment.score}) — ${assessment.reasons.join("; ")}` : "Not assessed."}`,
    "Suggested next step: Verify the evidence at the location, assess reachability and intended use, then apply the analyzer-specific remediation and re-run the scan."
  ];
  return lines.join("\n");
}

function describeReachability(reachability: DependencyReachability | undefined): string {
  if (!reachability) return "Not applicable or no package identity supplied.";
  if (reachability.status === "referenced") return `${reachability.packageName} is statically imported in ${reachability.usages.length} indexed file${reachability.usages.length === 1 ? "" : "s"}.`;
  return `No indexed JavaScript/TypeScript import of ${reachability.packageName} was observed; this is not proof of runtime unreachability.`;
}
