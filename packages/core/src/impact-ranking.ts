import type { Finding } from "./schemas.js";
import type { FindingSymbolLink, ImportRelation } from "./code-symbols.js";
import type { DependencyReachability } from "./dependency-reachability.js";

export interface ImpactAssessment {
  findingId: string;
  score: number;
  tier: "urgent" | "high" | "medium" | "low";
  reasons: string[];
}

/** Deterministic, evidence-backed ordering for triage; it never changes scanner severity. */
export function rankFindings(findings: Finding[], symbolLinks: FindingSymbolLink[], changedFiles: string[] = [], imports: ImportRelation[] = [], dependencyReachability: DependencyReachability[] = []): ImpactAssessment[] {
  const linkedFindings = new Set(symbolLinks.map((link) => link.findingId));
  const changedFileSet = new Set(changedFiles);
  const inbound = imports.reduce<Map<string, number>>((counts, edge) => counts.set(edge.to, (counts.get(edge.to) ?? 0) + 1), new Map());
  const reachabilityByFinding = new Map(dependencyReachability.map((assessment) => [assessment.findingId, assessment]));
  return findings.map((finding) => {
    const reasons = [`${finding.severity} scanner severity`];
    let score = severityScore(finding.severity);
    if (finding.category === "secret") { score += 15; reasons.push("potential credential exposure"); }
    if (finding.category === "dependency") { score += 10; reasons.push("third-party dependency exposure"); }
    const reachability = reachabilityByFinding.get(finding.id);
    if (reachability?.status === "referenced") {
      score += Math.min(15, 5 + reachability.usages.length * 2);
      reasons.push(`statically imported in ${reachability.usages.length} indexed file${reachability.usages.length === 1 ? "" : "s"}`);
    }
    if (linkedFindings.has(finding.id)) { score += 10; reasons.push("mapped to a concrete code symbol"); }
    if (finding.location && changedFileSet.has(finding.location.path)) { score += 15; reasons.push("located in a changed file"); }
    const importCount = finding.location ? inbound.get(finding.location.path) ?? 0 : 0;
    if (importCount) { score += Math.min(10, importCount * 2); reasons.push(`imported by ${importCount} local file${importCount === 1 ? "" : "s"}`); }
    if (finding.evidence.length > 1) { score += 5; reasons.push("multiple supporting evidence items"); }
    const tier: ImpactAssessment["tier"] = score >= 90 ? "urgent" : score >= 65 ? "high" : score >= 35 ? "medium" : "low";
    return { findingId: finding.id, score, tier, reasons };
  }).sort((left, right) => right.score - left.score || left.findingId.localeCompare(right.findingId));
}

function severityScore(severity: Finding["severity"]): number {
  return { critical: 90, high: 65, medium: 40, low: 20, info: 5 }[severity];
}

export function formatPriorityTable(findings: Finding[], assessments: ImpactAssessment[]): string {
  if (assessments.length === 0) return "No findings to prioritize.";
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  const rows = assessments.flatMap((assessment) => {
    const finding = byId.get(assessment.findingId);
    return finding ? [[String(assessment.score), assessment.tier.toUpperCase(), finding.analyzer, finding.ruleId, finding.title, assessment.reasons.join("; ")]] : [];
  });
  const headers = ["SCORE", "TIER", "ANALYZER", "RULE", "TITLE", "WHY"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}
