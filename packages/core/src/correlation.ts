import type { Evidence, Finding, Severity } from "./schemas.js";

export interface CorrelationResult {
  findings: Finding[];
  sourceFindingCount: number;
  correlatedGroupCount: number;
}

/**
 * Collapses equivalent dependency advisories reported by separate scanners while
 * retaining every scanner's evidence on the canonical finding. Other findings
 * remain one-to-one so correlation is conservative by default.
 */
export function correlateFindings(findings: Finding[]): CorrelationResult {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = correlationKey(finding) ?? `finding:${finding.id}`;
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }
  const correlated = [...groups.values()].map((group) => group.length === 1 ? group[0]! : mergeGroup(group));
  return {
    findings: correlated,
    sourceFindingCount: findings.length,
    correlatedGroupCount: [...groups.values()].filter((group) => group.length > 1).length
  };
}

function correlationKey(finding: Finding): string | undefined {
  if (finding.category !== "dependency") return undefined;
  const packageName = finding.metadata?.package;
  if (typeof packageName !== "string" || packageName.length === 0) return undefined;
  const advisory = advisoryKeys(finding)[0];
  return advisory ? `dependency:${packageName.toLowerCase()}:${advisory}` : undefined;
}

function advisoryKeys(finding: Finding): string[] {
  const aliases = typeof finding.metadata?.aliases === "string" ? finding.metadata.aliases.split(",") : [];
  const values = [finding.ruleId, ...aliases].map((value) => value.trim().toUpperCase()).filter(Boolean);
  return [...new Set(values)].sort((left, right) => advisoryPriority(left) - advisoryPriority(right) || left.localeCompare(right));
}

function advisoryPriority(value: string): number {
  if (value.startsWith("CVE-")) return 0;
  if (value.startsWith("GHSA-")) return 1;
  return 2;
}

function mergeGroup(group: Finding[]): Finding {
  const ordered = [...group].sort((left, right) => severityValue(right.severity) - severityValue(left.severity) || left.id.localeCompare(right.id));
  const primary = ordered[0]!;
  const analyzerIds = [...new Set(group.map((finding) => finding.analyzer))].sort();
  const evidence = group.flatMap((finding) => finding.evidence.map((item) => annotateEvidence(item, finding.analyzer)));
  const references = [...new Set(group.flatMap((finding) => finding.references ?? []))];
  const fixedVersion = group.map((finding) => finding.metadata?.fixedVersion).find((value): value is string => typeof value === "string" && value.length > 0);
  const advisory = advisoryKeys(primary)[0] ?? primary.ruleId;
  return {
    ...primary,
    id: `correlated:${primary.category}:${primary.metadata?.package ?? "global"}:${advisory}`,
    analyzer: analyzerIds.join("+"),
    ruleId: advisory,
    fingerprint: `correlated:${primary.category}:${primary.metadata?.package ?? "global"}:${advisory}`,
    evidence,
    references: references.length > 0 ? references : undefined,
    metadata: {
      ...primary.metadata,
      ...(fixedVersion ? { fixedVersion } : {}),
      analyzers: analyzerIds.join(","),
      observationCount: group.length,
      sourceFindingIds: group.map((finding) => finding.id).sort().join(",")
    }
  };
}

function annotateEvidence(evidence: Evidence, analyzer: string): Evidence {
  return { ...evidence, metadata: { ...evidence.metadata, analyzer } };
}

function severityValue(severity: Severity): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}
