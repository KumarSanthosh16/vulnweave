import type { ImpactAssessment } from "./impact-ranking.js";
import { findingsInChangeScope, formatChangeImpact, type ChangeImpact } from "./impact-surface.js";
import type { FindingOwnership } from "./ownership.js";
import type { RemediationAdvice } from "./remediation.js";
import type { ScanRecord } from "./run-store.js";

/** A concise, copyable pull-request review brief derived from stored local evidence. */
export function formatReviewPacket(record: ScanRecord, impact: ChangeImpact, ownership: FindingOwnership[], remediation: RemediationAdvice[], assessments: ImpactAssessment[]): string {
  const scoped = findingsInChangeScope(impact);
  const direct = new Set(impact.directlyChangedFindings.map((finding) => finding.id));
  const ownersByFinding = new Map(ownership.map((item) => [item.findingId, item.owners]));
  const remediationByFinding = new Map(remediation.map((item) => [item.findingId, item]));
  const assessmentByFinding = new Map(assessments.map((item) => [item.findingId, item]));
  const lines = ["VulnWeave review packet", formatChangeImpact(impact)];
  if (scoped.length === 0) {
    lines.push("Review findings: none in the changed-code scope.");
    return lines.join("\n");
  }
  const rows = scoped.map((finding) => {
    const advice = remediationByFinding.get(finding.id);
    const assessment = assessmentByFinding.get(finding.id);
    return [direct.has(finding.id) ? "DIRECT" : "DEPENDENT", finding.severity.toUpperCase(), String(assessment?.score ?? 0), ownersByFinding.get(finding.id)?.join(", ") || "Unassigned", finding.title, advice?.action ?? "Review scanner evidence."];
  });
  const headers = ["SCOPE", "SEVERITY", "SCORE", "OWNERS", "FINDING", "NEXT ACTION"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  lines.push("Review findings:", render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render));
  return lines.join("\n");
}
