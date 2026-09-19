import type { Finding, FindingCategory, Severity } from "./schemas.js";
import type { AppliedSuppression } from "./suppressions.js";

export interface FindingFilters {
  severity?: Severity;
  category?: FindingCategory;
  analyzer?: string;
}

export function filterFindings(findings: Finding[], filters: FindingFilters): Finding[] {
  return findings.filter((finding) =>
    (!filters.severity || finding.severity === filters.severity) &&
    (!filters.category || finding.category === filters.category) &&
    (!filters.analyzer || finding.analyzer.split("+").includes(filters.analyzer))
  );
}

/** A dependency-free, copyable terminal table for quick local triage. */
export function formatFindingsTable(findings: Finding[], suppressions: AppliedSuppression[] = []): string {
  if (findings.length === 0) return "No findings match the selected filters.";
  const suppressedIds = new Set(suppressions.map((suppression) => suppression.findingId));
  const rows = findings.map((finding) => [
    finding.severity.toUpperCase(),
    suppressedIds.has(finding.id) ? "SUPPRESSED" : "ACTIVE",
    finding.analyzer,
    truncate(finding.ruleId, 28),
    truncate(locationFor(finding), 36),
    truncate(finding.title, 48)
  ]);
  const headers = ["SEVERITY", "STATUS", "ANALYZER", "RULE", "LOCATION", "TITLE"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function locationFor(finding: Finding): string {
  if (finding.location) return `${finding.location.path}:${finding.location.startLine}`;
  const sourcePath = finding.metadata?.sourcePath;
  return typeof sourcePath === "string" ? sourcePath : "—";
}

function truncate(value: string, maximum: number): string {
  return value.length > maximum ? `${value.slice(0, maximum - 1)}…` : value;
}
