import type { DependencyUsage } from "./code-symbols.js";
import type { Finding } from "./schemas.js";

export interface DependencyReachability {
  findingId: string;
  packageName: string;
  status: "referenced" | "not-observed";
  usages: DependencyUsage[];
}

/**
 * Relates dependency findings to static JS/TS imports. A missing import is
 * deliberately reported as "not observed", not as runtime-unreachable.
 */
export function assessDependencyReachability(findings: Finding[], usages: DependencyUsage[]): DependencyReachability[] {
  return findings.flatMap((finding) => {
    if (finding.category !== "dependency") return [];
    const packageName = typeof finding.metadata?.package === "string" ? finding.metadata.package : undefined;
    if (!packageName) return [];
    const matchingUsages = usages.filter((usage) => usage.packageName.toLowerCase() === packageName.toLowerCase());
    return [{ findingId: finding.id, packageName, status: matchingUsages.length > 0 ? "referenced" : "not-observed", usages: matchingUsages }];
  });
}

export function formatDependencyReachability(assessments: DependencyReachability[]): string {
  if (assessments.length === 0) return "No dependency findings to assess.";
  const rows = assessments.map((assessment) => [assessment.status.toUpperCase(), assessment.packageName, String(assessment.usages.length), assessment.usages.map((usage) => `${usage.path}:${usage.line}`).join(", ") || "No indexed JS/TS import observed"]);
  const headers = ["STATUS", "PACKAGE", "IMPORTS", "STATIC EVIDENCE"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return ["Dependency reachability (static imports only; not runtime proof)", render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}
