import type { DependencyReachability } from "./dependency-reachability.js";
import type { Finding } from "./schemas.js";

export interface DependencyUpgradePlan {
  findingId: string;
  packageName: string;
  installedVersion?: string;
  targetVersion?: string;
  status: "upgrade-available" | "manual-advisory-review";
  staticImportCount: number;
}

/** Builds a non-mutating dependency plan from scanner-reported versions only. */
export function buildDependencyUpgradePlan(findings: Finding[], reachability: DependencyReachability[] = []): DependencyUpgradePlan[] {
  const reachabilityByFinding = new Map(reachability.map((item) => [item.findingId, item]));
  return findings.flatMap((finding) => {
    if (finding.category !== "dependency") return [];
    const packageName = textMetadata(finding, "package");
    if (!packageName) return [];
    const targetVersion = textMetadata(finding, "fixedVersion") || undefined;
    const status: DependencyUpgradePlan["status"] = targetVersion ? "upgrade-available" : "manual-advisory-review";
    return [{
      findingId: finding.id,
      packageName,
      installedVersion: textMetadata(finding, "version") || undefined,
      targetVersion,
      status,
      staticImportCount: reachabilityByFinding.get(finding.id)?.usages.length ?? 0
    }];
  }).sort((left, right) => left.packageName.localeCompare(right.packageName) || left.findingId.localeCompare(right.findingId));
}

export function formatDependencyUpgradePlan(plans: DependencyUpgradePlan[]): string {
  if (plans.length === 0) return "No dependency findings need an upgrade plan.";
  const rows = plans.map((plan) => [plan.status === "upgrade-available" ? "UPGRADE" : "REVIEW", plan.packageName, plan.installedVersion ?? "unknown", plan.targetVersion ?? "Check advisory", String(plan.staticImportCount), plan.status === "upgrade-available" ? "Upgrade, review compatibility, then re-run tests and VulnWeave." : "Review the advisory for a safe target version, then re-run tests and VulnWeave."]);
  const headers = ["ACTION", "PACKAGE", "CURRENT", "TARGET", "IMPORTS", "NEXT STEP"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return ["Dependency upgrade plan (advisory; no files are changed)", render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function textMetadata(finding: Finding, key: string): string {
  const value = finding.metadata?.[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}
