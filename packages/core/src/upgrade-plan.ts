import type { DependencyReachability } from "./dependency-reachability.js";
import type { Finding } from "./schemas.js";
import { pythonDependencyUpdateGuidance } from "./dependency-guidance.js";

export interface DependencyUpgradePlan {
  findingId: string;
  packageName: string;
  installedVersion?: string;
  targetVersion?: string;
  status: "upgrade-available" | "manual-advisory-review";
  staticImportCount: number;
  severity: Finding["severity"];
  advisoryIds: string[];
  sourcePath?: string;
  ecosystem?: string;
  recommendedChange: string;
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
    const sourcePath = textMetadata(finding, "sourcePath") || textMetadata(finding, "target") || undefined;
    const ecosystem = textMetadata(finding, "ecosystem") || undefined;
    return [{
      findingId: finding.id,
      packageName,
      installedVersion: textMetadata(finding, "version") || undefined,
      targetVersion,
      status,
      staticImportCount: reachabilityByFinding.get(finding.id)?.usages.length ?? 0,
      severity: finding.severity,
      advisoryIds: advisoryIds(finding),
      sourcePath,
      ecosystem,
      recommendedChange: recommendedChange(packageName, targetVersion, sourcePath, ecosystem)
    }];
  }).sort((left, right) => left.packageName.localeCompare(right.packageName) || left.findingId.localeCompare(right.findingId));
}

export function formatDependencyUpgradePlan(plans: DependencyUpgradePlan[]): string {
  if (plans.length === 0) return "No dependency findings need an upgrade plan.";
  const rows = plans.map((plan) => [plan.severity.toUpperCase(), plan.status === "upgrade-available" ? "UPGRADE" : "REVIEW", plan.packageName, plan.installedVersion ?? "unknown", plan.targetVersion ?? "Check advisory", plan.advisoryIds.join(",") || "Scanner advisory", plan.sourcePath ?? "Unknown manifest", String(plan.staticImportCount), plan.recommendedChange]);
  const headers = ["SEVERITY", "ACTION", "PACKAGE", "CURRENT", "TARGET", "ADVISORY", "MANIFEST", "IMPORTS", "RECOMMENDED CHANGE"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return ["Dependency upgrade plan (advisory; no files are changed)", render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function advisoryIds(finding: Finding): string[] {
  return [...new Set([finding.ruleId, ...(finding.references ?? [])].filter((value) => value.length > 0))];
}

function textMetadata(finding: Finding, key: string): string {
  const value = finding.metadata?.[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function recommendedChange(packageName: string, targetVersion: string | undefined, sourcePath: string | undefined, ecosystem: string | undefined): string {
  if (!targetVersion) return "Review the advisory for a safe target version; VulnWeave does not guess one.";
  const pythonGuidance = pythonDependencyUpdateGuidance(packageName, targetVersion, sourcePath, ecosystem);
  if (pythonGuidance) return pythonGuidance;
  const manifest = sourcePath ?? "the declared dependency manifest";
  if (ecosystem === "npm" || /(?:package-lock\.json|npm-shrinkwrap\.json|package\.json)$/i.test(manifest)) {
    return `Update ${packageName} in the package manifest, regenerate the lockfile, then review compatibility.`;
  }
  return `Update ${packageName} in ${manifest} to ${targetVersion} or later, then re-run tests and VulnWeave.`;
}
