import type { Finding } from "./schemas.js";
import type { FindingOwnership } from "./ownership.js";
import type { RemediationAdvice } from "./remediation.js";
import type { DependencyUpgradePlan } from "./upgrade-plan.js";
import type { AppliedSuppression } from "./suppressions.js";

/** A deterministic, non-mutating work queue assembled from scanner evidence. */
export interface RemediationPlanItem {
  findingId: string;
  severity: Finding["severity"];
  status: "active" | "accepted-risk";
  owners: string[];
  title: string;
  location?: string;
  action: string;
  verification: string;
  upgrade?: Pick<DependencyUpgradePlan, "packageName" | "installedVersion" | "targetVersion" | "status" | "sourcePath">;
  acceptance?: Pick<AppliedSuppression, "reason" | "owner" | "expiresOn">;
}

/**
 * Creates a review-ready queue. Accepted risks remain visible and retain their
 * expiry; this function never changes dependencies, source code, or policy.
 */
export function buildRemediationPlan(
  findings: Finding[],
  advice: RemediationAdvice[],
  ownership: FindingOwnership[] = [],
  upgrades: DependencyUpgradePlan[] = [],
  suppressions: AppliedSuppression[] = []
): RemediationPlanItem[] {
  const adviceByFinding = new Map(advice.map((item) => [item.findingId, item]));
  const ownersByFinding = new Map(ownership.map((item) => [item.findingId, item.owners]));
  const upgradesByFinding = new Map(upgrades.map((item) => [item.findingId, item]));
  const suppressionsByFinding = new Map(suppressions.map((item) => [item.findingId, item]));
  return findings.map((finding): RemediationPlanItem => {
    const remediation = adviceByFinding.get(finding.id);
    const suppression = suppressionsByFinding.get(finding.id);
    const upgrade = upgradesByFinding.get(finding.id);
    return {
      findingId: finding.id,
      severity: finding.severity,
      status: suppression ? "accepted-risk" : "active",
      owners: ownersByFinding.get(finding.id) ?? [],
      title: finding.title,
      location: finding.location ? `${finding.location.path}:${finding.location.startLine}` : undefined,
      action: remediation?.action ?? "Review the scanner evidence and assign a safe next step.",
      verification: remediation?.verification ?? "Re-run VulnWeave after completing the review.",
      ...(upgrade ? { upgrade: pickUpgrade(upgrade) } : {}),
      ...(suppression ? { acceptance: { reason: suppression.reason, owner: suppression.owner, expiresOn: suppression.expiresOn } } : {})
    };
  }).sort(comparePlanItems);
}

export function formatRemediationPlan(items: RemediationPlanItem[]): string {
  if (items.length === 0) return "No findings need a remediation plan.";
  const headers = ["SEVERITY", "STATUS", "OWNERS", "LOCATION", "FINDING", "NEXT STEP"];
  const rows = items.map((item) => [
    item.severity.toUpperCase(),
    item.status === "active" ? "ACTIVE" : `ACCEPTED UNTIL ${item.acceptance?.expiresOn ?? "review"}`,
    item.owners.join(", ") || "Unassigned",
    item.location ?? "—",
    item.title,
    planAction(item)
  ]);
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [
    "Remediation plan (advisory; no files or policies are changed)",
    render(headers),
    render(widths.map((width) => "-".repeat(width))),
    ...rows.map(render)
  ].join("\n");
}

function pickUpgrade(upgrade: DependencyUpgradePlan): RemediationPlanItem["upgrade"] {
  return {
    packageName: upgrade.packageName,
    ...(upgrade.installedVersion ? { installedVersion: upgrade.installedVersion } : {}),
    ...(upgrade.targetVersion ? { targetVersion: upgrade.targetVersion } : {}),
    status: upgrade.status,
    ...(upgrade.sourcePath ? { sourcePath: upgrade.sourcePath } : {})
  };
}

function planAction(item: RemediationPlanItem): string {
  if (item.acceptance) return `${item.acceptance.reason} (owner: ${item.acceptance.owner})`;
  if (item.upgrade?.targetVersion) return `Upgrade ${item.upgrade.packageName} to ${item.upgrade.targetVersion}; then verify.`;
  return item.action;
}

function comparePlanItems(left: RemediationPlanItem, right: RemediationPlanItem): number {
  const severity = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  return severity[left.severity] - severity[right.severity]
    || Number(left.status === "accepted-risk") - Number(right.status === "accepted-risk")
    || left.title.localeCompare(right.title)
    || left.findingId.localeCompare(right.findingId);
}
