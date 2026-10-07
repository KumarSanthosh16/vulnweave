import type { ScanRecord } from "./run-store.js";

/** Renders a safe GitHub Actions step summary from an already-saved local scan. */
export function toGitHubStepSummary(record: ScanRecord): string {
  const active = record.remediationPlan?.filter((item) => item.status === "active") ?? [];
  const accepted = record.remediationPlan?.filter((item) => item.status === "accepted-risk") ?? [];
  const gate = record.gate?.passed === false ? "needs review" : "passed";
  const analyzerHealth = record.analyzerHealth?.passed === false ? "needs review" : "passed";
  const scope = record.changeImpact?.reference
    ? `Changed-code review against \`${markdown(record.changeImpact.reference)}\`: ${record.changeImpact.changedFiles.length} changed file(s), ${record.changeImpact.directlyChangedFindings.length + record.changeImpact.importAffectedFindings.length} finding(s) in scope.`
    : "Full repository scan; no changed-code scope was requested.";
  const lines = [
    "## VulnWeave remediation summary",
    "",
    `**Security gate:** ${gate}  \\`,
    `**Analyzer health:** ${analyzerHealth}  \\`,
    `**Canonical findings:** ${record.findings.length}  \\`,
    `**Active work items:** ${active.length} · **Accepted risks:** ${accepted.length}`,
    "",
    scope,
    "",
    "### Highest-priority work"
  ];
  if (active.length === 0) {
    lines.push("No active finding requires remediation in this scan.");
  } else {
    lines.push("| Severity | Owners | Finding | Next step |", "| --- | --- | --- | --- |");
    for (const item of active.slice(0, 10)) {
      lines.push(`| ${item.severity.toUpperCase()} | ${markdown(item.owners.join(", ") || "Unassigned")} | ${markdown(item.title)} | ${markdown(summaryAction(item))} |`);
    }
  }
  if (accepted.length > 0) {
    lines.push("", "### Accepted risks", "| Expiry | Owner | Finding | Reason |", "| --- | --- | --- | --- |");
    for (const item of accepted.slice(0, 10)) {
      lines.push(`| ${markdown(item.acceptance?.expiresOn ?? "Review required")} | ${markdown(item.acceptance?.owner ?? "Unassigned")} | ${markdown(item.title)} | ${markdown(item.acceptance?.reason ?? "Accepted risk")} |`);
    }
  }
  lines.push("", "The full local HTML report and SARIF export are available as workflow artifacts when configured. VulnWeave does not modify source code, dependencies, or policy files.");
  return `${lines.join("\n")}\n`;
}

function summaryAction(item: NonNullable<ScanRecord["remediationPlan"]>[number]): string {
  if (item.upgrade?.targetVersion) return `Upgrade ${item.upgrade.packageName} to ${item.upgrade.targetVersion}, then verify.`;
  return item.action;
}

function markdown(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("|", "\\|").replaceAll("\r", " ").replaceAll("\n", " ");
}
