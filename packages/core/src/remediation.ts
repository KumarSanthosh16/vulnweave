import type { DependencyReachability } from "./dependency-reachability.js";
import type { Finding } from "./schemas.js";

/** Deterministic next-step guidance derived only from normalized scanner evidence. */
export interface RemediationAdvice {
  findingId: string;
  action: string;
  verification: string;
  rationale: string;
}

export function buildRemediationAdvice(findings: Finding[], dependencyReachability: DependencyReachability[] = []): RemediationAdvice[] {
  const reachabilityByFinding = new Map(dependencyReachability.map((item) => [item.findingId, item]));
  return findings.map((finding) => remediationFor(finding, reachabilityByFinding.get(finding.id)));
}

export function formatRemediationTable(findings: Finding[], advice: RemediationAdvice[]): string {
  if (advice.length === 0) return "No findings need remediation guidance.";
  const findingsById = new Map(findings.map((finding) => [finding.id, finding]));
  const rows = advice.flatMap((item) => {
    const finding = findingsById.get(item.findingId);
    return finding ? [[finding.severity.toUpperCase(), finding.analyzer, finding.title, item.action, item.verification]] : [];
  });
  const headers = ["SEVERITY", "ANALYZER", "FINDING", "NEXT ACTION", "VERIFY"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function remediationFor(finding: Finding, reachability: DependencyReachability | undefined): RemediationAdvice {
  const location = finding.location ? `${finding.location.path}:${finding.location.startLine}` : "the scanner-reported location";
  if (finding.category === "dependency") {
    const packageName = metadataText(finding, "package") ?? "the affected package";
    const version = metadataText(finding, "version");
    const fixedVersion = metadataText(finding, "fixedVersion");
    const versionText = version && version !== "unknown" ? ` from ${version}` : "";
    const target = fixedVersion ? ` to ${fixedVersion} or later` : " to a non-affected version identified by the advisory";
    const reachabilityText = reachability?.status === "referenced"
      ? `Static imports were observed in ${reachability.usages.length} indexed file${reachability.usages.length === 1 ? "" : "s"}.`
      : "No indexed JavaScript/TypeScript import was observed; review other languages, dynamic loading, and deployment use before deprioritizing.";
    return { findingId: finding.id, action: `Upgrade ${packageName}${versionText}${target}, then review compatibility changes.`, verification: `Reinstall dependencies, re-run VulnWeave, and run the affected application's tests.`, rationale: reachabilityText };
  }
  if (finding.category === "secret") {
    return { findingId: finding.id, action: "Treat the value as exposed: revoke or rotate it at its issuer, then remove it from code and move it to approved secret storage.", verification: "Confirm the old credential no longer authenticates, then re-run Gitleaks.", rationale: "VulnWeave intentionally does not retain the secret value in its report." };
  }
  if (finding.category === "infrastructure") {
    return { findingId: finding.id, action: `Review and correct the configuration at ${location} according to the reported rule.`, verification: "Re-run Trivy and validate the deployed configuration through the normal environment review.", rationale: "Configuration findings may affect runtime behavior even when source imports are absent." };
  }
  if (finding.category === "quality") {
    return { findingId: finding.id, action: `Review the code at ${location} and make the rule-compliant change.`, verification: "Add or update a focused regression test, then re-run the analyzer.", rationale: "The recommendation is based on the analyzer's reported rule and location." };
  }
  return { findingId: finding.id, action: `Review the code at ${location} and replace or constrain the reported risky behavior.`, verification: "Add a regression test for the safe behavior, then re-run Semgrep or the reporting analyzer.", rationale: "The recommendation is based on the normalized rule, location, and scanner evidence." };
}

function metadataText(finding: Finding, key: string): string | undefined {
  const value = finding.metadata?.[key];
  return typeof value === "string" || typeof value === "number" ? String(value) : undefined;
}
