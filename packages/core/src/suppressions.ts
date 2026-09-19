import type { Finding } from "./schemas.js";

/** A reviewed, time-bounded exception keyed to an analyzer-stable fingerprint. */
export interface FindingSuppression {
  fingerprint: string;
  reason: string;
  owner: string;
  expiresOn: string;
}

export interface AppliedSuppression extends FindingSuppression { findingId: string; }

export interface SuppressionResult {
  activeFindings: Finding[];
  suppressed: AppliedSuppression[];
  expired: FindingSuppression[];
}

export function applySuppressions(findings: Finding[], suppressions: FindingSuppression[], now = new Date()): SuppressionResult {
  const activeRules = suppressions.filter((rule) => !isExpired(rule, now));
  const expired = suppressions.filter((rule) => isExpired(rule, now));
  const byFingerprint = new Map(activeRules.map((rule) => [rule.fingerprint, rule]));
  const suppressed: AppliedSuppression[] = [];
  const activeFindings = findings.filter((finding) => {
    const rule = finding.fingerprint ? byFingerprint.get(finding.fingerprint) : undefined;
    if (!rule) return true;
    suppressed.push({ ...rule, findingId: finding.id });
    return false;
  });
  return { activeFindings, suppressed, expired };
}

function isExpired(rule: FindingSuppression, now: Date): boolean {
  return new Date(`${rule.expiresOn}T23:59:59.999Z`).getTime() < now.getTime();
}
