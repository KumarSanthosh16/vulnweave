import { readFile } from "node:fs/promises";
import type { Finding } from "./schemas.js";
import type { RunComparison } from "./run-store.js";

/** A committed snapshot of existing findings used to gate only newly introduced risk. */
export interface FindingBaseline {
  schemaVersion: 1;
  fingerprints: string[];
}

export function buildFindingBaseline(findings: Finding[]): FindingBaseline {
  return { schemaVersion: 1, fingerprints: [...new Set(findings.map(findingKey))].sort() };
}

export async function loadFindingBaseline(path: string): Promise<FindingBaseline> {
  try {
    return validateFindingBaseline(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    throw new Error(`Invalid finding baseline at ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function validateFindingBaseline(value: unknown): FindingBaseline {
  if (!isRecord(value) || value.schemaVersion !== 1 || !Array.isArray(value.fingerprints)) {
    throw new Error("expected schemaVersion 1 and a fingerprints array");
  }
  if (!value.fingerprints.every((fingerprint) => typeof fingerprint === "string" && fingerprint.length > 0)) {
    throw new Error("fingerprints must contain non-empty strings");
  }
  return { schemaVersion: 1, fingerprints: [...new Set(value.fingerprints)].sort() };
}

export function compareFindingsToBaseline(findings: Finding[], baseline: FindingBaseline): RunComparison {
  const baselineKeys = new Set(baseline.fingerprints);
  const currentByKey = new Map(findings.map((finding) => [findingKey(finding), finding]));
  return {
    newFindings: [...currentByKey].filter(([key]) => !baselineKeys.has(key)).map(([, finding]) => finding),
    resolvedFindings: baseline.fingerprints.filter((key) => !currentByKey.has(key)).map(findingFromBaselineKey),
    unchangedFindings: [...currentByKey].filter(([key]) => baselineKeys.has(key)).map(([, finding]) => finding)
  };
}

export function formatFindingBaseline(baseline: FindingBaseline): string {
  return `${JSON.stringify(baseline, null, 2)}\n`;
}

function findingKey(finding: Finding): string {
  return `${finding.analyzer}:${finding.fingerprint ?? finding.id}`;
}

function findingFromBaselineKey(key: string): Finding {
  return { id: key, analyzer: "baseline", ruleId: "baseline", category: "security", severity: "info", title: key, message: "Present in the finding baseline only.", evidence: [] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
