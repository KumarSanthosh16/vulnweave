import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import type { Finding } from "./schemas.js";
import type { AnalyzerRunStatus } from "./batch-orchestrator.js";
import { buildEvidenceGraph } from "./evidence-graph.js";
import type { CodeSymbol, DependencyUsage, FindingSymbolLink, ImportRelation } from "./code-symbols.js";
import type { DependencyReachability } from "./dependency-reachability.js";
import type { ImpactAssessment } from "./impact-ranking.js";
import type { GateResult } from "./gate-policy.js";
import type { AnalyzerHealthResult } from "./analyzer-health.js";
import type { AppliedSuppression } from "./suppressions.js";
import type { ChangeImpact } from "./impact-surface.js";
import type { RemediationAdvice } from "./remediation.js";
import type { FindingOwnership } from "./ownership.js";
import type { DependencyUpgradePlan } from "./upgrade-plan.js";
import type { QualitySignal } from "./code-quality.js";
import type { QualityGateResult } from "./quality-gate.js";

export interface ScanRecord {
  schemaVersion: 1;
  id: string;
  startedAt: string;
  completedAt: string;
  rootDir: string;
  analyzerId: string;
  findings: Finding[];
  /** Number of raw scanner observations before optional correlation. */
  sourceFindingCount?: number;
  analyzers?: AnalyzerRunStatus[];
  symbols?: CodeSymbol[];
  symbolLinks?: FindingSymbolLink[];
  impactAssessments?: ImpactAssessment[];
  changedPaths?: string[];
  imports?: ImportRelation[];
  dependencyUsages?: DependencyUsage[];
  dependencyReachability?: DependencyReachability[];
  remediation?: RemediationAdvice[];
  ownership?: FindingOwnership[];
  dependencyUpgradePlan?: DependencyUpgradePlan[];
  gate?: GateResult;
  analyzerHealth?: AnalyzerHealthResult;
  suppressions?: AppliedSuppression[];
  changeImpact?: ChangeImpact;
  qualitySignals?: QualitySignal[];
  qualityGate?: QualityGateResult;
}

export interface RunComparison {
  newFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
}

const stateDirectory = ".vulnweave";
const legacyStateDirectory = ".signal-impact";

export async function saveScanRecord(input: Omit<ScanRecord, "schemaVersion" | "id" | "completedAt">): Promise<ScanRecord> {
  const record: ScanRecord = { ...input, schemaVersion: 1, id: `${Date.now()}-${randomUUID()}`, completedAt: new Date().toISOString() };
  const runsDir = join(record.rootDir, stateDirectory, "runs");
  await mkdir(runsDir, { recursive: true });
  const serialized = `${JSON.stringify(record, null, 2)}\n`;
  await writeFile(join(runsDir, `${record.id}.json`), serialized, "utf8");
  await writeFile(join(record.rootDir, stateDirectory, "latest.json"), serialized, "utf8");
  const graphsDir = join(record.rootDir, stateDirectory, "graphs");
  await mkdir(graphsDir, { recursive: true });
  await writeFile(join(graphsDir, `${record.id}.json`), `${JSON.stringify(buildEvidenceGraph(record), null, 2)}\n`, "utf8");
  return record;
}

export async function loadScanRecord(rootDir: string, idOrLatest: string): Promise<ScanRecord> {
  const relativePath = idOrLatest === "latest" ? "latest.json" : join("runs", `${idOrLatest}.json`);
  try {
    return JSON.parse(await readFile(join(rootDir, stateDirectory, relativePath), "utf8")) as ScanRecord;
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
    // Retain reports created before the VulnWeave rename.
    return JSON.parse(await readFile(join(rootDir, legacyStateDirectory, relativePath), "utf8")) as ScanRecord;
  }
}

/** Reads recent valid local reports, newest first, while tolerating a malformed old report. */
export async function listScanRecords(rootDir: string, limit = 10): Promise<ScanRecord[]> {
  const readRuns = async (stateDir: string): Promise<ScanRecord[]> => {
    const entries = await readdir(join(rootDir, stateDir, "runs"), { withFileTypes: true });
    const files = entries.filter((entry) => entry.isFile() && entry.name.endsWith(".json")).map((entry) => entry.name).sort().reverse().slice(0, limit);
    const records = await Promise.all(files.map(async (file) => {
      try { return JSON.parse(await readFile(join(rootDir, stateDir, "runs", file), "utf8")) as ScanRecord; } catch { return undefined; }
    }));
    return records.filter((record): record is ScanRecord => record !== undefined);
  };
  try { return await readRuns(stateDirectory); } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
    try { return await readRuns(legacyStateDirectory); } catch (legacyError) {
      if (legacyError instanceof Error && "code" in legacyError && legacyError.code === "ENOENT") return [];
      throw legacyError;
    }
  }
}

export function compareScanRecords(current: Pick<ScanRecord, "findings">, previous: Pick<ScanRecord, "findings">): RunComparison {
  const currentByKey = new Map(current.findings.map((finding) => [findingKey(finding), finding]));
  const previousByKey = new Map(previous.findings.map((finding) => [findingKey(finding), finding]));
  return {
    newFindings: [...currentByKey].filter(([key]) => !previousByKey.has(key)).map(([, finding]) => finding),
    resolvedFindings: [...previousByKey].filter(([key]) => !currentByKey.has(key)).map(([, finding]) => finding),
    unchangedFindings: [...currentByKey].filter(([key]) => previousByKey.has(key)).map(([, finding]) => finding)
  };
}

export function formatScanSummary(record: ScanRecord, comparison?: RunComparison): string {
  const bySeverity = record.findings.reduce<Record<string, number>>((totals, finding) => {
    totals[finding.severity] = (totals[finding.severity] ?? 0) + 1;
    return totals;
  }, {});
  const lines = [
    `VulnWeave scan: ${record.analyzerId}`,
    `Findings: ${record.findings.length}`,
    `Severity: critical ${bySeverity.critical ?? 0} | high ${bySeverity.high ?? 0} | medium ${bySeverity.medium ?? 0} | low ${bySeverity.low ?? 0} | info ${bySeverity.info ?? 0}`,
    `Run: ${record.id}`
  ];
  if (record.sourceFindingCount !== undefined && record.sourceFindingCount !== record.findings.length) {
    lines.push(`Correlation: ${record.sourceFindingCount} scanner observations → ${record.findings.length} canonical issues`);
  }
  if (record.suppressions?.length) lines.push(`Suppressed: ${record.suppressions.length} active finding${record.suppressions.length === 1 ? "" : "s"} excluded from the gate`);
  if (comparison) lines.push(`Compared with previous run: ${comparison.newFindings.length} new | ${comparison.resolvedFindings.length} resolved | ${comparison.unchangedFindings.length} unchanged`);
  if (record.analyzers) lines.push(`Analyzers: ${record.analyzers.map((run) => `${run.analyzerId} ${run.status} (${run.findings.length})`).join(" | ")}`);
  return lines.join("\n");
}

function findingKey(finding: Finding): string {
  return `${finding.analyzer}:${finding.fingerprint ?? finding.id}`;
}
