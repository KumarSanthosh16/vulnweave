import { execFile as executeFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { AnalyzerAdapter, AnalysisRequest, FindingInput, SourceLocation } from "@vulnweave/core";

const execFile = promisify(executeFile);

/** The subset of Gitleaks' stable JSON report shape used by this adapter. */
export interface GitleaksReportEntry {
  RuleID: string;
  Description?: string;
  File: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Fingerprint?: string;
  Tags?: string[];
}

/**
 * Runs a locally installed Gitleaks binary. It never places the `Secret` field
 * from Gitleaks output into a finding, logs, or evidence.
 */
export class GitleaksAnalyzer implements AnalyzerAdapter {
  readonly id = "gitleaks";
  readonly displayName = "Gitleaks";

  async isAvailable(): Promise<boolean> {
    try {
      await execFile("gitleaks", ["version"]);
      return true;
    } catch {
      return false;
    }
  }

  async analyze(request: AnalysisRequest): Promise<FindingInput[]> {
    const reportDir = await mkdtemp(join(tmpdir(), "VulnWeave-gitleaks-"));
    const reportPath = join(reportDir, "report.json");
    try {
      try {
        await execFile("gitleaks", gitleaksArguments(request.rootDir, reportPath, request.config?.gitleaksConfig));
      } catch (error) {
        // Gitleaks exits with status 1 when it found leaks; that is a successful scan.
        if (!(isExitCode(error, 1))) throw error;
      }
      const report = JSON.parse(await readFile(reportPath, "utf8")) as GitleaksReportEntry[];
      return parseGitleaksReport(report);
    } finally {
      await rm(reportDir, { recursive: true, force: true });
    }
  }
}

export function gitleaksArguments(rootDir: string, reportPath: string, configPath: unknown): string[] {
  return [
    "detect", "--no-banner", "--source", rootDir,
    ...(typeof configPath === "string" && configPath.length > 0 ? ["--config", configPath] : []),
    "--report-format", "json", "--report-path", reportPath
  ];
}

function isExitCode(error: unknown, expected: number): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === expected;
}

/** Converts Gitleaks JSON to product-owned contracts without exposing secret values. */
export function parseGitleaksReport(entries: GitleaksReportEntry[]): FindingInput[] {
  return entries.map((entry) => {
    const location = toLocation(entry);
    return {
      ruleId: entry.RuleID,
      category: "secret",
      severity: "high",
      title: entry.Description ?? `Potential secret detected by ${entry.RuleID}`,
      message: "A potential secret was detected. Rotate or revoke it if valid, then remove it from the repository.",
      location,
      fingerprint: entry.Fingerprint,
      metadata: entry.Tags?.length ? { tags: entry.Tags.join(",") } : undefined,
      evidence: [{
        id: `gitleaks:${entry.Fingerprint ?? `${entry.File}:${entry.StartLine ?? 1}`}`,
        kind: "source",
        summary: "Gitleaks matched a possible secret at this location.",
        location,
        // Match may contain a secret, so no scanner text is included here.
        metadata: entry.Match ? { matchPresent: true } : undefined
      }]
    };
  });
}

function toLocation(entry: GitleaksReportEntry): SourceLocation {
  return {
    path: entry.File,
    startLine: entry.StartLine ?? 1,
    startColumn: entry.StartColumn ?? 1,
    endLine: entry.EndLine,
    endColumn: entry.EndColumn
  };
}
