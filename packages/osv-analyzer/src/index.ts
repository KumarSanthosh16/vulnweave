import { execFile as executeFile } from "node:child_process";
import { promisify } from "node:util";
import type { AnalyzerAdapter, AnalysisRequest, FindingInput, Severity } from "@vulnweave/core";

const execFile = promisify(executeFile);

export interface OsvVulnerability {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
}
export interface OsvReport {
  results: Array<{
    source: { path: string; type: string };
    packages: Array<{
      package: { name: string; version?: string; ecosystem?: string };
      vulnerabilities?: OsvVulnerability[];
    }>;
  }>;
}

/** Runs the local OSV-Scanner binary against detected dependency manifests and lockfiles. */
export class OsvAnalyzer implements AnalyzerAdapter {
  readonly id = "osv";
  readonly displayName = "OSV-Scanner";

  async isAvailable(): Promise<boolean> {
    try { await execFile("osv-scanner", ["--version"]); return true; } catch { return false; }
  }

  async analyze(request: AnalysisRequest): Promise<FindingInput[]> {
    const { stdout } = await execFile("osv-scanner", [
      "scan", "source", "--format", "json", "--recursive", request.rootDir
    ], { maxBuffer: 20 * 1024 * 1024 });
    return parseOsvReport(JSON.parse(stdout) as OsvReport);
  }
}

/** Normalizes OSV's package-centric report into one finding per affected package/advisory. */
export function parseOsvReport(report: OsvReport): FindingInput[] {
  return report.results.flatMap((result) => result.packages.flatMap((affectedPackage) =>
    (affectedPackage.vulnerabilities ?? []).map((vulnerability) => ({
      ruleId: vulnerability.id,
      category: "dependency" as const,
      severity: normalizeSeverity(vulnerability.database_specific?.severity),
      title: `${affectedPackage.package.name}@${affectedPackage.package.version ?? "unknown"} is affected by ${vulnerability.id}`,
      message: vulnerability.summary ?? "A known vulnerability affects this dependency.",
      fingerprint: `osv:${result.source.path}:${affectedPackage.package.name}:${affectedPackage.package.version ?? "unknown"}:${vulnerability.id}`,
      metadata: {
        package: affectedPackage.package.name,
        version: affectedPackage.package.version ?? "unknown",
        ecosystem: affectedPackage.package.ecosystem ?? "unknown",
        sourcePath: result.source.path,
        sourceType: result.source.type,
        aliases: vulnerability.aliases?.join(",") ?? ""
      },
      evidence: [{
        id: `osv:${result.source.path}:${affectedPackage.package.name}:${vulnerability.id}`,
        kind: "dependency" as const,
        summary: "OSV-Scanner found this vulnerable dependency in a local manifest or lockfile.",
        metadata: { package: affectedPackage.package.name, version: affectedPackage.package.version ?? "unknown", sourcePath: result.source.path }
      }]
    }))
  ));
}

function normalizeSeverity(value?: string): Severity {
  switch (value?.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MODERATE": case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return "medium";
  }
}
