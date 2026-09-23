import { execFile as executeFile } from "node:child_process";
import { promisify } from "node:util";
import type { AnalyzerAdapter, AnalysisRequest, FindingInput, Severity, SourceLocation } from "@vulnweave/core";

const execFile = promisify(executeFile);

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  PrimaryURL?: string;
  References?: string[];
}

export interface TrivyMisconfiguration {
  ID: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  PrimaryURL?: string;
  CauseMetadata?: { Resource?: string; StartLine?: number; EndLine?: number };
}

export interface TrivyResult {
  Target: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

export interface TrivyReport { Results?: TrivyResult[]; }

/** Runs local Trivy filesystem checks for dependencies and configuration. */
export class TrivyAnalyzer implements AnalyzerAdapter {
  readonly id = "trivy";
  readonly displayName = "Trivy";

  async isAvailable(): Promise<boolean> {
    try { await execFile("trivy", ["--version"]); return true; } catch { return false; }
  }

  async analyze(request: AnalysisRequest): Promise<FindingInput[]> {
    const { stdout } = await execFile("trivy", trivyArguments(request.rootDir), { maxBuffer: 20 * 1024 * 1024 });
    return parseTrivyReport(JSON.parse(stdout) as TrivyReport);
  }
}

/** Excludes generated and third-party directories at the root and every nested depth. */
export function trivyArguments(rootDir: string): string[] {
  const skippedDirectories = [
    "node_modules", "**/node_modules",
    // pnpm keeps package contents beneath this directory. Trivy can discover
    // those contents independently of the parent node_modules entry.
    "node_modules/.pnpm", "**/node_modules/.pnpm",
    ".pnpm-store", "**/.pnpm-store",
    ".git", "**/.git",
    ".vulnweave", "**/.vulnweave",
    "dist", "**/dist",
    ".astro", "**/.astro",
    "fixtures", "**/fixtures"
  ];
  // Trivy's configuration scanner can follow pnpm links after directory
  // filtering. File-level exclusions make generated dependency contents
  // unambiguous while root lockfiles remain available to vulnerability scans.
  const skippedFiles = ["node_modules/**", "**/node_modules/**"];
  return [
    "fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig",
    ...skippedDirectories.flatMap((directory) => ["--skip-dirs", directory]),
    ...skippedFiles.flatMap((file) => ["--skip-files", file]),
    rootDir
  ];
}

/** Converts Trivy's filesystem report without retaining configuration file contents. */
export function parseTrivyReport(report: TrivyReport): FindingInput[] {
  return (report.Results ?? []).filter((result) => !isGeneratedDependencyTarget(result.Target)).flatMap((result) => [
    ...(result.Vulnerabilities ?? []).map((vulnerability) => normalizeVulnerability(result, vulnerability)),
    ...(result.Misconfigurations ?? []).map((misconfiguration) => normalizeMisconfiguration(result, misconfiguration))
  ]);
}

/**
 * Trivy can follow pnpm links after its own skip globs are applied. Do not
 * publish findings for installed package contents: they are not user-owned
 * source, while root manifests and lockfiles remain scanned for dependency
 * vulnerabilities.
 */
function isGeneratedDependencyTarget(target: string): boolean {
  return /(^|[/\\])node_modules(?:[/\\]|$)/.test(target);
}

function normalizeVulnerability(result: TrivyResult, vulnerability: TrivyVulnerability): FindingInput {
  const version = vulnerability.InstalledVersion ?? "unknown";
  return {
    ruleId: vulnerability.VulnerabilityID,
    category: "dependency",
    severity: normalizeSeverity(vulnerability.Severity),
    title: `${vulnerability.PkgName}@${version} is affected by ${vulnerability.VulnerabilityID}`,
    message: vulnerability.Title ?? vulnerability.Description ?? "A known vulnerability affects this dependency.",
    fingerprint: `trivy:vulnerability:${result.Target}:${vulnerability.PkgName}:${version}:${vulnerability.VulnerabilityID}`,
    references: uniqueReferences(vulnerability.PrimaryURL, vulnerability.References),
    metadata: { target: result.Target, targetType: result.Type ?? "unknown", package: vulnerability.PkgName, version, fixedVersion: vulnerability.FixedVersion ?? "" },
    evidence: [{
      id: `trivy:vulnerability:${result.Target}:${vulnerability.PkgName}:${vulnerability.VulnerabilityID}`,
      kind: "dependency",
      summary: "Trivy found a vulnerable dependency in this local target.",
      metadata: { package: vulnerability.PkgName, version, target: result.Target }
    }]
  };
}

function normalizeMisconfiguration(result: TrivyResult, misconfiguration: TrivyMisconfiguration): FindingInput {
  const location = configurationLocation(result.Target, misconfiguration.CauseMetadata);
  return {
    ruleId: misconfiguration.ID,
    category: "infrastructure",
    severity: normalizeSeverity(misconfiguration.Severity),
    title: misconfiguration.Title ?? misconfiguration.ID,
    message: misconfiguration.Description ?? "Trivy found a configuration issue.",
    location,
    fingerprint: `trivy:misconfiguration:${result.Target}:${misconfiguration.ID}:${location?.startLine ?? 0}`,
    references: uniqueReferences(misconfiguration.PrimaryURL),
    metadata: { target: result.Target, targetType: result.Type ?? "unknown", resource: misconfiguration.CauseMetadata?.Resource ?? "", sourcePath: result.Target },
    evidence: [{
      id: `trivy:misconfiguration:${result.Target}:${misconfiguration.ID}:${location?.startLine ?? 0}`,
      kind: "configuration",
      summary: "Trivy found this configuration issue in a local target.",
      location,
      metadata: { target: result.Target, resource: misconfiguration.CauseMetadata?.Resource ?? "" }
    }]
  };
}

function configurationLocation(path: string, cause?: TrivyMisconfiguration["CauseMetadata"]): SourceLocation | undefined {
  if (!cause?.StartLine || cause.StartLine < 1) return undefined;
  return { path, startLine: cause.StartLine, startColumn: 1, endLine: cause.EndLine };
}

function uniqueReferences(primary?: string, references?: string[]): string[] | undefined {
  const values = [...new Set([primary, ...(references ?? [])].filter((value): value is string => Boolean(value)))];
  return values.length > 0 ? values : undefined;
}

function normalizeSeverity(value?: string): Severity {
  switch (value?.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MEDIUM": case "MODERATE": return "medium";
    case "LOW": return "low";
    default: return "info";
  }
}
