import { execFile as executeFile } from "node:child_process";
import { basename, extname, isAbsolute, relative, sep } from "node:path";
import { promisify } from "node:util";
import type { AnalyzerAdapter, AnalysisRequest, FindingInput, Severity, SourceLocation } from "@vulnweave/core";

const execFile = promisify(executeFile);

export interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity?: string;
    fingerprint?: string;
    metadata?: Record<string, unknown>;
  };
}

interface SemgrepReport { results: SemgrepResult[]; }

/** Runs a local Semgrep binary against explicitly supplied local rule configurations. */
export class SemgrepAnalyzer implements AnalyzerAdapter {
  readonly id = "semgrep";
  readonly displayName = "Semgrep";

  async isAvailable(): Promise<boolean> {
    try {
      await execFile("semgrep", ["--version"]);
      return true;
    } catch {
      return false;
    }
  }

  async analyze(request: AnalysisRequest): Promise<FindingInput[]> {
    const configPaths = semgrepConfigPaths(request.config?.semgrepConfig);
    if (configPaths.length === 0) {
      throw new Error("Semgrep requires local rules: pass --semgrep-config path/to/rules.yml or --semgrep-pack name");
    }
    const { stdout } = await execFile("semgrep", [
      "scan", "--json", "--quiet", "--exclude", "fixtures", ...configPaths.flatMap((path) => ["--config", path]), request.rootDir
    ], { maxBuffer: 20 * 1024 * 1024 });
    const report = JSON.parse(stdout) as SemgrepReport;
    return relativizeFindings(parseSemgrepReport(report.results, configPaths), request.rootDir);
  }
}

/** Converts Semgrep's tool-specific JSON into product-owned findings. */
export function parseSemgrepReport(results: SemgrepResult[], configPath?: string | string[]): FindingInput[] {
  return results.map((result) => {
    const location: SourceLocation = {
      path: result.path,
      startLine: result.start.line,
      startColumn: result.start.col,
      endLine: result.end.line,
      endColumn: result.end.col
    };
    const metadata = toScalarMetadata(result.extra.metadata);
    const ruleId = normalizeRuleId(result.check_id, configPath);
    const title = typeof result.extra.metadata?.message === "string"
      ? result.extra.metadata.message
      : ruleId;
    return {
      ruleId,
      category: "security",
      severity: normalizeSeverity(result.extra.severity),
      title,
      message: result.extra.message,
      location,
      fingerprint: result.extra.fingerprint,
      metadata,
      evidence: [{
        id: `semgrep:${result.extra.fingerprint ?? `${result.path}:${result.start.line}:${result.check_id}`}`,
        kind: "source",
        summary: "Semgrep matched this local rule at the source location.",
        location
      }]
    };
  });
}

/** Makes tool-emitted absolute paths portable in terminal output, SARIF, and baselines. */
export function relativizeFindings(findings: FindingInput[], rootDir: string): FindingInput[] {
  return findings.map((finding) => ({
    ...finding,
    location: relativizeLocation(finding.location, rootDir),
    evidence: finding.evidence?.map((evidence) => ({ ...evidence, location: relativizeLocation(evidence.location, rootDir) }))
  }));
}

function normalizeRuleId(checkId: string, configPath?: string | string[]): string {
  const yamlSuffix = checkId.match(/\.ya?ml\.(.+)$/i)?.[1];
  if (yamlSuffix) return yamlSuffix;
  for (const path of typeof configPath === "string" ? [configPath] : configPath ?? []) {
    const configName = basename(path, extname(path));
    const configIndex = checkId.lastIndexOf(`${configName}.`);
    if (configIndex >= 0) return checkId.slice(configIndex + configName.length + 1);
  }
  return checkId;
}

function semgrepConfigPaths(value: unknown): string[] {
  if (typeof value === "string") return value ? [value] : [];
  return Array.isArray(value) ? value.filter((path): path is string => typeof path === "string" && path.length > 0) : [];
}

function relativizeLocation(location: SourceLocation | undefined, rootDir: string): SourceLocation | undefined {
  if (!location || !isAbsolute(location.path)) return location;
  const path = relative(rootDir, location.path);
  return path === "" || path === ".." || path.startsWith(`..${sep}`) ? location : { ...location, path: path.split(sep).join("/") };
}

function normalizeSeverity(value?: string): Severity {
  switch (value?.toUpperCase()) {
    case "ERROR": case "CRITICAL": return "high";
    case "WARNING": case "HIGH": return "medium";
    case "LOW": return "low";
    default: return "info";
  }
}

function toScalarMetadata(metadata?: Record<string, unknown>): Record<string, string | number | boolean> | undefined {
  if (!metadata) return undefined;
  const scalarEntries = Object.entries(metadata).filter((entry): entry is [string, string | number | boolean] => {
    const value = entry[1];
    return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
  });
  return scalarEntries.length > 0 ? Object.fromEntries(scalarEntries) : undefined;
}
