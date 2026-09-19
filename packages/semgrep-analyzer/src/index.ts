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

/** Runs a local Semgrep binary against an explicitly supplied local rule configuration. */
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
    const configPath = request.config?.semgrepConfig;
    if (typeof configPath !== "string" || configPath.length === 0) {
      throw new Error("Semgrep requires a local rules file: pass --semgrep-config path/to/rules.yml");
    }
    const { stdout } = await execFile("semgrep", [
      "scan", "--json", "--quiet", "--exclude", "fixtures", "--config", configPath, request.rootDir
    ], { maxBuffer: 20 * 1024 * 1024 });
    const report = JSON.parse(stdout) as SemgrepReport;
    return relativizeFindings(parseSemgrepReport(report.results, configPath), request.rootDir);
  }
}

/** Converts Semgrep's tool-specific JSON into product-owned findings. */
export function parseSemgrepReport(results: SemgrepResult[], configPath?: string): FindingInput[] {
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

function normalizeRuleId(checkId: string, configPath?: string): string {
  const yamlSuffix = checkId.match(/\.ya?ml\.(.+)$/i)?.[1];
  if (yamlSuffix) return yamlSuffix;
  if (!configPath) return checkId;
  const configName = basename(configPath, extname(configPath));
  const configIndex = checkId.lastIndexOf(`${configName}.`);
  return configIndex >= 0 ? checkId.slice(configIndex + configName.length + 1) : checkId;
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
