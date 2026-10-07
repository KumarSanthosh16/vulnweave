import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Severity } from "./schemas.js";
import type { QualityOptions } from "./code-quality.js";
import type { QualityGatePolicy } from "./quality-gate.js";
import type { FindingSuppression } from "./suppressions.js";
import type { CodeOwnersRule } from "./ownership.js";
import { parseDocument } from "yaml";

export type ConfiguredAnalyzer = "all" | "mock" | "gitleaks" | "osv" | "semgrep" | "trivy";
export type ConfiguredRealAnalyzer = Exclude<ConfiguredAnalyzer, "all" | "mock">;

/** Portable project policy stored beside source, separate from local scan state. */
export interface VulnWeaveProjectConfig {
  schemaVersion: 1;
  analyzer?: ConfiguredAnalyzer;
  /** A focused real-analyzer set. Mutually exclusive with the legacy analyzer field. */
  analyzers?: ConfiguredRealAnalyzer[];
  semgrepConfig?: string;
  gitleaksConfig?: string;
  baselinePolicy?: string;
  failOn?: Severity;
  requireAnalyzers?: boolean;
  quality?: QualityOptions;
  qualityGate?: QualityGatePolicy;
  suppressions?: FindingSuppression[];
  /** Repository-local ownership rules. They supplement or override CODEOWNERS. */
  owners?: CodeOwnersRule[];
}

export async function loadProjectConfig(rootDir: string): Promise<VulnWeaveProjectConfig | undefined> {
  for (const [filename, format] of [[".vulnweave.yml", "yaml"], ["vulnweave.config.json", "json"]] as const) {
    const path = join(rootDir, filename);
    try {
      const source = await readFile(path, "utf8");
      const value = format === "yaml" ? parseYaml(source) : JSON.parse(source);
      return validateProjectConfig(value);
    } catch (error) {
      if (isMissingFile(error)) continue;
      throw new Error(`Invalid VulnWeave project policy at ${path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return undefined;
}

export function validateProjectConfig(value: unknown): VulnWeaveProjectConfig {
  if (!isRecord(value)) throw new Error("expected an object");
  if (value.schemaVersion !== 1) throw new Error("schemaVersion must be 1");
  if (value.analyzer !== undefined && !["all", "mock", "gitleaks", "osv", "semgrep", "trivy"].includes(stringValue(value.analyzer))) {
    throw new Error("analyzer must be all, mock, gitleaks, osv, semgrep, or trivy");
  }
  if (value.analyzer !== undefined && value.analyzers !== undefined) throw new Error("use either analyzer or analyzers, not both");
  if (value.analyzers !== undefined) validateAnalyzers(value.analyzers);
  if (value.semgrepConfig !== undefined && typeof value.semgrepConfig !== "string") throw new Error("semgrepConfig must be a string");
  if (value.gitleaksConfig !== undefined && typeof value.gitleaksConfig !== "string") throw new Error("gitleaksConfig must be a string");
  if (value.baselinePolicy !== undefined && typeof value.baselinePolicy !== "string") throw new Error("baselinePolicy must be a string");
  if (value.failOn !== undefined && !["critical", "high", "medium", "low", "info"].includes(stringValue(value.failOn))) {
    throw new Error("failOn must be critical, high, medium, low, or info");
  }
  if (value.requireAnalyzers !== undefined && typeof value.requireAnalyzers !== "boolean") throw new Error("requireAnalyzers must be a boolean");
  if (value.quality !== undefined) validateQuality(value.quality);
  if (value.qualityGate !== undefined) validateQualityGate(value.qualityGate);
  if (value.suppressions !== undefined) validateSuppressions(value.suppressions);
  if (value.owners !== undefined) validateOwners(value.owners);
  return {
    schemaVersion: 1,
    ...(typeof value.analyzer === "string" ? { analyzer: value.analyzer as ConfiguredAnalyzer } : {}),
    ...(Array.isArray(value.analyzers) ? { analyzers: value.analyzers as ConfiguredRealAnalyzer[] } : {}),
    ...(typeof value.semgrepConfig === "string" ? { semgrepConfig: value.semgrepConfig } : {}),
    ...(typeof value.gitleaksConfig === "string" ? { gitleaksConfig: value.gitleaksConfig } : {}),
    ...(typeof value.baselinePolicy === "string" ? { baselinePolicy: value.baselinePolicy } : {}),
    ...(typeof value.failOn === "string" ? { failOn: value.failOn as Severity } : {}),
    ...(typeof value.requireAnalyzers === "boolean" ? { requireAnalyzers: value.requireAnalyzers } : {}),
    ...(isRecord(value.quality) ? { quality: value.quality as QualityOptions } : {}),
    ...(isRecord(value.qualityGate) ? { qualityGate: value.qualityGate as QualityGatePolicy } : {}),
    ...(Array.isArray(value.suppressions) ? { suppressions: value.suppressions as FindingSuppression[] } : {}),
    ...(Array.isArray(value.owners) ? { owners: value.owners as CodeOwnersRule[] } : {})
  };
}

function validateAnalyzers(value: unknown): void {
  if (!Array.isArray(value) || value.length === 0) throw new Error("analyzers must be a non-empty array");
  const allowed: ConfiguredRealAnalyzer[] = ["gitleaks", "osv", "semgrep", "trivy"];
  if (!value.every((analyzer) => typeof analyzer === "string" && allowed.includes(analyzer as ConfiguredRealAnalyzer))) {
    throw new Error("analyzers may contain only gitleaks, osv, semgrep, or trivy");
  }
  if (new Set(value).size !== value.length) throw new Error("analyzers must not contain duplicates");
}

function parseYaml(source: string): unknown {
  const document = parseDocument(source, { prettyErrors: false });
  if (document.errors.length > 0) throw document.errors[0] ?? new Error("invalid YAML");
  return document.toJS();
}

function validateQuality(value: unknown): void {
  if (!isRecord(value)) throw new Error("quality must be an object");
  for (const key of ["complexityThreshold", "duplicateBlockLines", "nestingThreshold", "functionLineThreshold", "parameterThreshold"] as const) {
    const threshold = value[key];
    if (threshold !== undefined && (typeof threshold !== "number" || !Number.isInteger(threshold) || threshold < 2)) throw new Error(`quality.${key} must be an integer of at least 2`);
  }
}

function validateQualityGate(value: unknown): void {
  if (!isRecord(value)) throw new Error("qualityGate must be an object");
  for (const key of ["maxComplexitySignals", "maxDuplicateCodeSignals", "maxUnreferencedFiles"]) {
    const limit = value[key];
    if (limit !== undefined && (typeof limit !== "number" || !Number.isInteger(limit) || limit < 0)) throw new Error(`qualityGate.${key} must be a non-negative integer`);
  }
}

function validateSuppressions(value: unknown): void {
  if (!Array.isArray(value)) throw new Error("suppressions must be an array");
  for (const [index, entry] of value.entries()) {
    if (!isRecord(entry)) throw new Error(`suppressions[${index}] must be an object`);
    if (!nonEmptyString(entry.fingerprint) || !nonEmptyString(entry.reason) || !nonEmptyString(entry.owner)) throw new Error(`suppressions[${index}] requires fingerprint, reason, and owner`);
    if (!isDate(entry.expiresOn)) throw new Error(`suppressions[${index}].expiresOn must be YYYY-MM-DD`);
  }
}

function validateOwners(value: unknown): void {
  if (!Array.isArray(value)) throw new Error("owners must be an array");
  for (const [index, entry] of value.entries()) {
    if (!isRecord(entry)) throw new Error(`owners[${index}] must be an object`);
    if (!nonEmptyString(entry.pattern)) throw new Error(`owners[${index}].pattern must be a non-empty string`);
    if (!Array.isArray(entry.owners) || entry.owners.length === 0 || !entry.owners.every(nonEmptyString)) throw new Error(`owners[${index}].owners must be a non-empty string array`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function stringValue(value: unknown): string { return typeof value === "string" ? value : ""; }
function nonEmptyString(value: unknown): boolean { return typeof value === "string" && value.length > 0; }
function isDate(value: unknown): boolean {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  return !Number.isNaN(new Date(`${value}T00:00:00.000Z`).getTime());
}
function isMissingFile(error: unknown): boolean { return error instanceof Error && "code" in error && error.code === "ENOENT"; }
