import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Severity } from "./schemas.js";
import type { FindingSuppression } from "./suppressions.js";

export type ConfiguredAnalyzer = "all" | "mock" | "gitleaks" | "osv" | "semgrep" | "trivy";

/** Portable project policy stored beside source, separate from local scan state. */
export interface VulnWeaveProjectConfig {
  schemaVersion: 1;
  analyzer?: ConfiguredAnalyzer;
  semgrepConfig?: string;
  failOn?: Severity;
  requireAnalyzers?: boolean;
  suppressions?: FindingSuppression[];
}

export async function loadProjectConfig(rootDir: string): Promise<VulnWeaveProjectConfig | undefined> {
  const path = join(rootDir, "vulnweave.config.json");
  try {
    return validateProjectConfig(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    if (isMissingFile(error)) return undefined;
    throw new Error(`Invalid VulnWeave project config at ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function validateProjectConfig(value: unknown): VulnWeaveProjectConfig {
  if (!isRecord(value)) throw new Error("expected a JSON object");
  if (value.schemaVersion !== 1) throw new Error("schemaVersion must be 1");
  if (value.analyzer !== undefined && !["all", "mock", "gitleaks", "osv", "semgrep", "trivy"].includes(stringValue(value.analyzer))) {
    throw new Error("analyzer must be all, mock, gitleaks, osv, semgrep, or trivy");
  }
  if (value.semgrepConfig !== undefined && typeof value.semgrepConfig !== "string") throw new Error("semgrepConfig must be a string");
  if (value.failOn !== undefined && !["critical", "high", "medium", "low", "info"].includes(stringValue(value.failOn))) {
    throw new Error("failOn must be critical, high, medium, low, or info");
  }
  if (value.requireAnalyzers !== undefined && typeof value.requireAnalyzers !== "boolean") throw new Error("requireAnalyzers must be a boolean");
  if (value.suppressions !== undefined) validateSuppressions(value.suppressions);
  return {
    schemaVersion: 1,
    ...(typeof value.analyzer === "string" ? { analyzer: value.analyzer as ConfiguredAnalyzer } : {}),
    ...(typeof value.semgrepConfig === "string" ? { semgrepConfig: value.semgrepConfig } : {}),
    ...(typeof value.failOn === "string" ? { failOn: value.failOn as Severity } : {}),
    ...(typeof value.requireAnalyzers === "boolean" ? { requireAnalyzers: value.requireAnalyzers } : {}),
    ...(Array.isArray(value.suppressions) ? { suppressions: value.suppressions as FindingSuppression[] } : {})
  };
}

function validateSuppressions(value: unknown): void {
  if (!Array.isArray(value)) throw new Error("suppressions must be an array");
  for (const [index, entry] of value.entries()) {
    if (!isRecord(entry)) throw new Error(`suppressions[${index}] must be an object`);
    if (!nonEmptyString(entry.fingerprint) || !nonEmptyString(entry.reason) || !nonEmptyString(entry.owner)) throw new Error(`suppressions[${index}] requires fingerprint, reason, and owner`);
    if (!isDate(entry.expiresOn)) throw new Error(`suppressions[${index}].expiresOn must be YYYY-MM-DD`);
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
