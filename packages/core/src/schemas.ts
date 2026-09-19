/** Stable, analyzer-neutral data contracts owned by VulnWeave. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingCategory = "security" | "quality" | "dependency" | "secret" | "infrastructure";

export interface SourceLocation {
  path: string;
  startLine: number;
  startColumn: number;
  endLine?: number;
  endColumn?: number;
}

export interface Evidence {
  id: string;
  kind: "source" | "dependency" | "configuration" | "command" | "external";
  summary: string;
  location?: SourceLocation;
  excerpt?: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface Finding {
  /** Deterministic within an analyzer; consumers should not infer its format. */
  id: string;
  analyzer: string;
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  message: string;
  location?: SourceLocation;
  evidence: Evidence[];
  fingerprint?: string;
  references?: string[];
  metadata?: Record<string, string | number | boolean>;
}

/** Adapter-owned data before core assigns the canonical analyzer name and fallback ID. */
export type FindingInput = Omit<Finding, "id" | "analyzer" | "evidence"> & { id?: string; evidence?: Evidence[] };

const severities: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const categories: readonly FindingCategory[] = ["security", "quality", "dependency", "secret", "infrastructure"];

export function assertValidFinding(value: Finding): Finding {
  if (!value.id || !value.analyzer || !value.ruleId || !value.title || !value.message) {
    throw new Error("Finding requires id, analyzer, ruleId, title, and message");
  }
  if (!severities.includes(value.severity)) throw new Error(`Unknown severity: ${value.severity}`);
  if (!categories.includes(value.category)) throw new Error(`Unknown finding category: ${value.category}`);
  if (!Array.isArray(value.evidence)) throw new Error("Finding evidence must be an array");
  if (value.location) assertValidLocation(value.location);
  for (const evidence of value.evidence) {
    if (!evidence.id || !evidence.kind || !evidence.summary) throw new Error("Evidence requires id, kind, and summary");
    if (evidence.location) assertValidLocation(evidence.location);
  }
  return value;
}

function assertValidLocation(location: SourceLocation): void {
  if (!location.path || location.startLine < 1 || location.startColumn < 1) {
    throw new Error("Source locations require a path and one-based start line/column");
  }
}
