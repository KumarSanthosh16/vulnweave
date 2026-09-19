import type { ScanRecord } from "./run-store.js";
import { compareScanRecords } from "./run-store.js";

export interface TrendPoint {
  id: string;
  completedAt: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  newFindings: number;
  resolvedFindings: number;
  gate: "passed" | "failed" | "not-configured";
  analyzerHealth: "passed" | "failed" | "not-required";
}

export interface ScanTrend { points: TrendPoint[]; posture: "improving" | "worsening" | "unchanged" | "insufficient-history"; }

/** Derives a compact local history without changing stored scan records. */
export function buildScanTrend(records: ScanRecord[]): ScanTrend {
  const ordered = [...records].sort((left, right) => left.completedAt.localeCompare(right.completedAt));
  const points: TrendPoint[] = ordered.map((record, index) => {
    const previous = ordered[index - 1];
    const comparison = previous ? compareScanRecords(record, previous) : undefined;
    const counts = record.findings.reduce<Record<string, number>>((totals, finding) => ({ ...totals, [finding.severity]: (totals[finding.severity] ?? 0) + 1 }), {});
    return {
      id: record.id, completedAt: record.completedAt, findings: record.findings.length,
      critical: counts.critical ?? 0, high: counts.high ?? 0, medium: counts.medium ?? 0, low: counts.low ?? 0,
      newFindings: comparison?.newFindings.length ?? 0, resolvedFindings: comparison?.resolvedFindings.length ?? 0,
      gate: !record.gate?.failOn ? "not-configured" : record.gate.passed ? "passed" : "failed",
      analyzerHealth: !record.analyzerHealth?.required ? "not-required" : record.analyzerHealth.passed ? "passed" : "failed"
    };
  });
  return { points, posture: postureFor(points) };
}

export function formatScanTrend(trend: ScanTrend): string {
  if (trend.points.length === 0) return "No saved scans available for a trend.";
  const headers = ["RUN", "FINDINGS", "CRIT", "HIGH", "MED", "LOW", "NEW", "RESOLVED", "GATE", "ANALYZERS"];
  const rows = [...trend.points].reverse().map((point) => [point.id.slice(0, 12), String(point.findings), String(point.critical), String(point.high), String(point.medium), String(point.low), String(point.newFindings), String(point.resolvedFindings), point.gate, point.analyzerHealth]);
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [`Security trend: ${trend.posture}`, render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function postureFor(points: TrendPoint[]): ScanTrend["posture"] {
  if (points.length < 2) return "insufficient-history";
  const previous = points[points.length - 2]!;
  const latest = points[points.length - 1]!;
  const score = (point: TrendPoint) => point.critical * 100 + point.high * 25 + point.medium * 5 + point.low;
  return score(latest) < score(previous) ? "improving" : score(latest) > score(previous) ? "worsening" : "unchanged";
}
