export type QualitySignalKind = "duplicate-code" | "duplicate-function" | "high-complexity" | "deep-nesting" | "oversized-function" | "excessive-parameters" | "unreferenced-file";

export interface QualitySignal {
  kind: QualitySignalKind;
  path: string;
  line: number;
  title: string;
  detail: string;
  score: number;
  relatedLocations?: Array<{ path: string; line: number }>;
  evidenceKinds?: QualitySignalKind[];
}

export interface QualityOptions {
  complexityThreshold?: number;
  duplicateBlockLines?: number;
  nestingThreshold?: number;
  functionLineThreshold?: number;
  parameterThreshold?: number;
}

/** Formats advisory quality signals without treating them as security findings. */
export function formatQualityTable(signals: QualitySignal[]): string {
  if (signals.length === 0) return "No duplicate-code or high-complexity signals were found.";
  const rows = signals.map((signal) => [signal.kind.toUpperCase(), String(signal.score), `${signal.path}:${signal.line}`, signal.title]);
  const headers = ["TYPE", "SCORE", "LOCATION", "DETAIL"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

/** Collapses overlapping block and function clone observations into one actionable issue. */
export function correlateQualitySignals(signals: QualitySignal[]): QualitySignal[] {
  const groups = new Map<string, QualitySignal[]>();
  const retained = signals.filter((signal) => signal.kind !== "duplicate-code" && signal.kind !== "duplicate-function");
  for (const signal of signals.filter((item) => item.kind === "duplicate-code" || item.kind === "duplicate-function")) {
    const locations = [{ path: signal.path, line: signal.line }, ...(signal.relatedLocations ?? [])].sort((left, right) => left.path.localeCompare(right.path) || left.line - right.line);
    const key = locations.map((location) => `${location.path}:${location.line}`).join("|");
    const group = groups.get(key) ?? [];
    group.push(signal);
    groups.set(key, group);
  }
  const correlated = [...groups.values()].map((group) => {
    const first = group[0]!;
    const evidenceKinds = [...new Set(group.map((signal) => signal.kind))];
    const locations = [{ path: first.path, line: first.line }, ...(first.relatedLocations ?? [])].sort((left, right) => left.path.localeCompare(right.path) || left.line - right.line);
    const [primary, ...relatedLocations] = locations;
    return {
      kind: evidenceKinds.includes("duplicate-function") ? "duplicate-function" as const : "duplicate-code" as const,
      path: primary!.path, line: primary!.line, score: locations.length,
      title: `Duplicate implementation (${locations.length} locations)`,
      detail: evidenceKinds.length === 2 ? "Matching parsed function bodies and normalized source blocks." : evidenceKinds[0] === "duplicate-function" ? "Matching parsed function bodies after comments and whitespace are normalized." : "Matching normalized source blocks after comments and whitespace are removed.",
      relatedLocations, evidenceKinds
    };
  });
  return [...retained, ...correlated];
}
