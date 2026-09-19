import type { CodeSymbol, ImportRelation } from "./code-symbols.js";
import type { Finding } from "./schemas.js";

export interface FileHotspot { path: string; inboundImports: number; outboundImports: number; symbols: number; score: number; }

export interface ChangeImpact {
  reference?: string;
  changedFiles: string[];
  dependentFiles: string[];
  directlyChangedFindings: Finding[];
  importAffectedFindings: Finding[];
}

/** Traces local reverse-import relationships from changed files to affected source findings. */
export function analyzeChangeImpact(findings: Finding[], changedFiles: string[], imports: ImportRelation[], reference?: string): ChangeImpact {
  const changed = new Set(changedFiles);
  const dependents = reverseImportClosure(changed, imports);
  const directlyChangedFindings = findings.filter((finding) => finding.location && changed.has(finding.location.path));
  const importAffectedFindings = findings.filter((finding) => finding.location && !changed.has(finding.location.path) && dependents.has(finding.location.path));
  return { reference, changedFiles: [...changed].sort(), dependentFiles: [...dependents].sort(), directlyChangedFindings, importAffectedFindings };
}

/** Returns findings in changed files plus source findings in local import dependents. */
export function findingsInChangeScope(impact: ChangeImpact): Finding[] {
  const findings = new Map<string, Finding>();
  for (const finding of [...impact.directlyChangedFindings, ...impact.importAffectedFindings]) findings.set(finding.id, finding);
  return [...findings.values()];
}

export function formatChangeImpact(impact: ChangeImpact): string {
  const lines = [
    `Change impact${impact.reference ? `: ${impact.reference}` : ""}`,
    `Changed files: ${impact.changedFiles.length}`,
    `Import-affected files: ${impact.dependentFiles.length}`,
    `Findings: ${impact.directlyChangedFindings.length} directly changed | ${impact.importAffectedFindings.length} import-affected`
  ];
  if (impact.changedFiles.length > 0) lines.push(`Changed: ${impact.changedFiles.join(", ")}`);
  if (impact.dependentFiles.length > 0) lines.push(`Dependents: ${impact.dependentFiles.join(", ")}`);
  if (impact.changedFiles.length === 0) lines.push("No Git change context was found for this reference.");
  return lines.join("\n");
}

export function rankFileHotspots(symbols: CodeSymbol[], imports: ImportRelation[]): FileHotspot[] {
  const paths = new Set([...symbols.map((symbol) => symbol.path), ...imports.flatMap((edge) => [edge.from, edge.to])]);
  return [...paths].map((path) => {
    const inboundImports = imports.filter((edge) => edge.to === path).length;
    const outboundImports = imports.filter((edge) => edge.from === path).length;
    const symbolCount = symbols.filter((symbol) => symbol.path === path).length;
    return { path, inboundImports, outboundImports, symbols: symbolCount, score: inboundImports * 10 + outboundImports * 2 + symbolCount };
  }).sort((left, right) => right.score - left.score || left.path.localeCompare(right.path));
}

export function formatHotspotTable(hotspots: FileHotspot[]): string {
  if (hotspots.length === 0) return "No local source relationships found.";
  const headers = ["SCORE", "INBOUND", "OUTBOUND", "SYMBOLS", "FILE"];
  const rows = hotspots.map((hotspot) => [String(hotspot.score), String(hotspot.inboundImports), String(hotspot.outboundImports), String(hotspot.symbols), hotspot.path]);
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function reverseImportClosure(changed: Set<string>, imports: ImportRelation[]): Set<string> {
  const reverse = new Map<string, string[]>();
  for (const edge of imports) reverse.set(edge.to, [...(reverse.get(edge.to) ?? []), edge.from]);
  const dependents = new Set<string>();
  const queue = [...changed];
  while (queue.length > 0) {
    const path = queue.shift();
    if (!path) continue;
    for (const dependent of reverse.get(path) ?? []) {
      if (!dependents.has(dependent) && !changed.has(dependent)) {
        dependents.add(dependent);
        queue.push(dependent);
      }
    }
  }
  return dependents;
}
