import type { Finding } from "./schemas.js";

export interface CodeSymbol {
  id: string;
  path: string;
  name: string;
  kind: "function" | "class" | "method" | "interface";
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface FindingSymbolLink { findingId: string; symbolId: string; }
export interface ImportRelation { from: string; to: string; source: string; }
/** A static JavaScript/TypeScript import of an external package. */
export interface DependencyUsage {
  packageName: string;
  path: string;
  line: number;
  column: number;
  source: string;
}

/** Links a source finding to its narrowest enclosing declaration. */
export function linkFindingsToSymbols(findings: Finding[], symbols: CodeSymbol[]): FindingSymbolLink[] {
  return findings.flatMap((finding) => {
    if (!finding.location) return [];
    const candidates = symbols.filter((symbol) => symbol.path === finding.location?.path && contains(symbol, finding.location.startLine, finding.location.startColumn));
    const closest = candidates.sort((left, right) => span(left) - span(right))[0];
    return closest ? [{ findingId: finding.id, symbolId: closest.id }] : [];
  });
}

function contains(symbol: CodeSymbol, line: number, column: number): boolean {
  return (line > symbol.line || (line === symbol.line && column >= symbol.column)) &&
    (line < symbol.endLine || (line === symbol.endLine && column <= symbol.endColumn));
}

function span(symbol: CodeSymbol): number { return (symbol.endLine - symbol.line) * 10_000 + symbol.endColumn - symbol.column; }
