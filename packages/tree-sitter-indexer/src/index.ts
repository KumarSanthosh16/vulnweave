import { readFile, readdir } from "node:fs/promises";
import { dirname, extname, join, relative } from "node:path";
import Parser from "tree-sitter";
import JavaScript from "tree-sitter-javascript";
import TypeScript from "tree-sitter-typescript";
import { correlateQualitySignals, type CodeSymbol, type DependencyUsage, type ImportRelation, type QualityOptions, type QualitySignal } from "@vulnweave/core";
export type { CodeSymbol, DependencyUsage, ImportRelation } from "@vulnweave/core";

const ignoredDirectories = new Set(["node_modules", "dist", "fixtures", ".git", ".vulnweave", ".signal-impact"]);
export interface IndexOptions { includeTests?: boolean; }

/** Extracts top-level and member declarations from JavaScript, TypeScript, and TSX locally. */
export async function indexSymbols(rootDir: string, options: IndexOptions = {}): Promise<CodeSymbol[]> {
  const paths = await sourceFiles(rootDir, options);
  const symbols = await Promise.all(paths.map(async (path) => extractSymbols(relative(rootDir, path), await readFile(path, "utf8"))));
  return symbols.flat();
}

export async function indexImports(rootDir: string, options: IndexOptions = {}): Promise<ImportRelation[]> {
  const paths = await sourceFiles(rootDir, options);
  const knownPaths = new Set(paths.map((path) => relative(rootDir, path)));
  const imports = await Promise.all(paths.map(async (path) => extractImports(relative(rootDir, path), await readFile(path, "utf8"), knownPaths)));
  return imports.flat();
}

/** Indexes static external package imports without reading node_modules or running code. */
export async function indexDependencyUsages(rootDir: string, options: IndexOptions = {}): Promise<DependencyUsage[]> {
  const paths = await sourceFiles(rootDir, options);
  const usages = await Promise.all(paths.map(async (path) => extractDependencyUsages(relative(rootDir, path), await readFile(path, "utf8"))));
  return usages.flat();
}

/** Finds repeated source blocks and functions with a simple cyclomatic-complexity signal. */
export async function indexQualitySignals(rootDir: string, options: IndexOptions & { quality?: QualityOptions } = {}): Promise<QualitySignal[]> {
  const paths = await sourceFiles(rootDir, options);
  const sources = await Promise.all(paths.map(async (path) => ({ path: relative(rootDir, path), source: await readFile(path, "utf8") })));
  const knownPaths = new Set(sources.map((item) => item.path));
  const imports = sources.flatMap(({ path, source }) => extractImports(path, source, knownPaths));
  return correlateQualitySignals([...duplicateSignals(sources, options.quality?.duplicateBlockLines), ...functionDuplicateSignals(sources), ...sources.flatMap(({ path, source }) => maintainabilitySignals(path, source, options.quality)), ...unreferencedFileSignals([...knownPaths], imports)])
    .sort((left, right) => right.score - left.score || left.path.localeCompare(right.path) || left.line - right.line);
}

/** Reports non-entry source files without an observed local static import. */
export function unreferencedFileSignals(paths: string[], imports: ImportRelation[]): QualitySignal[] {
  const imported = new Set(imports.map((relation) => relation.to));
  return paths.filter((path) => !imported.has(path) && !isLikelyEntryPoint(path)).map((path) => ({
    kind: "unreferenced-file" as const, path, line: 1, score: 1,
    title: "No local static import observed",
    detail: "This may be an unused file, an application entry point, dynamically loaded code, or consumed by another package. Review before removal."
  }));
}

function isLikelyEntryPoint(path: string): boolean {
  return /(?:^|\/)(?:index|main|app|server|cli)\.(?:js|jsx|ts|tsx)$/.test(path);
}

export function extractSymbols(path: string, source: string): CodeSymbol[] {
  const parser = parserForPath(path);
  const symbols: CodeSymbol[] = [];
  const visit = (node: Parser.SyntaxNode): void => {
    const kind = node.type === "function_declaration" ? "function"
      : node.type === "class_declaration" ? "class"
      : node.type === "method_definition" ? "method"
      : node.type === "interface_declaration" ? "interface" : undefined;
    if (kind) {
      const name = node.childForFieldName("name")?.text;
      if (name) symbols.push({ id: `symbol:${path}:${name}:${node.startPosition.row + 1}`, path, name, kind, line: node.startPosition.row + 1, column: node.startPosition.column + 1, endLine: node.endPosition.row + 1, endColumn: node.endPosition.column + 1 });
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(parser.parse(source).rootNode);
  return symbols;
}

export function extractImports(path: string, source: string, knownPaths: Set<string>): ImportRelation[] {
  const parser = parserForPath(path);
  const imports: ImportRelation[] = [];
  const visit = (node: Parser.SyntaxNode): void => {
    if (node.type === "import_statement" || node.type === "export_statement") {
      const sourceValue = node.namedChildren.find((child) => child.type === "string")?.text.slice(1, -1);
      if (sourceValue?.startsWith(".")) {
        const target = resolveImport(path, sourceValue, knownPaths);
        if (target) imports.push({ from: path, to: target, source: sourceValue });
      }
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(parser.parse(source).rootNode);
  return imports;
}

export function extractDependencyUsages(path: string, source: string): DependencyUsage[] {
  const usages: DependencyUsage[] = [];
  const parser = parserForPath(path);
  const addUsage = (sourceValue: string | undefined, node: Parser.SyntaxNode): void => {
    const packageName = packageFromSpecifier(sourceValue);
    if (!packageName) return;
    usages.push({ packageName, path, line: node.startPosition.row + 1, column: node.startPosition.column + 1, source: sourceValue! });
  };
  const visit = (node: Parser.SyntaxNode): void => {
    if (node.type === "import_statement" || node.type === "export_statement") {
      const sourceNode = node.namedChildren.find((child) => child.type === "string");
      addUsage(sourceNode ? unquote(sourceNode.text) : undefined, sourceNode ?? node);
    }
    if (node.type === "call_expression" && node.childForFieldName("function")?.text === "require") {
      const argument = node.childForFieldName("arguments")?.namedChildren.find((child) => child.type === "string");
      addUsage(argument ? unquote(argument.text) : undefined, argument ?? node);
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(parser.parse(source).rootNode);
  return uniqueUsages(usages);
}

export function duplicateSignals(sources: Array<{ path: string; source: string }>, blockLines = 6): QualitySignal[] {
  const blocks = new Map<string, Array<{ path: string; line: number }>>();
  for (const { path, source } of sources) {
    const lines = source.split(/\r?\n/);
    for (let index = 0; index <= lines.length - blockLines; index += 1) {
      const block = lines.slice(index, index + blockLines).map(normalizeLine);
      if (block.some((line) => line.length === 0)) continue;
      const key = block.join("\n");
      const locations = blocks.get(key) ?? [];
      locations.push({ path, line: index + 1 });
      blocks.set(key, locations);
    }
  }
  const signals = [...blocks.values()].flatMap((locations) => {
    const distinct = locations.filter((location, index) => index === 0 || location.path !== locations[index - 1]?.path || location.line > (locations[index - 1]?.line ?? 0) + blockLines - 1);
    if (distinct.length < 2) return [];
    return distinct.map((location) => ({
      kind: "duplicate-code" as const, path: location.path, line: location.line,
      title: `Repeated ${blockLines}-line source block (${distinct.length} occurrences)`,
      detail: "Normalized whitespace and comments match another local source block.", score: distinct.length,
      relatedLocations: distinct.filter((other) => other.path !== location.path || other.line !== location.line)
    }));
  });
  const retained: QualitySignal[] = [];
  for (const signal of signals.sort((left, right) => left.path.localeCompare(right.path) || left.line - right.line)) {
    const relatedKey = signal.relatedLocations?.map((location) => location.path).sort().join(",") ?? "";
    const previous = retained.find((candidate) => candidate.path === signal.path && candidate.kind === signal.kind && signal.line - candidate.line <= 5 && (candidate.relatedLocations?.map((location) => location.path).sort().join(",") ?? "") === relatedKey);
    if (!previous) retained.push(signal);
  }
  return retained;
}

/** Finds exact duplicate parsed function bodies, ignoring function names and formatting. */
export function functionDuplicateSignals(sources: Array<{ path: string; source: string }>): QualitySignal[] {
  const bodies = new Map<string, Array<{ path: string; line: number }>>();
  for (const { path, source } of sources) {
    const parser = parserForPath(path);
    const visit = (node: Parser.SyntaxNode): void => {
      if (["function_declaration", "method_definition", "arrow_function", "function_expression"].includes(node.type)) {
        const body = node.childForFieldName("body");
        if (body && body.endPosition.row - body.startPosition.row >= 2) {
          const key = normalizeLine(body.text).replace(/[{}]/g, "");
          if (key.length > 30) {
            const locations = bodies.get(key) ?? [];
            locations.push({ path, line: node.startPosition.row + 1 });
            bodies.set(key, locations);
          }
        }
      }
      for (const child of node.namedChildren) visit(child);
    };
    visit(parser.parse(source).rootNode);
  }
  return [...bodies.values()].flatMap((locations) => locations.length < 2 ? [] : locations.map((location) => ({
    kind: "duplicate-function" as const, path: location.path, line: location.line, score: locations.length,
    title: `Repeated function body (${locations.length} occurrences)`,
    detail: "Parsed function bodies match after comments and whitespace are normalized.",
    relatedLocations: locations.filter((other) => other !== location)
  })));
}

export function complexitySignals(path: string, source: string, threshold = 10): QualitySignal[] {
  const parser = parserForPath(path);
  const signals: QualitySignal[] = [];
  const visit = (node: Parser.SyntaxNode): void => {
    if (["function_declaration", "method_definition", "arrow_function", "function_expression"].includes(node.type)) {
      const complexity = 1 + decisionCount(node);
      if (complexity >= threshold) {
        const name = node.childForFieldName("name")?.text ?? "anonymous function";
        signals.push({ kind: "high-complexity", path, line: node.startPosition.row + 1, title: `${name} has complexity ${complexity}`, detail: "Counted branches include conditionals, loops, catch clauses, switch cases, and ternaries.", score: complexity });
      }
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(parser.parse(source).rootNode);
  return signals;
}

export function maintainabilitySignals(path: string, source: string, options: QualityOptions = {}): QualitySignal[] {
  const parser = parserForPath(path);
  const signals: QualitySignal[] = [];
  const visit = (node: Parser.SyntaxNode): void => {
    if (["function_declaration", "method_definition", "arrow_function", "function_expression"].includes(node.type)) {
      const name = node.childForFieldName("name")?.text ?? "anonymous function";
      const line = node.startPosition.row + 1;
      const complexity = 1 + decisionCount(node);
      const lineCount = node.endPosition.row - node.startPosition.row + 1;
      const parameters = node.childForFieldName("parameters")?.namedChildCount ?? 0;
      const nesting = maxNesting(node);
      if (complexity >= (options.complexityThreshold ?? 10)) signals.push(signal("high-complexity", path, line, complexity, `${name} has complexity ${complexity}`, "Counted branches include conditionals, loops, catch clauses, switch cases, and ternaries."));
      if (lineCount >= (options.functionLineThreshold ?? 50)) signals.push(signal("oversized-function", path, line, lineCount, `${name} spans ${lineCount} lines`, "Large functions can be harder to test and change safely."));
      if (parameters >= (options.parameterThreshold ?? 5)) signals.push(signal("excessive-parameters", path, line, parameters, `${name} has ${parameters} parameters`, "Many parameters can indicate that a value object or smaller operation would be clearer."));
      if (nesting >= (options.nestingThreshold ?? 4)) signals.push(signal("deep-nesting", path, line, nesting, `${name} nests control flow ${nesting} levels deep`, "Deeply nested control flow can make behavior harder to follow and test."));
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(parser.parse(source).rootNode);
  return signals;
}

function signal(kind: QualitySignal["kind"], path: string, line: number, score: number, title: string, detail: string): QualitySignal { return { kind, path, line, score, title, detail }; }

function maxNesting(node: Parser.SyntaxNode): number {
  let maximum = 0;
  const visit = (current: Parser.SyntaxNode, depth: number): void => {
    if (current !== node && ["function_declaration", "method_definition", "arrow_function", "function_expression"].includes(current.type)) return;
    const nested = ["if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement", "switch_statement", "try_statement"].includes(current.type) ? depth + 1 : depth;
    maximum = Math.max(maximum, nested);
    for (const child of current.namedChildren) visit(child, nested);
  };
  visit(node, 0);
  return maximum;
}

function decisionCount(node: Parser.SyntaxNode): number {
  let count = 0;
  const visit = (current: Parser.SyntaxNode): void => {
    if (current !== node && ["function_declaration", "method_definition", "arrow_function", "function_expression"].includes(current.type)) return;
    if (["if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement", "catch_clause", "switch_case", "ternary_expression"].includes(current.type)) count += 1;
    for (const child of current.namedChildren) visit(child);
  };
  visit(node);
  return count;
}

function normalizeLine(line: string): string {
  return line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "").replace(/\s+/g, " ").trim();
}

function parserForPath(path: string): Parser {
  const parser = new Parser();
  parser.setLanguage(path.endsWith(".ts") || path.endsWith(".tsx") ? (path.endsWith(".tsx") ? TypeScript.tsx : TypeScript.typescript) : JavaScript);
  return parser;
}

function unquote(value: string): string { return value.slice(1, -1); }

function packageFromSpecifier(source: string | undefined): string | undefined {
  if (!source || source.startsWith(".") || source.startsWith("/") || source.startsWith("node:")) return undefined;
  const segments = source.split("/");
  if (source.startsWith("@")) return segments.length >= 2 ? `${segments[0]}/${segments[1]}` : undefined;
  return segments[0];
}

function uniqueUsages(usages: DependencyUsage[]): DependencyUsage[] {
  const seen = new Set<string>();
  return usages.filter((usage) => {
    const key = `${usage.path}:${usage.line}:${usage.column}:${usage.source}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function resolveImport(from: string, source: string, knownPaths: Set<string>): string | undefined {
  const raw = join(dirname(from), source);
  const base = extname(raw) ? raw.slice(0, -extname(raw).length) : raw;
  return [raw, ...[".ts", ".tsx", ".js", ".jsx"].map((extension) => `${base}${extension}`)].find((candidate) => knownPaths.has(candidate));
}

async function sourceFiles(directory: string, options: IndexOptions): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return ignoredDirectories.has(entry.name) ? [] : sourceFiles(path, options);
    if (!/\.(?:js|jsx|ts|tsx)$/.test(entry.name)) return [];
    if (!options.includeTests && /\.(?:test|spec)\.(?:js|jsx|ts|tsx)$/.test(entry.name)) return [];
    return [path];
  }));
  return paths.flat();
}
