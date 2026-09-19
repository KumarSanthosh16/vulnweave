import { readFile, readdir } from "node:fs/promises";
import { dirname, extname, join, relative } from "node:path";
import Parser from "tree-sitter";
import JavaScript from "tree-sitter-javascript";
import TypeScript from "tree-sitter-typescript";
import type { CodeSymbol, DependencyUsage, ImportRelation } from "@vulnweave/core";
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
