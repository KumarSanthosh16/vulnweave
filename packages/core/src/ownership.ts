import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Finding } from "./schemas.js";

export interface CodeOwnersRule { pattern: string; owners: string[]; }
export interface FindingOwnership { findingId: string; path?: string; owners: string[]; }

/** Loads the first standard CODEOWNERS file found in the project, if any. */
export async function loadCodeOwners(rootDir: string): Promise<CodeOwnersRule[]> {
  for (const path of [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]) {
    try { return parseCodeOwners(await readFile(join(rootDir, path), "utf8")); } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
    }
  }
  return [];
}

/** Parses the portable subset of GitHub CODEOWNERS needed for local routing. */
export function parseCodeOwners(source: string): CodeOwnersRule[] {
  return source.split("\n").flatMap((line) => {
    const meaningful = line.trim().replace(/\s+#.*$/, "");
    if (!meaningful || meaningful.startsWith("#")) return [];
    const [pattern, ...owners] = meaningful.split(/\s+/);
    return pattern && owners.length > 0 ? [{ pattern, owners }] : [];
  });
}

/** Applies GitHub's last-match-wins rule to a repository-relative path. */
export function ownersForPath(path: string, rules: CodeOwnersRule[]): string[] {
  let owners: string[] = [];
  for (const rule of rules) if (matches(path, rule.pattern)) owners = rule.owners;
  return owners;
}

export function assignFindingOwners(findings: Finding[], rules: CodeOwnersRule[]): FindingOwnership[] {
  return findings.map((finding) => ({ findingId: finding.id, path: finding.location?.path, owners: finding.location ? ownersForPath(finding.location.path, rules) : [] }));
}

export function formatOwnershipTable(findings: Finding[], ownership: FindingOwnership[], rules: CodeOwnersRule[]): string {
  if (rules.length === 0) return "No CODEOWNERS file was found. Add .github/CODEOWNERS to enable local ownership routing.";
  const findingById = new Map(findings.map((finding) => [finding.id, finding]));
  const rows = ownership.flatMap((item) => {
    const finding = findingById.get(item.findingId);
    return finding ? [[finding.severity.toUpperCase(), item.path ?? "—", item.owners.join(", ") || "Unassigned", finding.title]] : [];
  });
  if (rows.length === 0) return `CODEOWNERS loaded (${rules.length} rules), but this scan has no findings to route.`;
  const headers = ["SEVERITY", "PATH", "OWNERS", "FINDING"];
  const widths = headers.map((header, index) => Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)));
  const render = (cells: string[]) => cells.map((cell, index) => cell.padEnd(widths[index] ?? cell.length)).join("  ");
  return [render(headers), render(widths.map((width) => "-".repeat(width))), ...rows.map(render)].join("\n");
}

function matches(path: string, pattern: string): boolean {
  const normalizedPath = path.replaceAll("\\", "/");
  const normalizedPattern = pattern.replaceAll("\\", "/");
  const glob = normalizedPattern.endsWith("/") ? `${normalizedPattern}**` : normalizedPattern;
  const expression = globToRegExp(glob.startsWith("/") ? glob.slice(1) : glob);
  if (expression.test(normalizedPath)) return true;
  // A pattern without a slash applies to a matching filename anywhere in the tree.
  return !glob.includes("/") && expression.test(normalizedPath.split("/").at(-1) ?? "");
}

function globToRegExp(pattern: string): RegExp {
  let expression = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    const next = pattern[index + 1];
    if (character === undefined) continue;
    if (character === "*" && next === "*") { expression += ".*"; index += 1; }
    else if (character === "*") expression += "[^/]*";
    else if (character === "?") expression += "[^/]";
    else expression += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
  }
  return new RegExp(`^${expression}$`);
}
