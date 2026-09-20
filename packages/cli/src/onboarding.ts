import { access, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const starterConfig = {
  schemaVersion: 1,
  analyzer: "all",
  semgrepConfig: "rules/vulnweave-starter.yml",
  baselinePolicy: "vulnweave.baseline.json"
};

const starterBaseline = {
  schemaVersion: 1,
  failOn: "high",
  requireAnalyzers: true,
  suppressions: []
};

const starterSemgrepRules = `rules:
  - id: vulnweave.security.no-eval
    message: Avoid eval: executing dynamic input can create a code-injection risk.
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      category: security
      technology: [javascript, typescript]
    patterns:
      - pattern: eval(...)
`;

export interface InitializationResult { created: string[]; existing: string[]; }

/** Creates an explicit, reviewable local policy without overwriting user files. */
export async function initializeProject(rootDir: string): Promise<InitializationResult> {
  const files = [
    ["vulnweave.config.json", `${JSON.stringify(starterConfig, null, 2)}\n`],
    ["vulnweave.baseline.json", `${JSON.stringify(starterBaseline, null, 2)}\n`],
    ["rules/vulnweave-starter.yml", starterSemgrepRules]
  ] as const;
  const result: InitializationResult = { created: [], existing: [] };
  for (const [relativePath, content] of files) {
    const path = join(rootDir, relativePath);
    try {
      await access(path);
      result.existing.push(relativePath);
      continue;
    } catch {
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, content, "utf8");
      result.created.push(relativePath);
    }
  }
  return result;
}

export function formatInitialization(result: InitializationResult): string {
  const created = result.created.length > 0 ? `Created: ${result.created.join(", ")}` : "Created: none";
  const existing = result.existing.length > 0 ? `Already present (left unchanged): ${result.existing.join(", ")}` : "Already present: none";
  return `VulnWeave is ready.\n${created}\n${existing}\n\nNext: vulnweave scan .`;
}
