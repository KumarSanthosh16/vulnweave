import { access, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const starterConfig = `# Review and commit this policy with your repository.\nschemaVersion: 1\nanalyzer: all\n# For a focused scanner set, replace the line above with:\n# analyzers: [gitleaks, osv, semgrep]\nsemgrepConfig: rules/vulnweave-starter.yml\nbaselinePolicy: vulnweave.baseline.json\n\n# Optional project-specific ownership rules. They override matching CODEOWNERS entries.\n# owners:\n#   - pattern: services/payments/**\n#     owners: ["@payments-team"]\n`;

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
  - id: vulnweave.python.no-shell-true
    message: Avoid shell=True with subprocess calls; pass an argument list and validate untrusted input instead.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: CWE-78
      technology: [python]
    pattern: subprocess.$FUNC(..., shell=True, ...)
  - id: vulnweave.python.redirecting-request
    message: Review redirecting outbound requests. User-controlled URLs can create SSRF paths.
    languages: [python]
    severity: WARNING
    metadata:
      category: security
      cwe: CWE-918
      technology: [python]
    pattern: requests.$METHOD(..., allow_redirects=True, ...)
  - id: vulnweave.python.insecure-tls-verification
    message: Do not disable TLS certificate verification for outbound requests.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: CWE-295
      technology: [python]
    pattern: requests.$METHOD(..., verify=False, ...)
`;

export interface InitializationResult { created: string[]; existing: string[]; }

/** Creates an explicit, reviewable local policy without overwriting user files. */
export async function initializeProject(rootDir: string): Promise<InitializationResult> {
  const legacyConfigExists = await exists(join(rootDir, "vulnweave.config.json"));
  const files = [
    ...(legacyConfigExists ? [] : [[".vulnweave.yml", starterConfig] as const]),
    ["vulnweave.baseline.json", `${JSON.stringify(starterBaseline, null, 2)}\n`],
    ["rules/vulnweave-starter.yml", starterSemgrepRules]
  ] as const;
  const result: InitializationResult = { created: [], existing: legacyConfigExists ? ["vulnweave.config.json"] : [] };
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

async function exists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export function formatInitialization(result: InitializationResult): string {
  const created = result.created.length > 0 ? `Created: ${result.created.join(", ")}` : "Created: none";
  const existing = result.existing.length > 0 ? `Already present (left unchanged): ${result.existing.join(", ")}` : "Already present: none";
  return `VulnWeave is ready.\n${created}\n${existing}\n\nNext: vulnweave scan .`;
}
