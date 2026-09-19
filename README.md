# VulnWeave

VulnWeave is a local-first code quality and security product that turns tool output into durable, explainable evidence and eventually into impact-aware reasoning. This repository establishes the internal boundary before scanner integrations are added.

## What works now

The runnable CLI drives a deterministic mock analyzer through the complete core pipeline:

```text
Analyzer Adapter → Orchestrator → normalized Finding + Evidence → JSON CLI output
```

Run it after installing dependencies:

```bash
pnpm install
pnpm test
pnpm cli
```

Pass a repository path with `pnpm cli -- /path/to/repository`. The mock is intentional: it verifies contracts and developer workflow without requiring an external binary, credentials, or a source checkout.

## Structure

```text
packages/
  core/          Analyzer API, normalized schemas, orchestration state machine
  gitleaks-analyzer/ Local secrets adapter
  mock-analyzer/ Minimal adapter fixture used end-to-end
  osv-analyzer/      Local dependency-vulnerability adapter
  semgrep-analyzer/ Local source-pattern adapter
  trivy-analyzer/    Local dependency and configuration adapter
  cli/           Small executable boundary for local runs
```

## Core contracts

`AnalyzerAdapter` is the narrow integration seam. An adapter owns invoking a third-party tool and converting its native output into `FindingInput`. The core owns normalization and rejects invalid normalized results.

Every `Finding` has an analyzer, rule ID, category, severity, human-readable explanation, optional location, and zero or more `Evidence` objects. Evidence is deliberately first-class: later graph and AI features should cite evidence rather than invent claims. IDs are deterministic when an adapter does not supply one.

The `AnalysisOrchestrator` moves one run through `idle → preparing → running → normalizing → completed`, with explicit `failed` and `cancelled` terminal states. It is intentionally small today; future queueing, caching, progress events, cancellation signals, and multi-analyzer aggregation belong here rather than in adapters.

## MVP direction

The real adapters are Gitleaks (secrets), Semgrep CE (source patterns), OSV-Scanner (dependency vulnerabilities), and Trivy (filesystem dependencies and configuration). Run `pnpm cli -- . --analyzer gitleaks` after installing [Gitleaks](https://github.com/gitleaks/gitleaks); matched secret text is deliberately excluded from the normalized result. Semgrep uses an explicit local rules file: `pnpm cli -- . --analyzer semgrep --semgrep-config rules/semgrep-starter.yml`. This repository includes that small starter policy, which flags JavaScript/TypeScript `eval` usage. Run `pnpm cli -- . --analyzer osv` after installing [OSV-Scanner](https://google.github.io/osv-scanner/installation/). OSV-Scanner examines local manifests and lockfiles, then queries the OSV vulnerability database for advisories. Run `pnpm cli -- . --analyzer trivy --format summary` after installing [Trivy](https://trivy.dev/latest/docs/); it enables Trivy's vulnerability and misconfiguration scanners, while Gitleaks remains the dedicated secret scanner. Trivy may overlap OSV on dependency advisories; that is intentional for now, because its configuration coverage adds a distinct evidence source. Each analyzer remains a replaceable worker; their outputs converge on the same schema, then feed a future evidence graph that connects findings to symbols, files, dependencies, owners, and change impact.

Tree-sitter belongs beside that graph as a local code-structure provider, not as an analyzer replacement. AI should consume normalized evidence and graph context to explain prioritization or propose remediation; it must not be the source of record for scanner claims.

## Development checks

`pnpm check` performs strict TypeScript checks. `pnpm test` validates schema rejection/acceptance and the orchestrator's success and failure flows. `pnpm build` produces ESM packages under each `dist/` folder.

## Safe end-to-end fixture

`fixtures/intentional-findings/` is a tiny, non-production project for manually validating the Semgrep path. It contains no secret-like values, scanner-detectable configuration, or vulnerable package lockfile. The automated suite uses deterministic scanner-shaped observations to exercise Trivy normalization, correlation, evidence graph generation, priority ranking, SARIF output, and gate behavior without relying on scanner downloads or vulnerability databases. The directory is excluded from normal repository-wide Semgrep, Trivy, and source-index scans, so it does not create noise in VulnWeave's own report.

## Local history and comparison

Every CLI scan is saved locally under `.vulnweave/runs/`; the most recent scan is also stored as `.vulnweave/latest.json`. These files are ignored by Git. Existing `.signal-impact/` reports remain readable after the rename. Use a concise terminal report with `pnpm cli -- . --analyzer osv --format summary`, or compare a fresh scan with the previous one using `pnpm cli -- . --analyzer osv --format summary --compare latest`. Add `--no-save` for an entirely ephemeral run.

Run the available real analyzers together with `pnpm cli -- . --analyzer all --semgrep-config rules/semgrep-starter.yml --format summary`. A failed or unavailable scanner is recorded in the summary and does not prevent the other scanners from producing findings. For CI, add `--require-analyzers`: this exits unsuccessfully if any selected analyzer is unavailable or fails, independently of the finding-severity gate.

## Project policy

`vulnweave.config.json` is a versioned, committed policy file. This repository configures all local analyzers, the starter Semgrep rules, a high-severity gate, and required analyzer health. With that file in a scanned repository, `pnpm cli -- . --format summary` uses those defaults; an explicitly supplied CLI option takes precedence. Keep local state and reports under `.vulnweave/`, not in this policy file.

### Time-bounded suppressions

Use a suppression only for an explicitly reviewed finding fingerprint. Every entry requires a reason, an owner, and an expiry date. An active suppression remains visible in JSON, tables, graphs, and scan history, but is excluded from the severity gate; after its expiry date, it automatically becomes gate-eligible again.

```json
{
  "suppressions": [{
    "fingerprint": "scanner-stable-fingerprint",
    "reason": "Accepted until the upstream upgrade window.",
    "owner": "team@example.com",
    "expiresOn": "2026-12-31"
  }]
}
```

## Finding correlation

When OSV-Scanner and Trivy report the same package advisory, VulnWeave correlates the scanner observations into one canonical dependency issue. It preserves all underlying evidence and chooses the highest reported severity, so summaries, priorities, SARIF export, and gates do not double-count the same advisory. The summary only prints a `Correlation:` line when this reduces the number of findings. Analyzer filtering still recognizes each contributing scanner, such as `--filter-analyzer osv`.

## Triage views

Use `--format table` for a compact finding list, then narrow it without changing the saved result: `pnpm cli -- . --analyzer all --semgrep-config rules/semgrep-starter.yml --format table --severity high`, `--category dependency`, or `--filter-analyzer osv`.

## Evidence graph

Each saved scan now writes a local graph JSON file to `.vulnweave/graphs/`. It connects normalized findings to source files, scanner evidence, and affected dependencies. View its compact shape with `pnpm cli -- . --analyzer all --semgrep-config rules/semgrep-starter.yml --format graph`. This is the stable foundation for later Tree-sitter symbol and impact relationships.

When a dependency finding has static JavaScript or TypeScript import evidence, the graph also connects that dependency node to each importing file. This is evidence of an indexed static import, not a runtime-reachability claim.

## Tree-sitter symbols

VulnWeave now indexes JavaScript, TypeScript, and TSX declarations locally with Tree-sitter. Run `pnpm cli -- . --analyzer all --semgrep-config rules/semgrep-starter.yml --format symbols` to list functions, classes, methods, and interfaces with their source locations. Every scan links a source finding to its narrowest enclosing symbol, then persists that relationship in the evidence graph.

## Evidence-backed priority

Use `--format priorities` to rank findings deterministically. The score starts with scanner severity, then adds explicit evidence-based signals for potential credentials, dependency exposure, symbol mapping, changed source files, and multiple evidence items. It never changes scanner severity or uses an AI model to invent risk: `pnpm cli -- . --analyzer all --semgrep-config rules/semgrep-starter.yml --format priorities`. Git context is optional; scans outside a Git repository simply have no changed-file signal.

## Dependency reachability

For dependency findings, `pnpm cli -- . --format reachability` identifies whether the affected package is statically imported by indexed JavaScript or TypeScript source. A `referenced` result contributes a small, explicit priority signal. `not-observed` only means no indexed static import was found—it never claims that a package is runtime-unreachable, because dynamic imports, generated code, other languages, and deployment configuration may still use it. The same evidence appears in the HTML report when dependency findings exist.

## Remediation guidance

Use `pnpm cli -- . --format remediation` for deterministic next-step guidance. It derives an advisory from the normalized finding: dependency findings use the package and fixed-version evidence when available; secret findings recommend rotation without exposing matched text; source and configuration findings retain their reported location. Guidance never changes code, dependencies, credentials, or configuration. It is also included in the local HTML report.

## Local ownership routing

VulnWeave optionally reads `.github/CODEOWNERS`, `CODEOWNERS`, or `docs/CODEOWNERS` using GitHub's last-match-wins convention. Use `pnpm cli -- . --format ownership` to route source findings to the matching owners. When no CODEOWNERS file is present, the command reports that ownership routing is not configured; it never invents owners. Routed owners also appear beside findings in the HTML report.

## Change impact

Use `--changed-since <git-ref> --format changes` to compare the current `HEAD` with a Git reference. VulnWeave reports changed files, local files that import them (including transitive dependents), and findings directly located in either set. For example: `pnpm cli -- . --changed-since main --format changes`. This is an impact-focused review aid; it does not claim runtime reachability or replace the normal severity gate.

For a pull-request-focused severity gate, add `--review-changes`: `pnpm cli -- . --changed-since main --review-changes --format summary`. It evaluates only findings in changed JavaScript/TypeScript files and their local import dependents. The scanners still inspect the whole repository and the normal full-repository gate remains the recommended protected-branch check. The command fails clearly when Git change context is unavailable rather than silently evaluating an empty scope.

Use `--format review` to produce one copyable review packet for a Git change: `pnpm cli -- . --changed-since main --format review`. It combines changed and import-affected findings with deterministic priority, CODEOWNERS routing, and remediation guidance. It does not post comments or contact owners.

## Local HTML report

Create a self-contained dashboard from a scan record without starting a server or sending data anywhere:

```bash
pnpm build
node packages/cli/dist/index.js . --format html > vulnweave-report.html
```

Open `vulnweave-report.html` locally. It shows severity totals, gate and analyzer status, findings (including suppression status), priorities, evidence graph totals, and recent local trend history.

## Local trends

Use `pnpm cli -- . --format trend` to view recent saved scans. Add `--history 20` to inspect a longer local history. Each row shows severity totals, new and resolved findings compared with the prior scan, gate status, and analyzer health. No report data leaves the machine.
