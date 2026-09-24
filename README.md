# VulnWeave

<p align="center">
  <img src="apps/docs/public/vulnweave-logo.png" alt="VulnWeave" width="360" />
</p>

Licensed under the [Apache License 2.0](LICENSE). The local CLI and core are open source; any future hosted or enterprise products may be offered under separate commercial terms.

VulnWeave is a local-first security and code-impact analysis tool. It runs trusted open-source scanners against a repository, combines their results into one consistent view, removes duplicate dependency alerts, and helps developers decide what needs attention first.

It is designed for developers who want useful security feedback without sending source code or scan history to a hosted service. Scan data stays on the local machine unless you explicitly export it.

## Why use VulnWeave?

Security scanners are valuable, but their output is often fragmented: one tool detects secrets, another finds vulnerable packages, another flags risky code, and each uses a different report format. VulnWeave is the evidence and workflow layer above those scanners.

It answers practical questions:

- What issues were found across all scanners?
- Which reports describe the same dependency vulnerability?
- Is this issue new, or is it already an accepted baseline issue?
- Which findings are highest priority based on local code and dependency evidence?
- Can this change pass a security gate in CI?

VulnWeave does not replace security review, penetration testing, or the scanners it runs. It does not automatically change code, dependencies, or credentials. Its dependency usage result only reports observed static JavaScript/TypeScript imports; it never claims a package is runtime-safe or unreachable.

## What it does today

- Runs Gitleaks, Semgrep, OSV-Scanner, and Trivy locally.
- Normalizes results into one portable finding and evidence schema.
- Correlates overlapping OSV and Trivy dependency advisories into canonical issues.
- Produces terminal views, JSON, SARIF, and a self-contained HTML report.
- Enforces severity and analyzer-health gates for local use and CI.
- Supports baseline-aware scans, local history, trends, and reviewed suppressions.
- Builds local evidence graphs, code-symbol links, dependency import observations, priority rankings, remediation advice, upgrade plans, ownership routing, and changed-code review context.
- Provides advisory code-quality feedback for duplicate implementations, complexity, deep nesting, oversized functions, excessive parameters, and potential unreferenced files.

## Quick start

This repository is currently run from a source checkout. Install the required scanner binaries—Gitleaks, Semgrep, OSV-Scanner, and Trivy—then install the workspace dependencies:

```bash
pnpm install
pnpm cli -- init .
pnpm cli -- doctor
pnpm cli -- scan .
pnpm cli -- findings .
pnpm cli -- quality .
pnpm cli -- report . > vulnweave-report.html
```

Open `vulnweave-report.html` locally to view the dashboard. The project configuration (`vulnweave.config.json`) selects the analyzers and rules; `vulnweave.baseline.json` defines the reviewable gate policy. Scan history is stored locally in `.vulnweave/` and is ignored by Git.

`init` never overwrites existing policy files. It creates a starter configuration, a High-severity baseline policy, and a small Semgrep rule file for projects that do not already have them. Review these files before committing them to a repository.

For continuous integration, use:

```bash
pnpm cli -- ci .
```

The command exits unsuccessfully when findings violate the configured policy or a required analyzer is unavailable. That is intended behavior for a security gate.

## Documentation

This README is the project overview and fast path for evaluators, users, and contributors. The complete technical documentation lives in `apps/docs/`; it is a static Astro site with no runtime backend or telemetry. It includes:

- Beginner onboarding, prerequisites, first scan, and report reading.
- Full command, format, filtering, saved-history, and baseline reference.
- Project configuration, baseline policy, time-bounded suppressions, and quality gates.
- Analyzer setup, local Semgrep packs, custom Gitleaks configuration, and scanner limitations.
- CI, HTML/SARIF reports, trends, remediation, upgrades, ownership, evidence graph, dependency reachability, and changed-code review.
- Architecture, contribution rules, release process, licensing, and security reporting.

Run it locally with:

```bash
pnpm docs:dev
```

Create the deployable static output with `pnpm docs:build`; Astro writes it to `apps/docs/dist/`.

The README deliberately retains the most important commands, configuration examples, scanner model, legal notices, and development workflow below, so a GitHub visitor can understand and try the project without leaving this page.

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
apps/
  docs/          Static Astro documentation site
```

## Core contracts

`AnalyzerAdapter` is the narrow integration seam. An adapter owns invoking a third-party tool and converting its native output into `FindingInput`. The core owns normalization and rejects invalid normalized results.

Every `Finding` has an analyzer, rule ID, category, severity, human-readable explanation, optional location, and zero or more `Evidence` objects. Evidence is deliberately first-class: later graph and AI features should cite evidence rather than invent claims. IDs are deterministic when an adapter does not supply one.

The `AnalysisOrchestrator` moves one run through `idle → preparing → running → normalizing → completed`, with explicit `failed` and `cancelled` terminal states. It is intentionally small today; future queueing, caching, progress events, cancellation signals, and multi-analyzer aggregation belong here rather than in adapters.

## Scanner support and architecture

The current adapters are Gitleaks (secrets), Semgrep CE (source patterns), OSV-Scanner (dependency vulnerabilities), and Trivy (filesystem dependencies and configuration). Run `pnpm cli -- doctor` to confirm their availability. Matched secret text is deliberately excluded from normalized results. Semgrep uses local rules; this repository includes `rules/semgrep-starter.yml`, which flags JavaScript/TypeScript `eval` usage. Trivy may overlap OSV on dependency advisories; VulnWeave intentionally keeps their evidence, then correlates the duplicate advisory into one canonical issue.

Each analyzer remains a replaceable worker. Its output converges on the same schema and evidence graph, connecting findings to symbols, files, dependencies, owners, and change impact. This makes the results explainable and creates a safe foundation for later AI-assisted explanation features: any future AI output must cite the scanner evidence rather than invent security claims.

### Optional local policy packs

The default `semgrep-starter.yml` stays deliberately small. Add a reviewed pack explicitly with `--semgrep-pack typescript-security` (dynamic-code and direct child-process execution checks) or `--semgrep-pack typescript-quality` (diagnostic `console.log` checks). Packs are additive, so this enables the starter policy plus the selected pack:

```bash
pnpm cli -- . --analyzer semgrep --semgrep-pack typescript-security --format table
pnpm cli -- . --analyzer semgrep --semgrep-pack typescript-quality --format table
```

Pack rules are versioned local YAML under `rules/packs/`, and each finding retains its `vulnweavePack` metadata for provenance. Review and tune local rules before enabling them in a merge gate.

Tree-sitter belongs beside that graph as a local code-structure provider, not as an analyzer replacement. AI should consume normalized evidence and graph context to explain prioritization or propose remediation; it must not be the source of record for scanner claims.

## Development checks

`pnpm check` performs strict TypeScript checks. `pnpm test` validates schema rejection/acceptance and the orchestrator's success and failure flows. `pnpm build` produces ESM packages under each `dist/` folder.

## Safe end-to-end fixture

`fixtures/intentional-findings/` is a tiny, non-production project for manually validating the Semgrep path. It contains no secret-like values, scanner-detectable configuration, or vulnerable package lockfile. The automated suite uses deterministic scanner-shaped observations to exercise Trivy normalization, correlation, evidence graph generation, priority ranking, SARIF output, and gate behavior without relying on scanner downloads or vulnerability databases. The directory is excluded from normal repository-wide Semgrep, Trivy, and source-index scans, so it does not create noise in VulnWeave's own report.

## Local history and comparison

Every CLI scan is saved locally under `.vulnweave/runs/`; the most recent scan is also stored as `.vulnweave/latest.json`. These files are ignored by Git. Existing `.signal-impact/` reports remain readable after the rename. Use a concise terminal report with `pnpm cli -- . --analyzer osv --format summary`, or compare a fresh scan with the previous one using `pnpm cli -- . --analyzer osv --format summary --compare latest`. Add `--no-save` for an entirely ephemeral run.

Run the available real analyzers together with `pnpm cli -- . --analyzer all --semgrep-config rules/semgrep-starter.yml --format summary`. A failed or unavailable scanner is recorded in the summary and does not prevent the other scanners from producing findings. For CI, add `--require-analyzers`: this exits unsuccessfully if any selected analyzer is unavailable or fails, independently of the finding-severity gate.

## Installation diagnostics

Run `pnpm cli -- --version` to show the VulnWeave version and whether Gitleaks, Semgrep, OSV-Scanner, and Trivy are installed. This is read-only and does not scan the current project.

## Friendly commands

For everyday use, the CLI provides compact commands that use your committed project configuration:

```bash
pnpm cli -- scan .
pnpm cli -- findings .
pnpm cli -- priorities .
pnpm cli -- history .
pnpm cli -- review . --base main
pnpm cli -- ci .
pnpm cli -- doctor
```

`report` writes HTML to standard output so it can be saved without a server: `pnpm cli -- report . > vulnweave-report.html`. The existing flag-based interface remains available for scripting, filtering, and scanner-specific options.

`quality` is advisory-only by default. It reports correlated duplicate implementations (using normalized source-block and parsed function-body evidence), cyclomatic complexity, oversized functions, excessive parameter counts, deep nesting, and non-entry source files with no observed local static import. An unreferenced-file signal is not proof that code is dead: dynamic imports, framework routing, generated code, and other packages may still consume it.

Tune the advisory thresholds in `vulnweave.config.json` when a project needs a different standard:

```json
{
  "quality": {
    "complexityThreshold": 12,
    "duplicateBlockLines": 8,
    "nestingThreshold": 4,
    "functionLineThreshold": 60,
    "parameterThreshold": 5
  }
}
```

Quality signals are saved with scans. The HTML report presents duplicate and maintainability signals; use `pnpm cli -- quality .` for the complete list, including unreferenced-file review. They remain separate from security findings and gates unless you explicitly opt in to a quality gate:

```json
{
  "qualityGate": {
    "maxComplexitySignals": 8,
    "maxDuplicateCodeSignals": 2,
    "maxUnreferencedFiles": 0
  }
}
```

When configured, `pnpm cli -- ci .` exits unsuccessfully if any quality limit is exceeded. Start with advisory reports, tune thresholds for the project, and enable a quality gate only after reviewing the baseline.

For custom Gitleaks rules, prefer a portable project setting in `vulnweave.config.json`:

```json
{ "gitleaksConfig": ".gitleaks.toml" }
```

For a one-off scan, use `pnpm cli -- scan . --gitleaks-config .gitleaks.toml`.

## Project policy

`vulnweave.config.json` is a versioned, committed scan configuration. It selects analyzers, rules, and the baseline policy file. `vulnweave.baseline.json` is the separate reviewable risk policy: it holds the gate threshold, analyzer-health requirement, and approved exceptions. With both files committed, `pnpm cli -- . --format summary` uses those defaults; an explicitly supplied CLI option takes precedence. Keep local state and reports under `.vulnweave/`, not in either policy file.

## Third-party licensing

VulnWeave Core is licensed under Apache-2.0. It invokes Gitleaks, Semgrep Community Edition, OSV-Scanner, and Trivy as separately installed local tools and does not bundle their binaries. Their licenses and the direct runtime/development dependency inventory are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). See [SECURITY.md](SECURITY.md) for the vulnerability-reporting process and [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) before creating a public release. Any future hosted or enterprise offering will be governed by separate commercial terms and must keep a clear boundary from Apache-2.0 core code.

The included baseline starts with a high-severity gate and requires all selected analyzers to complete:

```json
{
  "schemaVersion": 1,
  "failOn": "high",
  "requireAnalyzers": true,
  "suppressions": []
}
```

### Time-bounded suppressions

Use a suppression only for an explicitly reviewed finding fingerprint, in `vulnweave.baseline.json`. Every entry requires a reason, an owner, and an expiry date. An active suppression remains visible in JSON, tables, graphs, and scan history, but is excluded from the severity gate; after its expiry date, it automatically becomes gate-eligible again.

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

The automated suite includes a deterministic gate fixture: a high finding must fail the baseline, and only an approved, unexpired suppression may let it pass. This keeps the CI gate behavior protected as policy handling evolves.

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

## Dependency upgrade planning

Use `pnpm cli -- . --format upgrades` to turn dependency findings into a non-mutating upgrade plan. When Trivy reports a fixed version, the plan shows it alongside the installed version and indexed import count. When no scanner-reported fixed version exists, the plan clearly requests manual advisory review rather than guessing a target version. It never edits lockfiles or packages.

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
