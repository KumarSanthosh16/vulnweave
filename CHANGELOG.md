# Changelog

All notable changes to VulnWeave are documented here.

## 0.2.0 — Unreleased

### Added

- Portable finding-baseline files for new-findings-only CI gates.
- Scanner-reported dependency upgrade plans and ecosystem-aware guidance for Python requirements and npm manifests.
- Focused local Semgrep packs for Python and Node web-service settings, with safe fixtures.
- An npm-ready `@vulnweave/cli` package that bundles the CLI, reviewed rules, and required legal notices while keeping scanner binaries external.

### Changed

- The public documentation now includes npm installation guidance and continues to document source-checkout use for contributors.
- Named Semgrep packs resolve from VulnWeave itself, so they work when scanning another checkout.

### Compatibility

- Requires Node.js 20 or later, pnpm 12 for source development, and separately installed supported analyzers.

## 0.1.0

### Added

- Local-first orchestration for Gitleaks, Semgrep, OSV-Scanner, and Trivy.
- Normalized findings and first-class evidence, including overlap correlation.
- Local HTML and SARIF reports, trends, baselines, gates, suppressions, and CI support.
- Evidence graph, source-symbol links, dependency import observations, ownership routing, and changed-code review.
- Advisory code-quality signals for complexity, duplicate implementations, nesting, function size, parameters, and unreferenced files.
- Static Astro documentation site for users and contributors.

### Security and privacy

- Source code and saved scan history remain local unless a user explicitly exports an artifact.
- Normalized secret findings deliberately omit matched secret values.
