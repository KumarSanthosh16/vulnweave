# Changelog

All notable changes to VulnWeave are documented here.

## 0.1.0 — Unreleased

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

### Compatibility

- Requires Node.js 22, pnpm 12, and separately installed supported analyzers.
