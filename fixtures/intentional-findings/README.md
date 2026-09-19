# Intentional findings fixture

This small project is safe test data for VulnWeave. It contains no credentials, no production code, and no installable vulnerable dependency.

- `src/eval-demo.ts` is a harmless Semgrep demonstration.

VulnWeave excludes `fixtures/` when scanning a repository root, so normal project scans remain clean. To exercise the source-pattern fixture directly from the workspace root:

```bash
pnpm cli -- fixtures/intentional-findings --analyzer semgrep --semgrep-config rules/semgrep-starter.yml --format table
```

The automated test suite uses deterministic scanner-shaped data to cover Trivy normalization, correlation, graph generation, prioritization, SARIF, and gates without requiring network access or external scanner databases.
