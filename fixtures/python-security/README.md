# Python security fixture

This directory deliberately contains unsafe Python patterns. It is a demo-only fixture, not application code.

From the VulnWeave repository root, validate the Python starter pack with:

```bash
pnpm cli -- fixtures/python-security --analyzer semgrep --semgrep-config rules/packs/python-security.yml --format table
```

The expected result is three Semgrep findings: `shell=True`, redirect-following requests, and disabled TLS verification.
