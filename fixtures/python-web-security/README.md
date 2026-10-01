# Python web-security fixture

This demo-only directory deliberately includes an unsafe Flask-style debug setting
and an unverified TLS context. It is not application code.

From the VulnWeave repository root, validate the pack with:

```bash
pnpm cli -- fixtures/python-web-security --analyzer semgrep --semgrep-pack python-web-security --format table
```

The expected result is two Semgrep findings.
