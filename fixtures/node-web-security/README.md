# Node web-security fixture

This demo-only directory deliberately includes unrestricted Express-style CORS and
globally disabled Node.js TLS verification. It is not application code.

From the VulnWeave repository root, validate the pack with:

```bash
pnpm cli -- fixtures/node-web-security --analyzer semgrep --semgrep-pack node-web-security --format table
```

The expected result is two Semgrep findings.
