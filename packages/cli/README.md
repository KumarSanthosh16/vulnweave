# VulnWeave CLI

VulnWeave is a local-first security and code-quality impact-analysis command-line tool. It runs separately installed Gitleaks, Semgrep, OSV-Scanner, and Trivy binaries; normalizes their results; and produces local terminal, HTML, and SARIF reports.

## Install

```bash
npm install --global @vulnweave/cli
vulnweave doctor
vulnweave scan .
```

Install the supported scanner binaries separately before scanning. `vulnweave doctor` reports which are available. Scan source code and reports stay on the local machine unless a user explicitly uploads an output artifact elsewhere.

## Common commands

```bash
vulnweave init .
vulnweave scan .
vulnweave findings .
vulnweave quality .
vulnweave report . > vulnweave-report.html
vulnweave ci .
```

See the project documentation for configuration, supported analyzers, local Semgrep packs, CI gates, limitations, and licensing details:
https://kumarsanthosh16.github.io/vulnweave/

## License

Apache-2.0. The external scanner binaries are not bundled and retain their own licenses. See `THIRD_PARTY_NOTICES.md` in this package.
