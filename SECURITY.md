# Security policy

## Reporting a vulnerability

Please do not include secrets, exploit payloads, or sensitive customer data in a public issue.

Before a public release, repository maintainers must enable GitHub Private Vulnerability Reporting and confirm that it is available for this repository. Once enabled, use the repository's **Security → Report a vulnerability** flow for confidential reports.

Until that setting is enabled, open a minimal public issue requesting a secure reporting channel without including vulnerability details. Maintainers should provide a private contact channel before any sensitive information is shared.

## Scope

VulnWeave Core runs local scanners and stores scan records on the local machine. Reports about unsafe handling of scan data, matched secret disclosure, command execution, dependency integrity, or misleading security claims are in scope.

Vulnerabilities reported by a third-party scanner against a user's own project are not automatically vulnerabilities in VulnWeave itself.

## Supported release line

The current development release line is `0.1.x`. Security fixes are published in a subsequent patch release when feasible.
