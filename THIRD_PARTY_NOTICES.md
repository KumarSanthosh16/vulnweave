# Third-party notices

VulnWeave is a local orchestration and reporting layer. It invokes supported
security analyzers as independently installed processes; it does not bundle,
modify, or redistribute their binaries or vulnerability databases.

## Supported external analyzers

| Component | License | Source |
|---|---|---|
| Gitleaks | MIT | https://github.com/gitleaks/gitleaks/blob/master/LICENSE |
| Semgrep Community Edition | LGPL-2.1 | https://github.com/semgrep/semgrep/blob/develop/LICENSE |
| OSV-Scanner | Apache-2.0 | https://github.com/google/osv-scanner/blob/main/LICENSE |
| Trivy | Apache-2.0 | https://github.com/aquasecurity/trivy/blob/main/LICENSE |

Users are responsible for obtaining and using these tools under their own
licenses and terms. Semgrep Community Edition is supported as a separately
installed executable. Do not treat this notice as permission to bundle,
modify, or redistribute Semgrep without separately meeting its LGPL terms.

## Direct runtime and development dependencies

| Component | License | Source |
|---|---|---|
| Tree-sitter and official grammars | MIT | https://github.com/tree-sitter/tree-sitter/blob/master/LICENSE |
| TypeScript | Apache-2.0 | https://github.com/microsoft/TypeScript/blob/main/LICENSE.txt |
| tsx | MIT | https://github.com/privatenumber/tsx/blob/master/LICENSE |
| esbuild | MIT | https://github.com/evanw/esbuild/blob/master/LICENSE.md |
| @types/node | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/LICENSE |

This file is an inventory aid, not legal advice. Before distributing a release,
generate a complete production dependency inventory, retain all required
copyright and license notices, and obtain legal review for your distribution
model. VulnWeave's own license has not yet been selected; do not assume an
open-source license applies to this repository.
