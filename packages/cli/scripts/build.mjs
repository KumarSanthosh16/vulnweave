import { build } from "esbuild";
import { rm } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const cliDirectory = resolve(fileURLToPath(new URL("..", import.meta.url)));
const repositoryDirectory = resolve(cliDirectory, "../..");
const packageSource = (name) => resolve(repositoryDirectory, "packages", name, "src", "index.ts");

await rm(resolve(cliDirectory, "dist"), { recursive: true, force: true });
await build({
  entryPoints: [resolve(cliDirectory, "src", "index.ts")],
  outfile: resolve(cliDirectory, "dist", "index.js"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  external: ["tree-sitter", "tree-sitter-javascript", "tree-sitter-typescript"],
  alias: {
    "@vulnweave/core": packageSource("core"),
    "@vulnweave/gitleaks-analyzer": packageSource("gitleaks-analyzer"),
    "@vulnweave/mock-analyzer": packageSource("mock-analyzer"),
    "@vulnweave/osv-analyzer": packageSource("osv-analyzer"),
    "@vulnweave/semgrep-analyzer": packageSource("semgrep-analyzer"),
    "@vulnweave/tree-sitter-indexer": packageSource("tree-sitter-indexer"),
    "@vulnweave/trivy-analyzer": packageSource("trivy-analyzer")
  }
});
