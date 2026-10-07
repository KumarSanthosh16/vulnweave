import { resolve } from "node:path";
import { loadScanRecord, toGitHubStepSummary } from "@vulnweave/core";

const rootDir = resolve(process.argv[2] ?? ".");
try {
  console.log(toGitHubStepSummary(await loadScanRecord(rootDir, "latest")));
} catch (error) {
  console.log(`## VulnWeave remediation summary\n\nA scan record was not available for this run. ${error instanceof Error ? error.message : String(error)}\n`);
}
