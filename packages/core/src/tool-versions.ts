import { execFile as executeFile } from "node:child_process";
import { promisify } from "node:util";

const execFile = promisify(executeFile);

export interface ToolVersion { id: string; displayName: string; version?: string; available: boolean; }
export interface VersionProbe { id: string; displayName: string; command: string; args: string[]; }

export const defaultVersionProbes: VersionProbe[] = [
  { id: "gitleaks", displayName: "Gitleaks", command: "gitleaks", args: ["version"] },
  { id: "semgrep", displayName: "Semgrep", command: "semgrep", args: ["--version"] },
  { id: "osv", displayName: "OSV-Scanner", command: "osv-scanner", args: ["--version"] },
  { id: "trivy", displayName: "Trivy", command: "trivy", args: ["--version"] }
];

export async function inspectToolVersions(probes: VersionProbe[] = defaultVersionProbes, run = runVersionProbe): Promise<ToolVersion[]> {
  return Promise.all(probes.map(async (probe) => {
    try {
      const output = (await run(probe.command, probe.args)).split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? "";
      return { id: probe.id, displayName: probe.displayName, version: output || "version not reported", available: true };
    } catch {
      return { id: probe.id, displayName: probe.displayName, available: false };
    }
  }));
}

export function formatVersionReport(vulnWeaveVersion: string, tools: ToolVersion[]): string {
  return [`VulnWeave ${vulnWeaveVersion}`, "Analyzers:", ...tools.map((tool) => `- ${tool.displayName}: ${tool.available ? tool.version : "not installed"}`)].join("\n");
}

async function runVersionProbe(command: string, args: string[]): Promise<string> {
  const { stdout, stderr } = await execFile(command, args, { timeout: 10_000 });
  return stdout || stderr;
}
