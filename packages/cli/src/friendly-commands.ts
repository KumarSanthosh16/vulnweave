export type FriendlyCommand = "init" | "scan" | "report" | "findings" | "priorities" | "review" | "ci" | "history" | "doctor";

const commands = new Set<FriendlyCommand>(["init", "scan", "report", "findings", "priorities", "review", "ci", "history", "doctor"]);

/** Converts the compact public commands into the existing flag-based CLI contract. */
export function expandFriendlyCommand(values: string[]): string[] {
  if (values[0] === "--") return ["--", ...expandFriendlyCommand(values.slice(1))];
  const command = values[0];
  if (!command || !commands.has(command as FriendlyCommand)) return values;
  const rest = values.slice(1);
  if (command === "init") return ["--init", ...rest];
  if (command === "doctor") return ["--version"];
  if (command === "scan") return [...rest, "--format", "summary"];
  if (command === "report") return [...rest, "--format", "html"];
  if (command === "findings") return [...rest, "--format", "table"];
  if (command === "priorities") return [...rest, "--format", "priorities"];
  if (command === "history") return [...rest, "--format", "trend"];
  if (command === "ci") return [...rest, "--format", "summary", "--require-analyzers"];

  const expanded: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const value = rest[index];
    if (value === undefined) continue;
    if (value === "--base") {
      const base = rest[++index];
      if (base === undefined || base.length === 0 || base.startsWith("-")) throw new Error("review --base requires a Git reference");
      expanded.push("--changed-since", base);
    } else {
      expanded.push(value);
    }
  }
  return [...expanded, "--review-changes", "--format", "review"];
}

export const friendlyCommandHelp = `Friendly commands:
  vulnweave init [path]                 Create safe starter policy files
  vulnweave scan [path]                 Scan with project defaults
  vulnweave report [path]               Print a self-contained HTML report
  vulnweave findings [path]             List findings as a table
  vulnweave priorities [path]           Rank findings by evidence-backed impact
  vulnweave review [path] --base <ref>  Review changed code against a Git reference
  vulnweave ci [path]                   Enforce policy and required analyzer health
  vulnweave history [path]              Show local scan trend
  vulnweave doctor                      Show installed analyzer versions`;
