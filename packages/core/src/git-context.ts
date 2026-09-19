import { execFile as executeFile } from "node:child_process";
import { promisify } from "node:util";

const execFile = promisify(executeFile);

/** Returns changed and untracked paths; non-Git directories simply yield no context. */
export async function changedPaths(rootDir: string): Promise<string[]> {
  try {
    const { stdout } = await execFile("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: rootDir });
    return stdout.split("\n").flatMap((line) => {
      if (!line) return [];
      // Porcelain v1 reserves the first three characters for status and separator.
      const path = line.slice(3).replace(/^.* -> /, "");
      return path ? [path] : [];
    });
  } catch {
    return [];
  }
}

/** Returns committed paths changed from a Git reference to the current HEAD. */
export async function changedPathsSince(rootDir: string, reference: string): Promise<string[]> {
  try {
    const { stdout } = await execFile("git", ["diff", "--name-only", "--diff-filter=ACMR", `${reference}...HEAD`], { cwd: rootDir });
    return stdout.split("\n").filter(Boolean);
  } catch {
    return [];
  }
}
