/** Identifies Python dependency sources so upgrade advice changes declarations, never lockfiles directly. */
export function pythonDependencyUpdateGuidance(packageName: string, targetVersion: string, sourcePath?: string, ecosystem?: string): string | undefined {
  if (!isPythonDependencySource(sourcePath, ecosystem)) return undefined;
  const path = sourcePath ?? "the Python dependency declaration";
  if (/(^|[/\\])requirements(?:-[^/\\]+)?\.txt$/i.test(path)) {
    return `Update ${packageName} in ${path} to ${targetVersion} or later, then recreate the environment or lockfile.`;
  }
  if (/(^|[/\\])poetry\.lock$/i.test(path)) {
    return `Update ${packageName} in ${replaceFilename(path, "pyproject.toml")} to ${targetVersion} or later, then run poetry lock and recreate the environment.`;
  }
  if (/(^|[/\\])pipfile\.lock$/i.test(path)) {
    return `Update ${packageName} in ${replaceFilename(path, "Pipfile")} to ${targetVersion} or later, then run pipenv lock and recreate the environment.`;
  }
  if (/(^|[/\\])uv\.lock$/i.test(path)) {
    return `Update ${packageName} in ${replaceFilename(path, "pyproject.toml")} to ${targetVersion} or later, then run uv lock and sync the environment.`;
  }
  if (/(^|[/\\])pyproject\.toml$/i.test(path)) {
    return `Update ${packageName} in ${path} to ${targetVersion} or later, then refresh the project's lockfile or environment with its package manager.`;
  }
  return `Update the declared ${packageName} dependency associated with ${path} to ${targetVersion} or later, then refresh the Python environment or lockfile.`;
}

function isPythonDependencySource(sourcePath: string | undefined, ecosystem: string | undefined): boolean {
  return ecosystem === "PyPI" || Boolean(sourcePath && /(^|[/\\])(?:requirements(?:-[^/\\]+)?\.txt|poetry\.lock|pipfile(?:\.lock)?|uv\.lock|pyproject\.toml)$/i.test(sourcePath));
}

function replaceFilename(path: string, filename: string): string {
  return path.replace(/[^/\\]+$/, filename);
}
