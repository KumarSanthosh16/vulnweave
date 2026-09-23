#!/usr/bin/env node
import { resolve } from "node:path";
import { AnalysisOrchestrator, analyzeChangeImpact, applySuppressions, assessDependencyReachability, assignFindingOwners, buildDependencyUpgradePlan, buildEvidenceGraph, buildRemediationAdvice, buildScanTrend, changedPaths, changedPathsSince, compareScanRecords, correlateFindings, evaluateAnalyzerHealth, evaluateGate, evaluateQualityGate, filterFindings, findingsInChangeScope, formatAnalyzerHealth, formatChangeImpact, formatDependencyReachability, formatDependencyUpgradePlan, formatFindingExplanation, formatFindingsTable, formatGateResult, formatGraphSummary, formatHotspotTable, formatOwnershipTable, formatPriorityTable, formatQualityGate, formatQualityTable, formatRemediationTable, formatReviewPacket, formatScanSummary, formatScanTrend, formatVersionReport, inspectToolVersions, linkFindingsToSymbols, listScanRecords, loadBaselinePolicy, loadCodeOwners, loadProjectConfig, loadScanRecord, rankFileHotspots, rankFindings, runAnalyzers, saveScanRecord, toHtmlReport, toSarif, type FindingCategory, type FindingSuppression, type Severity } from "@vulnweave/core";
import { GitleaksAnalyzer } from "@vulnweave/gitleaks-analyzer";
import { MockAnalyzer } from "@vulnweave/mock-analyzer";
import { OsvAnalyzer } from "@vulnweave/osv-analyzer";
import { SemgrepAnalyzer } from "@vulnweave/semgrep-analyzer";
import { indexDependencyUsages, indexImports, indexQualitySignals, indexSymbols } from "@vulnweave/tree-sitter-indexer";
import { TrivyAnalyzer } from "@vulnweave/trivy-analyzer";
import { expandFriendlyCommand, friendlyCommandHelp } from "./friendly-commands.js";
import { formatInitialization, initializeProject } from "./onboarding.js";

const args = expandFriendlyCommand(process.argv.slice(2));
if (args.includes("--version") || args.includes("-V")) {
  const version = process.env.npm_package_version ?? "0.1.0";
  console.log(formatVersionReport(version, await inspectToolVersions()));
  process.exit(0);
}
if (args.includes("--help") || args.includes("-h")) {
  console.log(`${friendlyCommandHelp}\n\nAdvanced usage:\n  vulnweave [path] [--analyzer all|mock|gitleaks|osv|semgrep|trivy] [--gitleaks-config rules.toml] [--semgrep-config rules.yml] [--semgrep-pack typescript-security|typescript-quality] [--format json|summary|table|quality|graph|symbols|priorities|hotspots|changes|review|trend|reachability|upgrades|remediation|ownership|explain|sarif|html] [--history N] [--changed-since git-ref] [--review-changes] [--finding id] [--severity level] [--category type] [--filter-analyzer id] [--include-tests] [--top N] [--baseline latest|run-id] [--fail-on info|low|medium|high|critical] [--require-analyzers] [--compare latest|run-id] [--no-save] [--no-gate] [--version]\n\nResults are saved locally under .vulnweave/ unless --no-save is used.`);
  process.exit(0);
}
if (args.includes("--init")) {
  const paths = args.filter((value) => value !== "--init" && value !== "--");
  if (paths.length > 1 || paths.some((value) => value.startsWith("-"))) throw new Error("init accepts at most one project path");
  const invocationDir = process.env.INIT_CWD ?? process.cwd();
  console.log(formatInitialization(await initializeProject(resolve(invocationDir, paths[0] ?? "."))));
  process.exit(0);
}

const options = await resolveOptions(parseOptions(args));
if (options.requireAnalyzers && options.analyzer !== "all") throw new Error("--require-analyzers is only valid with --analyzer all");
const adapter = options.analyzer === "mock" ? new MockAnalyzer()
  : options.analyzer === "gitleaks" ? new GitleaksAnalyzer()
  : options.analyzer === "osv" ? new OsvAnalyzer()
  : options.analyzer === "semgrep" ? new SemgrepAnalyzer()
  : options.analyzer === "trivy" ? new TrivyAnalyzer() : undefined;
if (!adapter && options.analyzer !== "all") throw new Error(`Unknown analyzer '${options.analyzer}'. Use all, mock, gitleaks, osv, semgrep, or trivy.`);
const previous = options.compare ? await loadScanRecord(options.rootDir, options.compare) : undefined;
const baseline = options.baseline ? await loadScanRecord(options.rootDir, options.baseline) : undefined;
const startedAt = new Date().toISOString();
const request = { rootDir: options.rootDir, config: { semgrepConfig: options.semgrepConfig, gitleaksConfig: options.gitleaksConfig } };
const batch = options.analyzer === "all"
  ? await runAnalyzers([new GitleaksAnalyzer(), new OsvAnalyzer(), new SemgrepAnalyzer(), new TrivyAnalyzer()], request)
  : undefined;
const result = adapter ? await new AnalysisOrchestrator().run(adapter, request) : undefined;
const rawFindings = batch?.findings ?? result?.findings ?? [];
const correlation = correlateFindings(rawFindings);
const findings = correlation.findings;
const suppressionResult = applySuppressions(findings, options.suppressions);
const analyzerId = options.analyzer === "all" ? "combined" : adapter?.id ?? "unknown";
const symbols = await indexSymbols(options.rootDir, { includeTests: options.includeTests });
const imports = await indexImports(options.rootDir, { includeTests: options.includeTests });
const dependencyUsages = await indexDependencyUsages(options.rootDir, { includeTests: options.includeTests });
const qualitySignals = await indexQualitySignals(options.rootDir, { includeTests: options.includeTests, quality: options.quality });
const qualityGate = evaluateQualityGate(qualitySignals, options.qualityGate);
const dependencyReachability = assessDependencyReachability(findings, dependencyUsages);
const dependencyUpgradePlan = buildDependencyUpgradePlan(findings, dependencyReachability);
const remediation = buildRemediationAdvice(findings, dependencyReachability);
const ownershipRules = await loadCodeOwners(options.rootDir);
const ownership = assignFindingOwners(findings, ownershipRules);
const symbolLinks = linkFindingsToSymbols(findings, symbols);
const changedFiles = options.changedSince ? await changedPathsSince(options.rootDir, options.changedSince) : await changedPaths(options.rootDir);
const impactAssessments = rankFindings(findings, symbolLinks, changedFiles, imports, dependencyReachability);
const changeImpact = analyzeChangeImpact(findings, changedFiles, imports, options.changedSince);
if (options.reviewChanges && changeImpact.changedFiles.length === 0) {
  console.error("VulnWeave could not start a changed-code review because no Git changes were found for the supplied reference.");
  console.error("Run this from a Git checkout with a valid base ref and changes, for example: vulnweave . --changed-since main --review-changes --format summary");
  console.error("For a full local scan without Git context, omit --review-changes and --changed-since.");
  process.exit(2);
}
const baselineComparison = baseline ? compareScanRecords({ findings }, baseline) : undefined;
const gateCandidates = options.reviewChanges
  ? (baselineComparison?.newFindings ?? findings).filter((finding) => findingsInChangeScope(changeImpact).some((scoped) => scoped.id === finding.id))
  : baselineComparison?.newFindings ?? findings;
const gate = evaluateGate(gateCandidates.filter((finding) => !suppressionResult.suppressed.some((suppression) => suppression.findingId === finding.id)), options.failOn);
const analyzerHealth = evaluateAnalyzerHealth(batch?.analyzers, options.requireAnalyzers);
const record = options.save
  ? await saveScanRecord({ startedAt, rootDir: options.rootDir, analyzerId, findings, sourceFindingCount: correlation.sourceFindingCount, analyzers: batch?.analyzers, symbols, imports, dependencyUsages, dependencyReachability, dependencyUpgradePlan, remediation, ownership, symbolLinks, impactAssessments, changedPaths: changedFiles, changeImpact, qualitySignals, qualityGate, gate, analyzerHealth, suppressions: suppressionResult.suppressed })
  : { schemaVersion: 1 as const, id: "unsaved", startedAt, completedAt: new Date().toISOString(), rootDir: options.rootDir, analyzerId, findings, sourceFindingCount: correlation.sourceFindingCount, analyzers: batch?.analyzers, symbols, imports, dependencyUsages, dependencyReachability, dependencyUpgradePlan, remediation, ownership, symbolLinks, impactAssessments, changedPaths: changedFiles, changeImpact, qualitySignals, qualityGate, gate, analyzerHealth, suppressions: suppressionResult.suppressed };
const comparison = previous ? compareScanRecords(record, previous) : undefined;
const history = options.save ? await listScanRecords(options.rootDir, options.history) : [record, ...(await listScanRecords(options.rootDir, options.history - 1))];
const trend = buildScanTrend(history);
const displayedRecord = { ...record, findings: filterFindings(record.findings, options.filters) };
const displayedAssessments = rankFindings(displayedRecord.findings, symbolLinks, changedFiles, imports, dependencyReachability);
const displayedRemediation = remediation.filter((item) => displayedRecord.findings.some((finding) => finding.id === item.findingId));
const explainedFinding = options.finding ? displayedRecord.findings.find((finding) => finding.id === options.finding) : displayedAssessments.length > 0 ? displayedRecord.findings.find((finding) => finding.id === displayedAssessments[0]?.findingId) : undefined;
const gateText = formatGateResult(gate, Boolean(baseline), options.reviewChanges);
const output = options.format === "summary" ? `${formatScanSummary(displayedRecord, comparison)}\n${gateText}\n${formatAnalyzerHealth(analyzerHealth)}\n${formatQualityGate(qualityGate)}`
  : options.format === "table" ? formatFindingsTable(displayedRecord.findings, displayedRecord.suppressions)
  : options.format === "quality" ? formatQualityTable(qualitySignals)
  : options.format === "graph" ? formatGraphSummary(buildEvidenceGraph(displayedRecord))
  : options.format === "symbols" ? formatSymbols(symbols)
  : options.format === "priorities" ? formatPriorityTable(displayedRecord.findings, displayedAssessments)
  : options.format === "hotspots" ? formatHotspotTable(rankFileHotspots(symbols, imports).slice(0, options.top))
  : options.format === "changes" ? formatChangeImpact(changeImpact)
  : options.format === "review" ? formatReviewPacket(displayedRecord, changeImpact, ownership, remediation, displayedAssessments)
  : options.format === "trend" ? formatScanTrend(trend)
  : options.format === "reachability" ? formatDependencyReachability(dependencyReachability.filter((assessment) => displayedRecord.findings.some((finding) => finding.id === assessment.findingId)))
  : options.format === "upgrades" ? formatDependencyUpgradePlan(dependencyUpgradePlan.filter((plan) => displayedRecord.findings.some((finding) => finding.id === plan.findingId)))
  : options.format === "remediation" ? formatRemediationTable(displayedRecord.findings, displayedRemediation)
  : options.format === "ownership" ? formatOwnershipTable(displayedRecord.findings, ownership.filter((item) => displayedRecord.findings.some((finding) => finding.id === item.findingId)), ownershipRules)
  : options.format === "explain" ? explainedFinding ? formatFindingExplanation(explainedFinding, displayedAssessments.find((assessment) => assessment.findingId === explainedFinding.id), symbols, symbolLinks, changedFiles, dependencyReachability) : "No findings available to explain. Use --finding <id> after a scan has findings."
  : options.format === "sarif" ? JSON.stringify(toSarif(displayedRecord.findings), null, 2)
  : options.format === "html" ? toHtmlReport(displayedRecord, trend)
  : JSON.stringify({ phase: "completed", record: displayedRecord, comparison }, null, 2);
console.log(output);
if (!options.noGate && (!gate.passed || !analyzerHealth.passed || !qualityGate.passed)) process.exitCode = 1;

interface ParsedOptions {
  analyzer?: string;
  rootDir: string;
  gitleaksConfig?: string;
  quality?: import("@vulnweave/core").QualityOptions;
  qualityGate?: import("@vulnweave/core").QualityGatePolicy;
  semgrepConfig?: string[];
  semgrepPacks: SemgrepPack[];
  format: "json" | "summary" | "table" | "quality" | "graph" | "symbols" | "priorities" | "hotspots" | "changes" | "review" | "trend" | "reachability" | "upgrades" | "remediation" | "ownership" | "explain" | "sarif" | "html";
  finding?: string;
  compare?: string;
  baseline?: string;
  changedSince?: string;
  reviewChanges: boolean;
  failOn?: Severity;
  requireAnalyzers: boolean;
  noGate: boolean;
  save: boolean;
  includeTests: boolean;
  top: number;
  history: number;
  filters: { severity?: Severity; category?: FindingCategory; analyzer?: string };
}

interface ResolvedOptions extends Omit<ParsedOptions, "analyzer"> { analyzer: string; suppressions: FindingSuppression[]; }

function parseOptions(values: string[]): ParsedOptions {
  let analyzer: string | undefined;
  let gitleaksConfig: string | undefined;
  const semgrepConfig: string[] = [];
  const semgrepPacks: SemgrepPack[] = [];
  let rootDir: string | undefined;
  let format: "json" | "summary" | "table" | "quality" | "graph" | "symbols" | "priorities" | "hotspots" | "changes" | "review" | "trend" | "reachability" | "upgrades" | "remediation" | "ownership" | "explain" | "sarif" | "html" = "json";
  let finding: string | undefined;
  let baseline: string | undefined;
  let changedSince: string | undefined;
  let reviewChanges = false;
  let failOn: Severity | undefined;
  let compare: string | undefined;
  let requireAnalyzers = false;
  let noGate = false;
  let save = true;
  let includeTests = false;
  let top = Number.POSITIVE_INFINITY;
  let history = 10;
  const filters: { severity?: Severity; category?: FindingCategory; analyzer?: string } = {};
  // pnpm runs a filtered package from that package's directory. INIT_CWD keeps
  // paths entered at the workspace root meaningful for `pnpm cli -- ...`.
  const invocationDir = process.env.INIT_CWD ?? process.cwd();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value === undefined) break;
    if (value === "--") continue;
    if (value === "--analyzer") { analyzer = requireValue(values, ++index, "--analyzer"); continue; }
    if (value === "--gitleaks-config") { gitleaksConfig = resolve(invocationDir, requireValue(values, ++index, "--gitleaks-config")); continue; }
    if (value === "--semgrep-config") { semgrepConfig.push(requireValue(values, ++index, "--semgrep-config")); continue; }
    if (value === "--semgrep-pack") { semgrepPacks.push(requireSemgrepPack(requireValue(values, ++index, "--semgrep-pack"))); continue; }
    if (value === "--format") { format = requireFormat(requireValue(values, ++index, "--format")); continue; }
    if (value === "--compare") { compare = requireValue(values, ++index, "--compare"); continue; }
    if (value === "--no-save") { save = false; continue; }
    if (value === "--include-tests") { includeTests = true; continue; }
    if (value === "--top") { top = requirePositiveInteger(requireValue(values, ++index, "--top"), "--top"); continue; }
    if (value === "--history") { history = requirePositiveInteger(requireValue(values, ++index, "--history"), "--history"); continue; }
    if (value === "--severity") { filters.severity = requireSeverity(requireValue(values, ++index, "--severity")); continue; }
    if (value === "--category") { filters.category = requireCategory(requireValue(values, ++index, "--category")); continue; }
    if (value === "--filter-analyzer") { filters.analyzer = requireValue(values, ++index, "--filter-analyzer"); continue; }
    if (value === "--finding") { finding = requireValue(values, ++index, "--finding"); continue; }
    if (value === "--baseline") { baseline = requireValue(values, ++index, "--baseline"); continue; }
    if (value === "--changed-since") { changedSince = requireValue(values, ++index, "--changed-since"); continue; }
    if (value === "--review-changes") { reviewChanges = true; continue; }
    if (value === "--fail-on") { failOn = requireSeverity(requireValue(values, ++index, "--fail-on")); continue; }
    if (value === "--require-analyzers") { requireAnalyzers = true; continue; }
    if (value === "--no-gate") { noGate = true; continue; }
    if (value.startsWith("-")) throw new Error(`Unknown option '${value}'`);
    if (rootDir) throw new Error("Only one scan path may be supplied");
    rootDir = resolve(invocationDir, value);
  }
  return {
    analyzer, gitleaksConfig,
    rootDir: rootDir ?? invocationDir,
    semgrepConfig: semgrepConfig.length > 0 ? semgrepConfig.map((path) => resolve(invocationDir, path)) : undefined,
    semgrepPacks, format, finding, compare, baseline, changedSince, reviewChanges, failOn, requireAnalyzers, noGate, save, includeTests, top, history, filters
  };
}

async function resolveOptions(parsed: ParsedOptions): Promise<ResolvedOptions> {
  const config = await loadProjectConfig(parsed.rootDir);
  const baselinePolicy = await loadBaselinePolicy(parsed.rootDir, config?.baselinePolicy ?? "vulnweave.baseline.json");
  return {
    ...parsed,
    analyzer: parsed.analyzer ?? config?.analyzer ?? "mock",
    gitleaksConfig: parsed.gitleaksConfig ?? (config?.gitleaksConfig ? resolve(parsed.rootDir, config.gitleaksConfig) : undefined),
    quality: config?.quality,
    qualityGate: config?.qualityGate,
    semgrepConfig: [...(parsed.semgrepConfig ?? (config?.semgrepConfig ? [resolve(parsed.rootDir, config.semgrepConfig)] : [])), ...parsed.semgrepPacks.map((pack) => resolve(parsed.rootDir, "rules", "packs", `${pack}.yml`))],
    failOn: parsed.failOn ?? config?.failOn ?? baselinePolicy?.failOn,
    requireAnalyzers: parsed.requireAnalyzers || (parsed.analyzer === undefined && (config?.requireAnalyzers === true || baselinePolicy?.requireAnalyzers === true)),
    suppressions: [...(baselinePolicy?.suppressions ?? []), ...(config?.suppressions ?? [])]
  };
}

function requirePositiveInteger(value: string, option: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new Error(`${option} requires a positive integer`);
  return parsed;
}

function requireFormat(value: string): "json" | "summary" | "table" | "quality" | "graph" | "symbols" | "priorities" | "hotspots" | "changes" | "review" | "trend" | "reachability" | "upgrades" | "remediation" | "ownership" | "explain" | "sarif" | "html" {
  if (value === "json" || value === "summary" || value === "table" || value === "quality" || value === "graph" || value === "symbols" || value === "priorities" || value === "hotspots" || value === "changes" || value === "review" || value === "trend" || value === "reachability" || value === "upgrades" || value === "remediation" || value === "ownership" || value === "explain" || value === "sarif" || value === "html") return value;
  throw new Error("--format must be json, summary, table, quality, graph, symbols, priorities, hotspots, changes, review, trend, reachability, upgrades, remediation, ownership, explain, sarif, or html");
}

function formatSymbols(symbols: Awaited<ReturnType<typeof indexSymbols>>): string {
  if (symbols.length === 0) return "No JavaScript or TypeScript symbols found.";
  return [`Symbols: ${symbols.length}`, ...symbols.map((symbol) => `${symbol.kind.padEnd(10)} ${symbol.path}:${symbol.line}  ${symbol.name}`)].join("\n");
}

function requireSeverity(value: string): Severity {
  if (["critical", "high", "medium", "low", "info"].includes(value)) return value as Severity;
  throw new Error("--severity must be critical, high, medium, low, or info");
}

function requireCategory(value: string): FindingCategory {
  if (["security", "quality", "dependency", "secret", "infrastructure"].includes(value)) return value as FindingCategory;
  throw new Error("--category must be security, quality, dependency, secret, or infrastructure");
}

type SemgrepPack = "typescript-security" | "typescript-quality";
function requireSemgrepPack(value: string): SemgrepPack {
  if (value === "typescript-security" || value === "typescript-quality") return value;
  throw new Error("--semgrep-pack must be typescript-security or typescript-quality");
}

function requireValue(values: string[], index: number, option: string): string {
  const value = values[index];
  if (!value || value.startsWith("-")) throw new Error(`${option} requires a value`);
  return value;
}
