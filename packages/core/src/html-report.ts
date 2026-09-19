import type { ScanRecord } from "./run-store.js";
import { buildEvidenceGraph } from "./evidence-graph.js";
import type { ScanTrend } from "./trends.js";

/** Produces a self-contained, local-only HTML dashboard from a saved scan record. */
export function toHtmlReport(record: ScanRecord, trend?: ScanTrend): string {
  const totals = record.findings.reduce<Record<string, number>>((counts, finding) => ({ ...counts, [finding.severity]: (counts[finding.severity] ?? 0) + 1 }), {});
  const graph = buildEvidenceGraph(record);
  const suppressed = new Set(record.suppressions?.map((item) => item.findingId) ?? []);
  const ownershipByFinding = new Map(record.ownership?.map((item) => [item.findingId, item.owners]) ?? []);
  const findingById = new Map(record.findings.map((finding) => [finding.id, finding]));
  const priorities = (record.impactAssessments ?? []).slice(0, 10).flatMap((assessment) => {
    const finding = findingById.get(assessment.findingId);
    return finding ? [`<li><strong>${assessment.score} · ${escapeHtml(assessment.tier)}</strong> · ${escapeHtml(finding.title)} <span class="meta">${escapeHtml(assessment.reasons.join("; "))}</span></li>`] : [];
  }).join("");
  const findings = record.findings.map((finding) => `<tr>
    <td><span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
    <td>${suppressed.has(finding.id) ? "Suppressed" : "Active"}</td>
    <td>${escapeHtml(finding.analyzer)}</td><td>${escapeHtml(finding.ruleId)}</td>
    <td>${escapeHtml(finding.location ? `${finding.location.path}:${finding.location.startLine}` : "—")}</td><td>${escapeHtml(ownershipByFinding.get(finding.id)?.join(", ") || "Unassigned")}</td>
    <td>${escapeHtml(finding.title)}</td></tr>`).join("");
  const analyzerStatus = record.analyzers?.map((run) => `<li><strong>${escapeHtml(run.displayName)}</strong> · ${escapeHtml(run.status)} · ${run.findings.length} findings</li>`).join("") ?? "<li>Single analyzer run</li>";
  const reachabilityRows = record.dependencyReachability?.map((assessment) => `<tr><td>${escapeHtml(assessment.packageName)}</td><td>${escapeHtml(assessment.status)}</td><td>${assessment.usages.length}</td><td>${escapeHtml(assessment.usages.map((usage) => `${usage.path}:${usage.line}`).join(", ") || "No indexed JS/TS import observed")}</td></tr>`).join("") ?? "";
  const remediation = record.remediation?.map((advice) => `<li><strong>${escapeHtml(advice.action)}</strong><br><span class="meta">Verify: ${escapeHtml(advice.verification)} · Why: ${escapeHtml(advice.rationale)}</span></li>`).join("") ?? "";
  const trendRows = trend?.points.slice(-8).reverse().map((point) => `<tr><td>${escapeHtml(point.id.slice(0, 12))}</td><td>${point.findings}</td><td>${point.critical}</td><td>${point.high}</td><td>${point.newFindings}</td><td>${point.resolvedFindings}</td><td>${escapeHtml(point.gate)}</td><td>${escapeHtml(point.analyzerHealth)}</td></tr>`).join("") ?? "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>VulnWeave report</title>
<style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#101827;color:#e7edf7}.page{max-width:1120px;margin:auto;padding:2rem}.eyebrow{color:#7dd3fc;text-transform:uppercase;letter-spacing:.12em;font-size:.75rem}h1{margin:.25rem 0}h2{margin-top:2.5rem}.meta{color:#aab7ca}.cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.75rem}.card,.panel{background:#172235;border:1px solid #2b3b55;border-radius:.7rem;padding:1rem}.card strong{display:block;font-size:1.7rem}.critical{color:#fb7185}.high{color:#fb923c}.medium{color:#facc15}.low{color:#7dd3fc}.info{color:#aab7ca}.severity{text-transform:uppercase;font-weight:700}table{width:100%;border-collapse:collapse;background:#172235;border-radius:.7rem;overflow:hidden}th,td{text-align:left;padding:.75rem;border-bottom:1px solid #2b3b55;vertical-align:top}th{color:#aab7ca;font-size:.75rem;text-transform:uppercase;letter-spacing:.07em}ul{padding-left:1.25rem;line-height:1.8}.status{display:flex;gap:.75rem;flex-wrap:wrap}.pass{color:#86efac}.fail{color:#fda4af}@media(max-width:720px){.page{padding:1rem}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}table{font-size:.85rem}th:nth-child(4),td:nth-child(4),th:nth-child(5),td:nth-child(5){display:none}}</style>
</head><body><main class="page"><p class="eyebrow">Local security report</p><h1>VulnWeave</h1><p class="meta">Run ${escapeHtml(record.id)} · ${escapeHtml(record.completedAt)}</p>
<section class="cards"><div class="card"><strong>${record.findings.length}</strong>Findings</div>${["critical", "high", "medium", "low"].map((severity) => `<div class="card"><strong class="${severity}">${totals[severity] ?? 0}</strong>${severity}</div>`).join("")}</section>
<section class="panel status"><span class="${record.gate?.passed === false ? "fail" : "pass"}">Gate: ${record.gate?.passed === false ? "failed" : "passed"}</span><span class="${record.analyzerHealth?.passed === false ? "fail" : "pass"}">Analyzer health: ${record.analyzerHealth?.passed === false ? "failed" : "passed"}</span>${record.suppressions?.length ? `<span>Suppressed: ${record.suppressions.length}</span>` : ""}</section>
<section><h2>Analyzers</h2><ul>${analyzerStatus}</ul></section>
<section><h2>Findings</h2>${findings ? `<table><thead><tr><th>Severity</th><th>Status</th><th>Analyzer</th><th>Rule</th><th>Location</th><th>Owners</th><th>Title</th></tr></thead><tbody>${findings}</tbody></table>` : "<div class=\"panel\">No findings.</div>"}</section>
<section><h2>Priority</h2>${priorities ? `<ul>${priorities}</ul>` : "<div class=\"panel\">No findings to prioritize.</div>"}</section>
<section><h2>Remediation</h2>${remediation ? `<ul>${remediation}</ul>` : "<div class=\"panel\">No findings need remediation guidance.</div>"}</section>
${record.dependencyReachability?.length ? `<section><h2>Dependency reachability</h2><p class="meta">Static JavaScript/TypeScript import evidence only; it is not runtime proof.</p><table><thead><tr><th>Package</th><th>Status</th><th>Imports</th><th>Static evidence</th></tr></thead><tbody>${reachabilityRows}</tbody></table></section>` : ""}
<section><h2>Evidence graph</h2><div class="panel">${graph.nodes.length} nodes · ${graph.edges.length} edges · ${record.symbols?.length ?? 0} indexed symbols</div></section>
${trend ? `<section><h2>Local trend · ${escapeHtml(trend.posture)}</h2><table><thead><tr><th>Run</th><th>Findings</th><th>Critical</th><th>High</th><th>New</th><th>Resolved</th><th>Gate</th><th>Analyzers</th></tr></thead><tbody>${trendRows}</tbody></table></section>` : ""}
</main></body></html>`;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
