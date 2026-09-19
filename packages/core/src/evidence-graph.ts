import type { ScanRecord } from "./run-store.js";

export type EvidenceNodeKind = "finding" | "evidence" | "file" | "dependency" | "symbol";
export interface EvidenceNode { id: string; kind: EvidenceNodeKind; label: string; }
export interface EvidenceEdge { from: string; to: string; relation: "has_evidence" | "located_in" | "affects_dependency" | "located_in_symbol" | "imports" | "statically_imported_by"; }
export interface EvidenceGraph { schemaVersion: 1; scanId: string; nodes: EvidenceNode[]; edges: EvidenceEdge[]; }

/** Builds an auditable local graph from already-normalized scanner evidence. */
export function buildEvidenceGraph(record: ScanRecord): EvidenceGraph {
  const nodes = new Map<string, EvidenceNode>();
  const edges: EvidenceEdge[] = [];
  const addNode = (node: EvidenceNode) => nodes.set(node.id, node);
  for (const symbol of record.symbols ?? []) addNode({ id: symbol.id, kind: "symbol", label: `${symbol.kind} ${symbol.name}` });
  for (const relation of record.imports ?? []) {
    addNode({ id: `file:${relation.from}`, kind: "file", label: relation.from });
    addNode({ id: `file:${relation.to}`, kind: "file", label: relation.to });
    edges.push({ from: `file:${relation.from}`, to: `file:${relation.to}`, relation: "imports" });
  }
  for (const finding of record.findings) {
    const findingId = `finding:${finding.analyzer}:${finding.id}`;
    addNode({ id: findingId, kind: "finding", label: finding.title });
    if (finding.location) {
      const fileId = `file:${finding.location.path}`;
      addNode({ id: fileId, kind: "file", label: finding.location.path });
      edges.push({ from: findingId, to: fileId, relation: "located_in" });
    }
    for (const link of record.symbolLinks?.filter((candidate) => candidate.findingId === finding.id) ?? []) {
      edges.push({ from: findingId, to: link.symbolId, relation: "located_in_symbol" });
    }
    for (const evidence of finding.evidence) {
      const evidenceId = `evidence:${finding.analyzer}:${evidence.id}`;
      addNode({ id: evidenceId, kind: "evidence", label: evidence.summary });
      edges.push({ from: findingId, to: evidenceId, relation: "has_evidence" });
      if (evidence.kind === "dependency") {
        const packageName = evidence.metadata?.package;
        const version = evidence.metadata?.version;
        if (typeof packageName === "string") {
          const dependencyId = `dependency:${packageName}@${typeof version === "string" ? version : "unknown"}`;
          addNode({ id: dependencyId, kind: "dependency", label: dependencyId.slice("dependency:".length) });
          edges.push({ from: findingId, to: dependencyId, relation: "affects_dependency" });
        }
      }
    }
  }
  for (const reachability of record.dependencyReachability ?? []) {
    if (reachability.status !== "referenced") continue;
    const finding = record.findings.find((candidate) => candidate.id === reachability.findingId);
    const version = typeof finding?.metadata?.version === "string" ? finding.metadata.version : "unknown";
    const dependencyId = `dependency:${reachability.packageName}@${version}`;
    addNode({ id: dependencyId, kind: "dependency", label: dependencyId.slice("dependency:".length) });
    for (const usage of reachability.usages) {
      const fileId = `file:${usage.path}`;
      addNode({ id: fileId, kind: "file", label: usage.path });
      edges.push({ from: dependencyId, to: fileId, relation: "statically_imported_by" });
    }
  }
  return { schemaVersion: 1, scanId: record.id, nodes: [...nodes.values()], edges };
}

export function formatGraphSummary(graph: EvidenceGraph): string {
  const byKind = graph.nodes.reduce<Record<string, number>>((counts, node) => ({ ...counts, [node.kind]: (counts[node.kind] ?? 0) + 1 }), {});
  return `Evidence graph: ${graph.nodes.length} nodes | ${graph.edges.length} edges\nNodes: findings ${byKind.finding ?? 0} | evidence ${byKind.evidence ?? 0} | files ${byKind.file ?? 0} | dependencies ${byKind.dependency ?? 0} | symbols ${byKind.symbol ?? 0}`;
}
