import type { SearchFacets } from '../graph/search';
import { searchWorkspace } from '../graph/search';
import type { SbomElement } from '../model/document';
import { effectiveLicense } from '../model/document';
import type { DocumentId, ElementId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';
import type { VexFinding } from './vex';
import { worstVexStatus } from './vex';

/**
 * The aggregated bill of materials across every loaded document — the
 * "give me the parts list of this release as a file" workflow.
 */

export interface InventoryRow {
  element: SbomElement;
  docId: DocumentId;
  docName: string;
}

export type InventorySortKey =
  | 'name'
  | 'version'
  | 'license'
  | 'supplier'
  | 'purpose'
  | 'purl'
  | 'document';

export function inventoryRows(
  ws: WorkspaceState,
  query: string,
  facets: SearchFacets,
): InventoryRow[] {
  const { hits } = searchWorkspace(ws, query, facets, Number.MAX_SAFE_INTEGER);
  return hits.map((hit) => ({
    element: hit.element,
    docId: hit.docId,
    docName: ws.documents.get(hit.docId)?.document.name ?? '',
  }));
}

export function sortInventory(
  rows: readonly InventoryRow[],
  key: InventorySortKey,
  direction: 'asc' | 'desc',
): InventoryRow[] {
  const sign = direction === 'asc' ? 1 : -1;
  const numeric = key === 'version';
  return [...rows].sort(
    (a, b) =>
      sign *
      sortValue(a, key).localeCompare(sortValue(b, key), undefined, {
        numeric,
        sensitivity: 'base',
      }),
  );
}

function sortValue(row: InventoryRow, key: InventorySortKey): string {
  switch (key) {
    case 'name':
      return row.element.name;
    case 'version':
      return row.element.version ?? '';
    case 'license':
      return effectiveLicense(row.element) ?? '';
    case 'supplier':
      return row.element.supplier ?? '';
    case 'purpose':
      return row.element.purpose ?? '';
    case 'purl':
      return row.element.purl ?? '';
    case 'document':
      return row.docName;
  }
}

const CSV_COLUMNS = [
  'name',
  'version',
  'license',
  'supplier',
  'purpose',
  'purl',
  'spdxId',
  'kind',
  'document',
] as const;

/** The VEX overlay rides the exports only when one is loaded. */
export type VexOverlay = ReadonlyMap<ElementId, VexFinding[]>;

function vexCells(findings: readonly VexFinding[] | undefined): [status: string, vulns: string] {
  if (!findings || findings.length === 0) return ['', ''];
  return [
    worstVexStatus(findings) ?? '',
    findings.map((f) => `${f.vulnerability} (${f.status})`).join('; '),
  ];
}

export function inventoryToCsv(rows: readonly InventoryRow[], vex?: VexOverlay): string {
  const withVex = vex !== undefined && vex.size > 0;
  const lines = [[...CSV_COLUMNS, ...(withVex ? ['vex_status', 'vex_vulnerabilities'] : [])].join(',')];
  for (const row of rows) {
    lines.push(
      [
        row.element.name,
        row.element.version ?? '',
        effectiveLicense(row.element) ?? '',
        row.element.supplier ?? '',
        row.element.purpose ?? '',
        row.element.purl ?? '',
        row.element.spdxId,
        row.element.kind,
        row.docName,
        ...(withVex ? vexCells(vex.get(row.element.id)) : []),
      ]
        .map(escapeCsv)
        .join(','),
    );
  }
  return lines.join('\r\n') + '\r\n';
}

function escapeCsv(value: string): string {
  return /[",\n\r;]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

export function inventoryToJson(rows: readonly InventoryRow[], vex?: VexOverlay): string {
  const withVex = vex !== undefined && vex.size > 0;
  return (
    JSON.stringify(
      rows.map((row) => {
        const findings = withVex ? vex.get(row.element.id) : undefined;
        return {
          name: row.element.name,
          version: row.element.version,
          license: effectiveLicense(row.element),
          supplier: row.element.supplier,
          purpose: row.element.purpose,
          purl: row.element.purl,
          spdxId: row.element.spdxId,
          kind: row.element.kind,
          document: row.docName,
          documentId: row.docId,
          ...(findings && findings.length > 0
            ? {
                vexStatus: worstVexStatus(findings),
                vexFindings: findings.map((f) => ({ vulnerability: f.vulnerability, status: f.status })),
              }
            : {}),
        };
      }),
      null,
      2,
    ) + '\n'
  );
}
