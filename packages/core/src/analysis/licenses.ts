import { licenseIdsInExpression, licenseExpressionError } from '../parse/spec-lint';
import { isDeprecatedLicenseId, isKnownLicenseId } from '../spec/spdx-license-ids';
import type { DocumentId } from '../model/ids';
import type { WorkspaceState } from '../workspace/workspace';
import { SPDX_LICENSE_LIST_SOURCE } from '../spec/spdx-license-ids';

/**
 * The licence inventory across the whole workspace: which SPDX identifiers
 * the loaded documents name, in how many packages and documents each, and
 * whether the identifier is on the SPDX License List, deprecated there, a
 * LicenseRef, or none of these. Counts and facts only. What a licence
 * obliges, or whether two are compatible, is not computed here and not
 * meant to be: BSI TR-03183-2 asks for identifiers, this answers whether
 * they are there.
 */

export type LicenseIdKind =
  /** On the SPDX License List and current. */
  | 'listed'
  /** On the SPDX License List but marked deprecated. */
  | 'deprecated'
  /** `LicenseRef-...` (including the ScanCode fallback `LicenseRef-scancode-...`). */
  | 'ref'
  /** Parses as an identifier but is not on the list and not a LicenseRef. */
  | 'unknown';

export interface LicenseIdRow {
  id: string;
  kind: LicenseIdKind;
  /** Packages naming this identifier in the declared field. */
  declared: number;
  /** Packages naming this identifier in the concluded field. */
  concluded: number;
  /** Packages naming it in either field (a package counts once). */
  packages: number;
  documents: number;
}

export interface LicenseInventory {
  rows: LicenseIdRow[];
  /** Packages considered (files never carry the fields the TR asks for). */
  packagesTotal: number;
  /** Packages whose declared licence is missing, NONE or NOASSERTION. */
  withoutDeclared: number;
  /** Packages whose concluded licence is missing, NONE or NOASSERTION. */
  withoutConcluded: number;
  /** Packages whose declared or concluded value is not a parsable SPDX expression (a licence text, a typo). */
  unparseable: number;
}

const ABSENT = new Set(['NONE', 'NOASSERTION']);

export function licenseInventory(ws: WorkspaceState): LicenseInventory {
  const byId = new Map<string, { declared: number; concluded: number; packages: Set<string>; documents: Set<DocumentId> }>();
  let packagesTotal = 0;
  let withoutDeclared = 0;
  let withoutConcluded = 0;
  let unparseable = 0;

  const entry = (id: string) => {
    let row = byId.get(id);
    if (!row) {
      row = { declared: 0, concluded: 0, packages: new Set(), documents: new Set() };
      byId.set(id, row);
    }
    return row;
  };

  for (const [docId, loaded] of ws.documents) {
    // SPDX 3 documents may carry the 3.0.1 additions the 2.x grammar lacks.
    const dialect = { spdx3: loaded.document.spec.model === 'spdx-3' };
    for (const element of loaded.document.elements) {
      if (element.kind !== 'package') continue;
      packagesTotal++;
      let broken = false;
      for (const field of ['declared', 'concluded'] as const) {
        const value = field === 'declared' ? element.licenseDeclared : element.licenseConcluded;
        const present = value !== undefined && value.trim() !== '' && !ABSENT.has(value.trim());
        if (!present) {
          if (field === 'declared') withoutDeclared++;
          else withoutConcluded++;
          continue;
        }
        if (licenseExpressionError(value, dialect) !== undefined) {
          broken = true;
          continue;
        }
        for (const id of licenseIdsInExpression(value, dialect)) {
          const row = entry(id);
          row[field]++;
          row.packages.add(element.id);
          row.documents.add(docId);
        }
      }
      if (broken) unparseable++;
    }
  }

  const rows: LicenseIdRow[] = [...byId.entries()]
    .map(([id, row]) => ({
      id,
      kind: kindOf(id),
      declared: row.declared,
      concluded: row.concluded,
      packages: row.packages.size,
      documents: row.documents.size,
    }))
    .sort((a, b) => b.packages - a.packages || a.id.localeCompare(b.id));

  return { rows, packagesTotal, withoutDeclared, withoutConcluded, unparseable };
}

export function kindOf(id: string): LicenseIdKind {
  if (/^(DocumentRef-[^:]+:)?LicenseRef-/.test(id)) return 'ref';
  if (isDeprecatedLicenseId(id)) return 'deprecated';
  if (isKnownLicenseId(id)) return 'listed';
  return 'unknown';
}

const CSV_HEADER = 'identifier,status,declared,concluded,packages,documents';

export function licenseInventoryToCsv(inventory: LicenseInventory): string {
  const lines = [CSV_HEADER];
  for (const row of inventory.rows) {
    lines.push([csvCell(row.id), row.kind, row.declared, row.concluded, row.packages, row.documents].join(','));
  }
  return lines.join('\n') + '\n';
}

export function licenseInventoryToMarkdown(inventory: LicenseInventory, opts: { generatedAt?: string } = {}): string {
  const lines: string[] = ['# License inventory', ''];
  if (opts.generatedAt) lines.push(`- Generated: ${opts.generatedAt}`);
  lines.push(`- SPDX License List: ${SPDX_LICENSE_LIST_SOURCE}`);
  lines.push(`- Packages: ${inventory.packagesTotal}`);
  lines.push(`- Without a declared licence (missing, NONE or NOASSERTION): ${inventory.withoutDeclared}`);
  lines.push(`- Without a concluded licence: ${inventory.withoutConcluded}`);
  lines.push(`- With a value that is not an SPDX expression: ${inventory.unparseable}`);
  lines.push('');
  lines.push('Identifiers are checked against the SPDX License List (ids and deprecation only). This table states nothing about what a licence obliges.');
  lines.push('');
  lines.push('| Identifier | Status | Declared | Concluded | Packages | Documents |');
  lines.push('| --- | --- | ---: | ---: | ---: | ---: |');
  for (const row of inventory.rows) {
    lines.push(`| ${row.id} | ${row.kind} | ${row.declared} | ${row.concluded} | ${row.packages} | ${row.documents} |`);
  }
  lines.push('');
  return lines.join('\n');
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
