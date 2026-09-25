import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { addDocument, addDocuments, emptyWorkspace } from '../workspace/workspace';
import { kindOf, licenseInventory, licenseInventoryToCsv, licenseInventoryToMarkdown } from './licenses';

/**
 * The licence inventory counts identifiers, never judges them. Pinned:
 * expressions are split into identifiers (exceptions excluded), a package
 * counts once per identifier however many fields name it, absent values
 * and unparseable values are counted apart, and the four identifier kinds
 * come out right.
 */

const spdx = (packages: string[][]) =>
  loadedFromText(
    'l.spdx',
    [
      'SPDXVersion: SPDX-2.3',
      'DataLicense: CC0-1.0',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: l',
      'DocumentNamespace: https://example.org/spdxdocs/l',
      'Creator: Organization: ACME',
      'Created: 2026-06-01T10:00:00Z',
      '',
      ...packages.flatMap((lines, i) => [
        `PackageName: p${i}`,
        `SPDXID: SPDXRef-P${i}`,
        'PackageDownloadLocation: NOASSERTION',
        ...lines,
        '',
      ]),
    ].join('\n'),
  );

describe('licenseInventory', () => {
  it('aggregates identifiers across fields, packages and expressions', () => {
    const ws = addDocument(
      emptyWorkspace,
      spdx([
        ['PackageLicenseDeclared: MIT', 'PackageLicenseConcluded: MIT'],
        ['PackageLicenseDeclared: Apache-2.0 OR MIT'],
        ['PackageLicenseDeclared: GPL-2.0-only WITH Classpath-exception-2.0', 'PackageLicenseConcluded: GPL-2.0'],
        ['PackageLicenseDeclared: LicenseRef-scancode-proprietary-license'],
        ['PackageLicenseDeclared: NOASSERTION'],
        ['PackageLicenseDeclared: MIT License'], // a name, not an expression
      ]),
    ).workspace;
    const inv = licenseInventory(ws);

    expect(inv.packagesTotal).toBe(6);
    expect(inv.withoutDeclared).toBe(1); // NOASSERTION
    expect(inv.withoutConcluded).toBe(4); // only two packages state one
    expect(inv.unparseable).toBe(1); // "MIT License"

    const byId = Object.fromEntries(inv.rows.map((r) => [r.id, r]));
    expect(byId.MIT).toMatchObject({ kind: 'listed', declared: 2, concluded: 1, packages: 2, documents: 1 });
    expect(byId['Apache-2.0']).toMatchObject({ kind: 'listed', packages: 1 });
    expect(byId['GPL-2.0-only']).toMatchObject({ kind: 'listed', declared: 1, concluded: 0 });
    expect(byId['GPL-2.0']).toMatchObject({ kind: 'deprecated', declared: 0, concluded: 1 });
    expect(byId['LicenseRef-scancode-proprietary-license']).toMatchObject({ kind: 'ref' });
    // The exception after WITH is not a licence and never becomes a row.
    expect(byId['Classpath-exception-2.0']).toBeUndefined();
    // Most-used first, then by id.
    expect(inv.rows[0]!.id).toBe('MIT');
  });

  it('counts documents separately from packages across a cascade', () => {
    const a = loadedFromText('a.spdx.json', loadFixture('cascade/leaf.spdx.json'));
    const b = spdx([['PackageLicenseDeclared: MIT']]);
    const ws = addDocuments(emptyWorkspace, [a, b]).workspace;
    const inv = licenseInventory(ws);
    const mit = inv.rows.find((r) => r.id === 'MIT');
    expect(mit).toBeDefined();
    expect(mit!.documents).toBeGreaterThanOrEqual(1);
    expect(inv.packagesTotal).toBe(
      [...ws.documents.values()].reduce((n, d) => n + d.document.elements.filter((e) => e.kind === 'package').length, 0),
    );
  });

  it('classifies identifiers without rating them', () => {
    expect(kindOf('MIT')).toBe('listed');
    expect(kindOf('GPL-2.0')).toBe('deprecated');
    expect(kindOf('LicenseRef-acme')).toBe('ref');
    expect(kindOf('DocumentRef-x:LicenseRef-acme')).toBe('ref');
    expect(kindOf('Acme-Proprietary-1.0')).toBe('unknown');
  });

  it('exports CSV and Markdown with the counts and the disclaimer', () => {
    const ws = addDocument(emptyWorkspace, spdx([['PackageLicenseDeclared: MIT, with a comma']])).workspace;
    const inv = licenseInventory(ws);
    const csv = licenseInventoryToCsv(inv);
    expect(csv.split('\n')[0]).toBe('identifier,status,declared,concluded,packages,documents');
    const md = licenseInventoryToMarkdown(inv, { generatedAt: '2026-09-25' });
    expect(md).toContain('# License inventory');
    expect(md).toContain('states nothing about what a licence obliges');
    expect(md).toContain('With a value that is not an SPDX expression: 1');
  });
});
