import { describe, expect, it } from 'vitest';
import { emptyFacets } from '../graph/search';
import { loadFixtureDocument, loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { findVersionConflicts, packageKey } from './conflicts';
import { diffCascades, diffToMarkdown, reachableDocs } from './diff';
import { inventoryRows, inventoryToCsv, sortInventory } from './inventory';
import { documentQuality } from './quality';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

function tagValueDoc(name: string, packages: [name: string, version: string, purl?: string][]): string {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    `DocumentName: ${name}`,
    `DocumentNamespace: https://example.org/spdxdocs/${name}`,
  ];
  packages.forEach(([pkgName, version, purl], i) => {
    lines.push(
      `PackageName: ${pkgName}`,
      `SPDXID: SPDXRef-P${i}`,
      `PackageVersion: ${version}`,
      'PackageDownloadLocation: NOASSERTION',
    );
    if (purl) lines.push(`ExternalRef: PACKAGE-MANAGER purl ${purl}`);
  });
  return lines.join('\n') + '\n';
}

describe('inventory', () => {
  const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');
  const packagesOnly = { ...emptyFacets, kinds: new Set(['package'] as const) };

  it('aggregates packages across all documents', () => {
    const rows = inventoryRows(ws, '', packagesOnly);
    expect(rows).toHaveLength(7);
    expect(rows.map((r) => r.docName)).toContain('acme-platform');
  });

  it('sorts by column', () => {
    const rows = sortInventory(inventoryRows(ws, '', packagesOnly), 'name', 'asc');
    expect(rows[0]!.element.name).toBe('auth-service');
    const desc = sortInventory(rows, 'name', 'desc');
    expect(desc[0]!.element.name).toBe('webstack');
  });

  it('escapes CSV fields with commas and quotes', () => {
    const tricky = loadedFromText(
      'tricky.spdx',
      tagValueDoc('tricky', [['weird, "pkg"', '1.0.0']]),
    );
    const wsr = addDocument(emptyWorkspace, tricky).workspace;
    const csv = inventoryToCsv(inventoryRows(wsr, '', emptyFacets));
    expect(csv).toContain('"weird, ""pkg"""');
    expect(csv.split('\r\n')[0]).toBe('name,version,license,supplier,purpose,purl,spdxId,kind,document');
  });
});

describe('version conflicts', () => {
  it('groups by purl identity and reports multi-version packages', () => {
    const a = loadedFromText(
      'imgA.spdx',
      tagValueDoc('imgA', [
        ['openssl', '3.3.2', 'pkg:apk/alpine/openssl@3.3.2'],
        ['zlib', '1.3.1', 'pkg:apk/alpine/zlib@1.3.1'],
      ]),
    );
    const b = loadedFromText(
      'imgB.spdx',
      tagValueDoc('imgB', [
        ['openssl', '3.0.9', 'pkg:apk/alpine/openssl@3.0.9?distro=3.18'],
        ['zlib', '1.3.1', 'pkg:apk/alpine/zlib@1.3.1'],
      ]),
    );
    let ws = addDocument(emptyWorkspace, a).workspace;
    ws = addDocument(ws, b).workspace;

    const conflicts = findVersionConflicts(ws);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]!.name).toBe('openssl');
    expect(conflicts[0]!.key).toBe('purl:pkg:apk/alpine/openssl');
    expect(conflicts[0]!.versions.map((v) => v.version)).toEqual(['3.0.9', '3.3.2']);
    expect(conflicts[0]!.total).toBe(2);
  });

  it('reports no conflicts for the example cascade fixtures', () => {
    const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/root.spdx');
    expect(findVersionConflicts(ws)).toEqual([]);
  });
});

describe('cascade diff', () => {
  it('walks resolved references when collecting a side', () => {
    const ws = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/auth.spdx', 'cascade/root.spdx');
    const rootId = [...ws.documents.values()].find((d) => d.source.fileName === 'root.spdx')!.document.id;
    // root → mid (checksum) → leaf (namespace); auth stays unresolved.
    expect(reachableDocs(ws, rootId)).toHaveLength(3);
  });

  it('computes added, removed, and version changes between two releases', () => {
    const v1 = loadedFromText(
      'rel1.spdx',
      tagValueDoc('release-1', [
        ['foo', '1.0.0', 'pkg:npm/foo@1.0.0'],
        ['bar', '2.0.0', 'pkg:npm/bar@2.0.0'],
        ['same', '5.0.0', 'pkg:npm/same@5.0.0'],
      ]),
    );
    const v2 = loadedFromText(
      'rel2.spdx',
      tagValueDoc('release-2', [
        ['foo', '1.1.0', 'pkg:npm/foo@1.1.0'],
        ['baz', '0.1.0', 'pkg:npm/baz@0.1.0'],
        ['same', '5.0.0', 'pkg:npm/same@5.0.0'],
      ]),
    );
    let ws = addDocument(emptyWorkspace, v1).workspace;
    ws = addDocument(ws, v2).workspace;
    const [aId, bId] = ws.order;

    const diff = diffCascades(ws, aId!, bId!);
    expect(diff.added.map((e) => e.name)).toEqual(['baz']);
    expect(diff.removed.map((e) => e.name)).toEqual(['bar']);
    expect(diff.changed.map((c) => c.name)).toEqual(['foo']);
    expect(diff.changed[0]!.a.versions).toEqual(['1.0.0']);
    expect(diff.changed[0]!.b.versions).toEqual(['1.1.0']);
    expect(diff.unchanged).toBe(1);

    const markdown = diffToMarkdown(diff, 'release-1', 'release-2');
    expect(markdown).toContain('### Added (1)');
    expect(markdown).toContain('- **foo** 1.0.0 → 1.1.0');
  });

  const checksumDoc = (name: string, packages: [name: string, version: string, sha: string][]) => {
    const lines = [
      'SPDXVersion: SPDX-2.3',
      'SPDXID: SPDXRef-DOCUMENT',
      `DocumentName: ${name}`,
      `DocumentNamespace: https://example.org/spdxdocs/${name}`,
    ];
    packages.forEach(([pkgName, version, sha], i) => {
      lines.push(
        `PackageName: ${pkgName}`,
        `SPDXID: SPDXRef-P${i}`,
        `PackageVersion: ${version}`,
        'PackageDownloadLocation: NOASSERTION',
        `PackageChecksum: SHA256: ${sha}`,
      );
    });
    return lines.join('\n') + '\n';
  };

  it('flags same version but different bytes as a digest-only change', () => {
    const v1 = loadedFromText('d1.spdx', checksumDoc('deliv-1', [['gateway', '2.1.0', 'aa'.repeat(32)]]));
    const v2 = loadedFromText('d2.spdx', checksumDoc('deliv-2', [['gateway', '2.1.0', 'bb'.repeat(32)]]));
    let ws = addDocument(emptyWorkspace, v1).workspace;
    ws = addDocument(ws, v2).workspace;
    const [aId, bId] = ws.order;

    const diff = diffCascades(ws, aId!, bId!);
    expect(diff.changed).toHaveLength(1);
    expect(diff.changed[0]!.reasons).toEqual(['digest']);
    expect(diff.changed[0]!.a.digests).toEqual([`SHA256:${'aa'.repeat(32)}`]);
    expect(diff.unchanged).toBe(0);

    const markdown = diffToMarkdown(diff, 'deliv-1', 'deliv-2');
    expect(markdown).toContain('(content changed, same version)');
  });

  it('reports both reasons when version AND bytes changed', () => {
    const v1 = loadedFromText('d1.spdx', checksumDoc('deliv-1', [['gateway', '2.1.0', 'aa'.repeat(32)]]));
    const v2 = loadedFromText('d2.spdx', checksumDoc('deliv-2', [['gateway', '2.2.0', 'bb'.repeat(32)]]));
    let ws = addDocument(emptyWorkspace, v1).workspace;
    ws = addDocument(ws, v2).workspace;
    const diff = diffCascades(ws, ws.order[0]!, ws.order[1]!);
    expect(diff.changed[0]!.reasons).toEqual(['version', 'digest']);
  });

  it('never judges digests when one side has no checksums', () => {
    const v1 = loadedFromText('d1.spdx', checksumDoc('deliv-1', [['gateway', '2.1.0', 'aa'.repeat(32)]]));
    const v2 = loadedFromText('d2.spdx', tagValueDoc('deliv-2', [['gateway', '2.1.0']]));
    let ws = addDocument(emptyWorkspace, v1).workspace;
    ws = addDocument(ws, v2).workspace;
    const diff = diffCascades(ws, ws.order[0]!, ws.order[1]!);
    expect(diff.changed).toHaveLength(0);
    expect(diff.unchanged).toBe(1);
  });
});

describe('packageKey with extraIdentity', () => {
  it('keeps same-named artifacts with different extraIdentity apart', () => {
    const base = {
      id: 'e1' as never,
      documentId: 'd' as never,
      spdxId: 'SPDXRef-a',
      kind: 'package' as const,
      name: 'config',
      raw: { kind: 'json' as const, value: {} },
    };
    const linux = { ...base, ocm: { role: 'resource' as const, extraIdentity: { os: 'linux', arch: 'amd64' } } };
    const darwin = { ...base, ocm: { role: 'resource' as const, extraIdentity: { arch: 'arm64', os: 'darwin' } } };
    const plain = { ...base };
    expect(packageKey(linux)).not.toBe(packageKey(darwin));
    expect(packageKey(linux)).not.toBe(packageKey(plain));
    // Key order inside extraIdentity must not matter.
    const linuxReordered = { ...base, ocm: { role: 'resource' as const, extraIdentity: { arch: 'amd64', os: 'linux' } } };
    expect(packageKey(linux)).toBe(packageKey(linuxReordered));
  });
});

describe('quality report', () => {
  it('summarizes NTIA-style coverage for a clean document', () => {
    const ws = loadAll('minimal.spdx');
    const loaded = [...ws.documents.values()][0]!;
    const report = documentQuality(ws, loaded);
    expect(report.document).toEqual({
      hasNamespace: true,
      hasCreated: true,
      hasCreators: true,
      hasRelationships: true,
    });
    expect(report.packages).toMatchObject({ total: 2, withVersion: 2, withUniqueId: 1, withLicense: 1 });
    expect(report.issues).toEqual({
      danglingLocalRefs: 0,
      unresolvedStructuralRefs: 0,
      duplicateSpdxIds: 0,
    });
  });

  it('counts dangling refs, unresolved structural refs, and duplicates', () => {
    const ws = loadAll('quirks.spdx');
    const loaded = [...ws.documents.values()][0]!;
    const report = documentQuality(ws, loaded);
    // CONTAINS SPDXRef-Package-dup exists; DocumentRef targets are external,
    // but nothing points at a missing local id in quirks.spdx.
    expect(report.issues.danglingLocalRefs).toBe(0);
    // NOSPACE, SPACED, NOCHECKSUM and MISSING are referenced by relationships
    // and unresolved; ORPHAN is informational.
    expect(report.issues.unresolvedStructuralRefs).toBe(3);
    expect(report.issues.duplicateSpdxIds).toBe(1);

    const dangling = loadedFromText(
      'dangling.spdx',
      tagValueDoc('dangling', [['ok', '1.0.0']]) + 'Relationship: SPDXRef-P0 CONTAINS SPDXRef-ghost\n',
    );
    const ws2 = addDocument(emptyWorkspace, dangling).workspace;
    const report2 = documentQuality(ws2, [...ws2.documents.values()][0]!);
    expect(report2.issues.danglingLocalRefs).toBe(1);
  });
});
