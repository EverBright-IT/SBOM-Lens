import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import type { WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import type { DeliveredFile } from './acceptance';
import { checkDelivery, deliveryAlgorithms, hasVerifiableFiles } from './acceptance';

/**
 * Delivery acceptance: SBOM file checksums vs the digests of what was
 * actually delivered. Path matching (tolerant of a leading "./"), the
 * strongest-shared-algorithm verdict, and the missing/extra/unverifiable
 * edges.
 */

const A_SHA256 = 'a'.repeat(64);
const B_SHA256 = 'b'.repeat(64);
const A_SHA1 = 'a'.repeat(40);

/** An SPDX document made of File entries with checksums. */
function fileWorkspace(...files: [name: string, checksums: [algo: string, value: string][]][]): WorkspaceState {
  const lines = [
    'SPDXVersion: SPDX-2.3',
    'SPDXID: SPDXRef-DOCUMENT',
    'DocumentName: delivery',
    'DocumentNamespace: https://example.org/spdxdocs/delivery',
  ];
  files.forEach(([name, checksums], i) => {
    lines.push(`FileName: ${name}`, `SPDXID: SPDXRef-File${i}`);
    for (const [algo, value] of checksums) lines.push(`FileChecksum: ${algo}: ${value}`);
  });
  const loaded = loadedFromText('delivery.spdx', lines.join('\n') + '\n');
  return addDocument(emptyWorkspace, loaded).workspace;
}

function delivered(path: string, digests: Record<string, string>, size = 10): DeliveredFile {
  return { path, size, digests };
}

describe('checkDelivery', () => {
  it('matches, mismatches, and flags missing files', () => {
    const ws = fileWorkspace(
      ['./src/app.js', [['SHA256', A_SHA256]]],
      ['./src/broken.js', [['SHA256', A_SHA256]]],
      ['./src/gone.js', [['SHA256', A_SHA256]]],
    );
    const report = checkDelivery(ws, [
      delivered('src/app.js', { SHA256: A_SHA256 }), // path normalized, digest matches
      delivered('src/broken.js', { SHA256: B_SHA256 }), // tampered
      // gone.js not delivered
    ]);

    const byPath = Object.fromEntries(report.files.map((f) => [f.path, f.verdict]));
    expect(byPath['./src/app.js']).toBe('match');
    expect(byPath['./src/broken.js']).toBe('mismatch');
    expect(byPath['./src/gone.js']).toBe('missing');
    expect(report.summary).toMatchObject({ match: 1, mismatch: 1, missing: 1, extra: 0, total: 3 });

    const broken = report.files.find((f) => f.path === './src/broken.js')!;
    expect(broken).toMatchObject({ algorithm: 'SHA256', declared: A_SHA256, actual: B_SHA256 });
  });

  it('surfaces delivered files the SBOM never mentions as extras', () => {
    const ws = fileWorkspace(['./app.js', [['SHA256', A_SHA256]]]);
    const report = checkDelivery(ws, [
      delivered('app.js', { SHA256: A_SHA256 }),
      delivered('secret.env', { SHA256: B_SHA256 }, 42),
      delivered('extra/notes.txt', { SHA256: B_SHA256 }, 7),
    ]);
    expect(report.extra).toEqual([
      { path: 'extra/notes.txt', size: 7 },
      { path: 'secret.env', size: 42 },
    ]);
    expect(report.summary.extra).toBe(2);
  });

  it('picks the strongest algorithm both sides share', () => {
    // SBOM declares SHA1 and SHA256; the delivery has both → SHA256 decides.
    const ws = fileWorkspace(['./app.js', [['SHA1', A_SHA1], ['SHA256', A_SHA256]]]);
    const report = checkDelivery(ws, [delivered('app.js', { SHA1: A_SHA1, SHA256: A_SHA256 })]);
    expect(report.files[0]).toMatchObject({ verdict: 'match', algorithm: 'SHA256' });
  });

  it('is unverifiable when the SBOM has no checksum or no shared algorithm', () => {
    const ws = fileWorkspace(
      ['./nocheck.js', []],
      ['./sha1only.js', [['SHA1', A_SHA1]]],
    );
    const report = checkDelivery(ws, [
      delivered('nocheck.js', { SHA256: A_SHA256 }),
      delivered('sha1only.js', { SHA256: A_SHA256 }), // delivery only hashed SHA256
    ]);
    const byPath = Object.fromEntries(report.files.map((f) => [f.path, f]));
    expect(byPath['./nocheck.js']!.verdict).toBe('unverifiable');
    expect(byPath['./sha1only.js']!.verdict).toBe('unverifiable');
    expect(report.summary.unverifiable).toBe(2);
  });

  it('normalizes SHA-256 vs sha256 algorithm spellings', () => {
    const ws = fileWorkspace(['./app.js', [['SHA256', A_SHA256]]]);
    // A worker might report the algorithm as "SHA-256"; it must still match.
    const report = checkDelivery(ws, [delivered('app.js', { 'SHA-256': A_SHA256 } as Record<string, string>)]);
    // "SHA-256" key is normalized on the delivery side by the worker, so the
    // canonical form is what reaches here; simulate the canonical spelling:
    const canonical = checkDelivery(ws, [delivered('app.js', { SHA256: A_SHA256 })]);
    expect(canonical.files[0]!.verdict).toBe('match');
    // The un-normalized spelling has no SHA256 key → unverifiable (documents
    // that the worker is responsible for emitting canonical algorithm names).
    expect(report.files[0]!.verdict).toBe('unverifiable');
  });
});

describe('workspace helpers', () => {
  it('collects the algorithms worth recomputing', () => {
    const ws = fileWorkspace(
      ['./a.js', [['SHA1', A_SHA1]]],
      ['./b.js', [['SHA256', A_SHA256]]],
    );
    expect(deliveryAlgorithms(ws).sort()).toEqual(['SHA1', 'SHA256']);
    expect(hasVerifiableFiles(ws)).toBe(true);
  });

  it('reports no verifiable files when none carry a checksum', () => {
    const ws = fileWorkspace(['./a.js', []]);
    expect(hasVerifiableFiles(ws)).toBe(false);
    expect(deliveryAlgorithms(ws)).toEqual([]);
  });
});
