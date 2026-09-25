import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { vexCoverage } from './vex';

/**
 * Coverage classifies packages by identifier (purl, CPE). A package that
 * carries only a checksum is "unmatchable" here even though a CSAF product
 * hash could still match it: coverage answers "could a statement about this
 * package be received", and that is an identifier question by design; hash
 * matching is a bonus on top, not the baseline.
 */
describe('vexCoverage', () => {
  it('counts a checksum-only package as unmatchable and a purl one as uncovered', () => {
    const doc = loadedFromText(
      'c.spdx',
      [
        'SPDXVersion: SPDX-2.3',
        'DataLicense: CC0-1.0',
        'SPDXID: SPDXRef-DOCUMENT',
        'DocumentName: c',
        'DocumentNamespace: https://example.org/spdxdocs/c',
        'Creator: Organization: ACME',
        'Created: 2026-06-01T10:00:00Z',
        '',
        'PackageName: hashed',
        'SPDXID: SPDXRef-H',
        'PackageDownloadLocation: NOASSERTION',
        'PackageChecksum: SHA256: ' + 'ab'.repeat(32),
        '',
        'PackageName: purled',
        'SPDXID: SPDXRef-P',
        'PackageDownloadLocation: NOASSERTION',
        'ExternalRef: PACKAGE-MANAGER purl pkg:npm/purled@1.0.0',
        '',
      ].join('\n'),
    );
    const ws = addDocument(emptyWorkspace, doc).workspace;
    expect(vexCoverage(ws, new Map())).toEqual({ covered: 0, uncovered: 1, unmatchable: 1, total: 2 });
  });
});
