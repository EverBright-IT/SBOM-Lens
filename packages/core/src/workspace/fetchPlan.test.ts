import { describe, expect, it } from 'vitest';
import { loadFixtureDocument } from '../test-fixtures';
import type { WorkspaceState } from './workspace';
import { addDocument, emptyWorkspace } from './workspace';
import { collectFetchCandidates } from './fetchPlan';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) ws = addDocument(ws, loadFixtureDocument(name)).workspace;
  return ws;
}

describe('collectFetchCandidates', () => {
  it('includes structural refs regardless of URL shape', () => {
    const ws = loadAll('cascade/mid.spdx'); // loaded standalone: both refs unresolved
    const urls = collectFetchCandidates(ws).map((c) => c.docRef);
    // RUNTIME's URI is a namespace URI without a file extension — structural, so included.
    expect(urls).toContain('DocumentRef-RUNTIME');
    expect(urls).toContain('DocumentRef-AUTH-2.0');
    // SCAN-REPORT is informational and points at a .tar.gz — excluded.
    expect(urls).not.toContain('DocumentRef-SCAN-REPORT');
  });

  it('includes informational refs when the URL looks like an SPDX document', () => {
    const ws = loadAll('quirks.spdx');
    const byRef = Object.fromEntries(collectFetchCandidates(ws).map((c) => [c.docRef, c]));
    // ORPHAN: informational but *.spdx → worth attempting.
    expect(byRef['DocumentRef-ORPHAN']).toBeDefined();
    expect(byRef['DocumentRef-ORPHAN']!.structural).toBe(false);
    // NOCHECKSUM: structural (a relationship points into it) despite the .pdf URL.
    expect(byRef['DocumentRef-NOCHECKSUM']).toBeDefined();
  });

  it('skips resolved refs, excluded URLs, and duplicate URLs', () => {
    const full = loadAll('cascade/leaf.spdx.json', 'cascade/mid.spdx', 'cascade/root.spdx');
    const candidates = collectFetchCandidates(full);
    // RUNTIME and WEBSTACK are resolved; only AUTH-2.0 remains fetchable.
    expect(candidates.map((c) => c.docRef)).toEqual(['DocumentRef-AUTH-2.0']);

    const excluded = collectFetchCandidates(full, new Set(candidates.map((c) => c.url)));
    expect(excluded).toEqual([]);
  });
});
