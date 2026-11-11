import { describe, expect, it } from 'vitest';
import { loadFixture, loadFixtureDocument, loadedFromText } from '../test-fixtures';
import { refKey } from './resolve';
import type { WorkspaceState } from './workspace';
import {
  addDocument,
  addDocuments,
  bindRef,
  emptyWorkspace,
  removeDocument,
  workspaceRoots,
} from './workspace';

const LEAF = 'cascade/leaf.spdx.json';
const MID = 'cascade/mid.spdx';
const AUTH = 'cascade/auth.spdx';
const ROOT = 'cascade/root.spdx';

function loadAll(...names: string[]): WorkspaceState {
  let ws = emptyWorkspace;
  for (const name of names) {
    const result = addDocument(ws, loadFixtureDocument(name));
    expect(result.outcome).toBe('added');
    ws = result.workspace;
  }
  return ws;
}

const docId = (ws: WorkspaceState, name: string) =>
  [...ws.documents.values()].find((d) => d.source.fileName === name.split('/').pop())!.document.id;

describe('cascade resolution', () => {
  const ws = loadAll(LEAF, MID, AUTH, ROOT);

  it('resolves by checksum (root → mid), tolerating version drift in the docRef name', () => {
    const resolution = ws.resolutions.get(refKey(docId(ws, ROOT), 'DocumentRef-WEBSTACK-2.2'));
    expect(resolution).toEqual({
      status: 'resolved',
      targetDocId: docId(ws, MID),
      method: 'checksum',
    });
  });

  it('resolves by namespace when the ref URI equals a loaded documentNamespace', () => {
    const resolution = ws.resolutions.get(refKey(docId(ws, MID), 'DocumentRef-RUNTIME'));
    expect(resolution).toEqual({
      status: 'resolved',
      targetDocId: docId(ws, LEAF),
      method: 'namespace',
    });
  });

  it('never auto-binds by name — surfaces a suggestion instead', () => {
    const resolution = ws.resolutions.get(refKey(docId(ws, MID), 'DocumentRef-AUTH-2.0'));
    expect(resolution).toMatchObject({
      status: 'unresolved',
      structural: true,
      suggestion: { docId: docId(ws, AUTH) },
    });
  });

  it('classifies refs without relationships as informational (not structural)', () => {
    const resolution = ws.resolutions.get(refKey(docId(ws, MID), 'DocumentRef-SCAN-REPORT'));
    expect(resolution).toMatchObject({ status: 'unresolved', structural: false });
  });

  it('computes roots as documents no resolved ref points to', () => {
    expect(workspaceRoots(ws)).toEqual([docId(ws, AUTH), docId(ws, ROOT)]);
  });

  it('manual binding re-parents and unbinding restores', () => {
    const key = refKey(docId(ws, MID), 'DocumentRef-AUTH-2.0');
    const bound = bindRef(ws, key, docId(ws, AUTH));
    expect(bound.resolutions.get(key)).toEqual({
      status: 'resolved',
      targetDocId: docId(ws, AUTH),
      method: 'manual',
    });
    expect(workspaceRoots(bound)).toEqual([docId(ws, ROOT)]);

    const unbound = bindRef(bound, key, null);
    expect(unbound.resolutions.get(key)?.status).toBe('unresolved');
  });

  it('load order does not matter', () => {
    const reversed = loadAll(ROOT, AUTH, MID, LEAF);
    expect(reversed.resolutions.get(refKey(docId(reversed, ROOT), 'DocumentRef-WEBSTACK-2.2'))).toMatchObject(
      { status: 'resolved', method: 'checksum' },
    );
    expect(workspaceRoots(reversed)).toEqual([docId(reversed, ROOT), docId(reversed, AUTH)]);
  });

  it('removing a mid document splits the cascade again', () => {
    const removed = removeDocument(ws, docId(ws, MID));
    expect(removed.documents.size).toBe(3);
    // leaf loses its parent and becomes a root again
    expect(workspaceRoots(removed)).toContain(docId(ws, LEAF));
  });
});

/**
 * Name suggestions run on the UI thread for every unresolved reference, on
 * every workspace change. What they cost (references × tokens × name length)
 * is chosen by whoever wrote the files: two files of 3 MB together kept the
 * app busy for minutes. So a pass gives up instead of finishing. The hostile
 * cases below are scaled down to a few hundred KB, where matching without a
 * bound still finishes, and then with the suggestion that the bound withholds.
 */
describe('name suggestions spend bounded work', () => {
  const LONG = 200_000;

  const spdxJson = (id: string, name: string, docRefs: readonly string[] = []) =>
    JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      SPDXID: 'SPDXRef-DOCUMENT',
      name,
      documentNamespace: `https://example.test/${id}`,
      creationInfo: { created: '2024-01-01T00:00:00Z', creators: ['Tool: test'] },
      externalDocumentRefs: docRefs.map((externalDocumentId) => ({
        externalDocumentId,
        spdxDocument: 'https://example.test/not-loaded',
      })),
    });

  /** Loads one document carrying `docRefs` and one per name; the suggestion per reference. */
  function suggest(docRefs: readonly string[], names: readonly string[]) {
    const carrier = loadedFromText('carrier.spdx.json', spdxJson('carrier', 'carrier', docRefs));
    const candidates = names.map((name, i) =>
      loadedFromText(`doc-${i}.spdx.json`, spdxJson(`doc-${i}`, name)),
    );
    const { workspace } = addDocuments(emptyWorkspace, [carrier, ...candidates]);
    const suggested = docRefs.map((docRef) => {
      const resolution = workspace.resolutions.get(refKey(carrier.document.id, docRef));
      expect(resolution?.status).toBe('unresolved');
      return resolution?.status === 'unresolved' ? resolution.suggestion?.docId : undefined;
    });
    return { suggested, candidateIds: candidates.map((c) => c.document.id) };
  }

  it('leaves an ordinary cascade alone: every drifted reference finds its document', () => {
    const parts = Array.from({ length: 60 }, (_, i) => `part${String(i).padStart(3, '0')}`);
    const { suggested, candidateIds } = suggest(
      parts.map((part) => `DocumentRef-${part}-2.0.0`),
      parts.map((part) => `${part}-1.0.0`),
    );
    expect(suggested).toEqual(candidateIds);
  });

  // The reported shape: every token is found, but only at the very end of the name.
  it('gives up on an id made of thousands of repeated tokens', () => {
    const docRef = `DocumentRef-${Array<string>(2_000).fill('ab').join('.')}`;
    const { suggested } = suggest([docRef], [`${'a'.repeat(LONG)}b`]);
    expect(suggested).toEqual([undefined]);
  });

  // Not a matter of deduplicating: these tokens all differ.
  it('gives up on an id made of thousands of distinct tokens', () => {
    const tokens = Array.from({ length: 2_000 }, (_, i) => `a${i.toString(36)}`);
    const { suggested } = suggest(
      [`DocumentRef-${tokens.join('.')}`],
      [`${'a'.repeat(LONG)} ${tokens.join(' ')}`],
    );
    expect(suggested).toEqual([undefined]);
  });

  // A single search can cost name × token: every start position matches all but one character.
  it('gives up on one very long token', () => {
    const token = `ab${'a'.repeat(5_000)}`;
    const { suggested } = suggest([`DocumentRef-${token}`], [`${'a'.repeat(LONG)}${token}`]);
    expect(suggested).toEqual([undefined]);
  });

  it('shares the bound across references: the first are matched, the last are not', () => {
    const docRefs = Array.from({ length: 2_000 }, (_, i) => `DocumentRef-ab-${i}`);
    const { suggested, candidateIds } = suggest(docRefs, [`${'a'.repeat(LONG)}b`]);
    expect(suggested[0]).toBe(candidateIds[0]);
    expect(suggested.at(-1)).toBeUndefined();
  });
});

describe('workspace hygiene', () => {
  it('skips byte-identical duplicates', () => {
    const first = addDocument(emptyWorkspace, loadFixtureDocument(LEAF));
    const second = addDocument(first.workspace, loadFixtureDocument(LEAF));
    expect(second.outcome).toBe('duplicate');
    expect(second.workspace.documents.size).toBe(1);
    expect(second.documentId).toBe(first.documentId);
  });

  it('keeps both documents on a namespace collision, under distinct ids', () => {
    const original = loadFixtureDocument('minimal.spdx');
    const variant = loadedFromText('minimal-variant.spdx', `${loadFixture('minimal.spdx')}\n# changed\n`);
    expect(variant.document.id).toBe(original.document.id);

    let ws = addDocument(emptyWorkspace, original).workspace;
    const result = addDocument(ws, variant);
    ws = result.workspace;
    expect(result.outcome).toBe('added');
    expect(ws.documents.size).toBe(2);
    expect(result.documentId).toMatch(/~dup-[0-9a-f]{8}$/);
    const remapped = ws.documents.get(result.documentId)!;
    expect(remapped.document.diagnostics.some((d) => d.code === 'DOC_NAMESPACE_COLLISION')).toBe(true);
    expect(remapped.document.elements[0]!.documentId).toBe(result.documentId);
  });
});
