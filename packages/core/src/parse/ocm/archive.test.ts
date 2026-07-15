import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS fixture builders without type declarations
import { buildComponentArchive, buildDeliveryCtf } from '../../../scripts/generate-ocm-fixtures.mjs';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { loadFixture, loadedFromText } from '../../test-fixtures';
import { buildIndexes } from '../../graph/indexes';
import { collectFetchCandidates } from '../../workspace/fetchPlan';
import { addDocuments, emptyWorkspace, workspaceRoots } from '../../workspace/workspace';
import type { LoadedDocument } from '../../workspace/workspace';
import { refKey } from '../../workspace/resolve';
import { getChildren, rootNodes } from '../../tree/derive';
import { readOcmDelivery } from './archive';
import type { DeliveryResult } from './archive';

function fixtureBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../../fixtures/${name}`, import.meta.url)));
}

/** DeliveryResult → LoadedDocuments the way the app does it. */
function toLoaded(result: DeliveryResult): LoadedDocument[] {
  const docs: LoadedDocument[] = result.documents.map((d) => ({
    document: d.document,
    indexes: buildIndexes(d.document),
    source: { fileName: d.fileName, byteSize: d.byteSize, sha1: d.sha1, text: d.text },
  }));
  for (const entry of result.extracted) {
    docs.push(loadedFromText(entry.fileName, new TextDecoder().decode(entry.bytes)));
  }
  return docs;
}

describe('fixture determinism', () => {
  it('committed binary fixtures match a fresh generator run byte-for-byte', () => {
    expect(fixtureBytes('ocm/delivery.ctf.tar')).toEqual(new Uint8Array(buildDeliveryCtf()));
    expect(fixtureBytes('ocm/component-archive.tar')).toEqual(new Uint8Array(buildComponentArchive()));
  });
});

describe('readOcmDelivery — CTF', () => {
  it('reads both artifact layouts and extracts the SPDX blob with a matching ref checksum', async () => {
    const result = await readOcmDelivery('delivery.ctf.tar', fixtureBytes('ocm/delivery.ctf.tar'));
    expect(result.documents.map((d) => d.document.name).sort()).toEqual([
      'acme.org/platform',
      'acme.org/webstack',
    ]);
    expect(result.extracted).toHaveLength(1);
    expect(result.extracted[0]!.fileName).toContain('webstack-sbom');

    const webstack = result.documents.find((d) => d.document.name === 'acme.org/webstack')!;
    const sbomRef = webstack.document.externalDocumentRefs.find((r) =>
      r.docRef.startsWith('DocumentRef-sbom-'),
    )!;
    expect(sbomRef.checksum?.algorithm).toBe('SHA1');
    // The ref's checksum is the SHA-1 of the extracted bytes — verify against
    // the real parse pipeline.
    const extractedDoc = loadedFromText(
      result.extracted[0]!.fileName,
      new TextDecoder().decode(result.extracted[0]!.bytes),
    );
    expect(sbomRef.checksum?.value).toBe(extractedDoc.source.sha1);

    const platform = result.documents.find((d) => d.document.name === 'acme.org/platform')!;
    expect(platform.document.externalDocumentRefs).toEqual([
      expect.objectContaining({ docRef: 'DocumentRef-ref-webstack', uri: 'ocm://acme.org/webstack/2.1.0' }),
    ]);
  });

  it('links everything inside ONE workspace batch: checksum + namespace resolution', async () => {
    const result = await readOcmDelivery('delivery.ctf.tar', fixtureBytes('ocm/delivery.ctf.tar'));
    const { workspace } = addDocuments(emptyWorkspace, toLoaded(result));
    expect(workspace.documents.size).toBe(3);

    const platform = [...workspace.documents.values()].find((d) => d.document.name === 'acme.org/platform')!;
    const webstack = [...workspace.documents.values()].find((d) => d.document.name === 'acme.org/webstack')!;

    // componentReference resolves via the synthetic ocm:// namespace…
    const refResolution = workspace.resolutions.get(refKey(platform.document.id, 'DocumentRef-ref-webstack'));
    expect(refResolution).toMatchObject({ status: 'resolved', method: 'namespace' });

    // …and the SBOM blob via its byte checksum.
    const sbomRefName = webstack.document.externalDocumentRefs.find((r) =>
      r.docRef.startsWith('DocumentRef-sbom-'),
    )!.docRef;
    const sbomResolution = workspace.resolutions.get(refKey(webstack.document.id, sbomRefName));
    expect(sbomResolution).toMatchObject({ status: 'resolved', method: 'checksum' });

    // The delivery collapses to ONE root (platform), and the tree walks
    // platform → webstack → sbom resource → SPDX packages.
    expect(workspaceRoots(workspace)).toEqual([platform.document.id]);
    const [root] = rootNodes(workspace);
    const [platformPkg] = getChildren(workspace, root!);
    const children = getChildren(workspace, platformPkg!);
    expect(children.length).toBeGreaterThanOrEqual(1);

    // Fetch-all must ignore synthetic schemes.
    expect(collectFetchCandidates(workspace)).toHaveLength(0);
  });
});

describe('readOcmDelivery — component archive & sweep', () => {
  it('reads a component archive with its local blobs', async () => {
    const result = await readOcmDelivery('component-archive.tar', fixtureBytes('ocm/component-archive.tar'));
    expect(result.documents).toHaveLength(1);
    expect(result.documents[0]!.document.name).toBe('acme.org/webstack');
    expect(result.extracted).toHaveLength(1);
  });

  it('sweeps a plain tar of SPDX files', async () => {
    const tar: Uint8Array = writeTar([
      { name: 'a/minimal.spdx', bytes: loadFixture('minimal.spdx') },
      { name: 'b/notes.txt', bytes: 'not an sbom' },
    ]);
    const result = await readOcmDelivery('bundle.tar', tar);
    expect(result.documents).toHaveLength(0);
    expect(result.extracted).toHaveLength(1);
    expect(result.extracted[0]!.fileName).toBe('bundle.tar!a/minimal.spdx');
  });

  it('degrades on a corrupt index and reports empty archives', async () => {
    const badIndex: Uint8Array = writeTar([{ name: 'artifact-index.json', bytes: '{broken' }]);
    const bad = await readOcmDelivery('bad.tar', badIndex);
    expect(bad.diagnostics.some((d) => d.code === 'CTF_INDEX_INVALID')).toBe(true);
    expect(bad.diagnostics.some((d) => d.code === 'ARCHIVE_NO_DOCUMENTS')).toBe(true);

    const junk = await readOcmDelivery('junk.tar', new Uint8Array(1024).fill(65));
    expect(junk.documents).toHaveLength(0);
    expect(junk.diagnostics.some((d) => d.code === 'TAR_CORRUPT')).toBe(true);
  });

  it('handles tgz input (in-test compression — gzip bytes are not pinned)', async () => {
    const tar: Uint8Array = writeTar([{ name: 'minimal.spdx', bytes: loadFixture('minimal.spdx') }]);
    const stream = new Blob([new Uint8Array(tar)]).stream().pipeThrough(new CompressionStream('gzip'));
    const tgz = new Uint8Array(await new Response(stream).arrayBuffer());
    const result = await readOcmDelivery('bundle.tgz', tgz);
    expect(result.extracted).toHaveLength(1);
  });
});
