import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';
import { hashHex } from '../../util/sha1';
import { BLOB_FILES_MAX, BLOB_PREVIEW_MAX, inspectBlob } from './blob';

const enc = (text: string) => new TextEncoder().encode(text);

async function sha256Of(bytes: Uint8Array): Promise<string> {
  return hashHex('SHA-256', new Uint8Array(bytes).buffer as ArrayBuffer);
}

describe('inspectBlob — kinds and previews', () => {
  it('classifies JSON, YAML (by media type), and plain text', async () => {
    expect((await inspectBlob(enc('{"a":1}'), 'application/json', undefined)).kind).toBe('json');
    expect((await inspectBlob(enc('a: 1\nb: 2\n'), 'application/yaml', undefined)).kind).toBe('yaml');
    expect((await inspectBlob(enc('hello world'), undefined, undefined)).kind).toBe('text');
  });

  it('caps text previews at BLOB_PREVIEW_MAX and flags truncation', async () => {
    const big = 'x'.repeat(BLOB_PREVIEW_MAX + 100);
    const info = await inspectBlob(enc(big), 'text/plain', undefined);
    expect(info.previews![0]!.text).toHaveLength(BLOB_PREVIEW_MAX);
    expect(info.previews![0]!.truncated).toBe(true);
  });

  it('detects a helm chart (Chart.yaml one level deep) with file list and previews', async () => {
    const tar: Uint8Array = writeTar([
      { name: 'mychart/Chart.yaml', bytes: 'apiVersion: v2\nname: mychart\n' },
      { name: 'mychart/values.yaml', bytes: 'replicas: 1\n' },
      { name: 'mychart/templates/svc.yaml', bytes: 'kind: Service\n' },
    ]);
    const info = await inspectBlob(tar, undefined, undefined);
    expect(info.kind).toBe('helm-chart');
    expect(info.files!.map((f) => f.name)).toContain('mychart/templates/svc.yaml');
    expect(info.previews!.map((p) => p.name)).toEqual(['mychart/Chart.yaml', 'mychart/values.yaml']);
  });

  it('detects an OCI artifact set and lists its layers', async () => {
    const manifest = JSON.stringify({
      schemaVersion: 2,
      layers: [
        { mediaType: 'application/octet-stream', digest: 'sha256:aa', size: 3 },
        { mediaType: 'application/octet-stream', digest: 'sha256:bb', size: 4 },
      ],
    });
    const tar: Uint8Array = writeTar([
      { name: 'artifact-set-descriptor.json', bytes: manifest },
      { name: 'blobs/sha256.aa', bytes: 'one' },
      { name: 'blobs/sha256.bb', bytes: 'two2' },
    ]);
    const info = await inspectBlob(tar, undefined, undefined);
    expect(info.kind).toBe('oci-artifact');
    expect(info.oci!.layers).toHaveLength(2);
    expect(info.oci!.layers[0]).toEqual({ mediaType: 'application/octet-stream', digest: 'sha256:aa', size: 3 });
    expect(info.previews![0]!.text).toContain('"layers"');
  });

  it('treats a tar without markers as generic tar and caps the file list', async () => {
    const entries = Array.from({ length: BLOB_FILES_MAX + 5 }, (_, i) => ({
      name: `files/f${String(i).padStart(4, '0')}.txt`,
      bytes: 'x',
    }));
    const info = await inspectBlob(writeTar(entries) as Uint8Array, undefined, undefined);
    expect(info.kind).toBe('tar');
    expect(info.files).toHaveLength(BLOB_FILES_MAX);
    expect(info.filesTruncated).toBe(true);
  });

  it('renders a hex head for binary blobs', async () => {
    const bytes = new Uint8Array(300);
    bytes.set([0x7f, 0x45, 0x4c, 0x46]); // ELF magic, then zeros
    const info = await inspectBlob(bytes, 'application/octet-stream', undefined);
    expect(info.kind).toBe('binary');
    expect(info.previews![0]!.name).toBe('first 256 bytes');
    expect(info.previews![0]!.text.startsWith('00000000  7f 45 4c 46')).toBe(true);
    expect(info.previews![0]!.truncated).toBe(true);
  });

  it('un-gzips compressed blobs and marks them compressed', async () => {
    const stream = new Blob([enc('{"inner":true}')]).stream().pipeThrough(new CompressionStream('gzip'));
    const gz = new Uint8Array(await new Response(stream).arrayBuffer());
    const info = await inspectBlob(gz, undefined, undefined);
    expect(info.compressed).toBe(true);
    expect(info.kind).toBe('json');
    expect(info.size).toBe(gz.byteLength);
  });
});

describe('inspectBlob — digest check', () => {
  it('matches genericBlobDigest/v1 against the stored bytes', async () => {
    const bytes = enc('payload');
    const value = await sha256Of(bytes);
    const info = await inspectBlob(bytes, undefined, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value,
    });
    expect(info.digestCheck).toBe('match');
  });

  it('checks the STORED (compressed) bytes for gzip blobs', async () => {
    const stream = new Blob([enc('payload')]).stream().pipeThrough(new CompressionStream('gzip'));
    const gz = new Uint8Array(await new Response(stream).arrayBuffer());
    const info = await inspectBlob(gz, undefined, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value: await sha256Of(gz),
    });
    expect(info.digestCheck).toBe('match');
  });

  it('reports a mismatch for a wrong declared value', async () => {
    const info = await inspectBlob(enc('payload'), undefined, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value: '9'.repeat(64),
    });
    expect(info.digestCheck).toBe('mismatch');
  });

  it('matches ociArtifactDigest/v1 against the manifest bytes', async () => {
    const manifest = JSON.stringify({ schemaVersion: 2, layers: [{ digest: 'sha256:aa', size: 1 }] });
    const tar: Uint8Array = writeTar([{ name: 'artifact-set-descriptor.json', bytes: manifest }]);
    const info = await inspectBlob(tar, undefined, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'ociArtifactDigest/v1',
      value: await sha256Of(enc(manifest)),
    });
    expect(info.digestCheck).toBe('match');
  });

  it('never guesses: unknown normalisation or hash stays unchecked, absent digest stays absent', async () => {
    const bytes = enc('payload');
    const unknownNorm = await inspectBlob(bytes, undefined, {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm: 'jsonNormalisation/v2',
      value: await sha256Of(bytes),
    });
    expect(unknownNorm.digestCheck).toBe('unchecked');

    const unknownHash = await inspectBlob(bytes, undefined, {
      hashAlgorithm: 'BLAKE3',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value: 'abc',
    });
    expect(unknownHash.digestCheck).toBe('unchecked');

    expect((await inspectBlob(bytes, undefined, undefined)).digestCheck).toBeUndefined();
    expect((await inspectBlob(bytes, undefined, {})).digestCheck).toBeUndefined();
  });

  it('accepts sha256/SHA-256 spellings and a sha256: value prefix', async () => {
    const bytes = enc('payload');
    const value = await sha256Of(bytes);
    const info = await inspectBlob(bytes, undefined, {
      hashAlgorithm: 'sha256',
      normalisationAlgorithm: 'genericBlobDigest/v1',
      value: `sha256:${value.toUpperCase()}`,
    });
    expect(info.digestCheck).toBe('match');
  });
});
