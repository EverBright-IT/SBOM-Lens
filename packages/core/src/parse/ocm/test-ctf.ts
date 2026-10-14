// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../../scripts/tar-writer.mjs';

/**
 * Test support: build minimal flat-layout CTFs from descriptor texts.
 * Digest strings are lookup keys for the walk, not verified hashes, so
 * stable fakes keep the fixtures readable. Imported by tests only.
 */

export function ctfOf(cds: string[]): Uint8Array {
  const hex = (i: number, c: string) => c.repeat(63) + i.toString(16);
  const entries: { name: string; bytes: string }[] = [];
  const artifacts = cds.map((cd, i) => {
    const cdDigest = `sha256:${hex(i, 'a')}`;
    const manifestDigest = `sha256:${hex(i, 'b')}`;
    const manifest = JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      layers: [
        {
          mediaType: 'application/vnd.ocm.software.component-descriptor.v2+yaml',
          digest: cdDigest,
          size: cd.length,
        },
      ],
    });
    entries.push({ name: `blobs/${manifestDigest.replace(':', '.')}`, bytes: manifest });
    entries.push({ name: `blobs/${cdDigest.replace(':', '.')}`, bytes: cd });
    return { repository: `component-descriptors/cv-${i}`, tag: `${i}`, digest: manifestDigest };
  });
  const index = JSON.stringify({ schemaVersion: 1, artifacts });
  return new Uint8Array(writeTar([{ name: 'artifact-index.json', bytes: index }, ...entries]));
}

export function cd(name: string, version: string, refs: [string, string][], extra = ''): string {
  const references =
    refs.length === 0
      ? '  componentReferences: []\n'
      : `  componentReferences:\n${refs
          .map(([n, v]) => `    - name: ${n.split('/').pop()}\n      componentName: ${n}\n      version: ${v}\n`)
          .join('')}`;
  return `meta:\n  schemaVersion: v2\ncomponent:\n  name: ${name}\n  version: ${version}\n  provider: ACME Corp\n  sources: []\n  resources: []\n${references}${extra}`;
}
