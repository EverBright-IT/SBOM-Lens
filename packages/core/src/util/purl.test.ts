import { describe, expect, it } from 'vitest';
import { PurlError, buildPurl } from './purl';

/**
 * Pinned against the purl-spec type definitions and README examples: a
 * composer's purl must be canonical, not merely parseable.
 */

describe('buildPurl', () => {
  it('builds the canonical oci form (spec example shape)', () => {
    // purl-spec oci example: pkg:oci/debian@sha256%3A244fd47e07d1004f0aed9c
    expect(
      buildPurl({ type: 'oci', name: 'Debian', version: 'sha256:244fd47e07d1004f0aed9c' }),
    ).toBe('pkg:oci/debian@sha256%3A244fd47e07d1004f0aed9c');
    expect(
      buildPurl({
        type: 'oci',
        name: 'static',
        version: 'sha256:244fd47e07d10',
        qualifiers: { repository_url: 'gcr.io/distroless/static', tag: 'latest' },
      }),
    ).toBe('pkg:oci/static@sha256%3A244fd47e07d10?repository_url=gcr.io/distroless/static&tag=latest');
  });

  it('rejects an oci namespace with the registry hint', () => {
    expect(() => buildPurl({ type: 'oci', namespace: 'ghcr.io', name: 'x' })).toThrow(/repository_url/);
  });

  it('builds maven with groupId namespace, preserving case', () => {
    expect(
      buildPurl({ type: 'maven', namespace: 'org.apache.xmlgraphics', name: 'batik-anim', version: '1.9.1' }),
    ).toBe('pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1');
    expect(() => buildPurl({ type: 'maven', name: 'no-group' })).toThrow(PurlError);
  });

  it('lowercases npm names and scopes and encodes the @ of the scope', () => {
    expect(buildPurl({ type: 'npm', namespace: '@Acme', name: 'WebStack', version: '3.0.0' })).toBe(
      'pkg:npm/%40acme/webstack@3.0.0',
    );
  });

  it('percent-encodes separators inside segments', () => {
    expect(buildPurl({ type: 'generic', name: 'a b/c@d', version: '1+2' })).toBe('pkg:generic/a%20b%2Fc%40d@1%2B2');
  });

  it('sorts qualifiers by key, lowercases keys, drops empty values', () => {
    expect(
      buildPurl({
        type: 'generic',
        name: 'thing',
        qualifiers: { 'x-Channel': 'stable', arch: 'amd64', empty: '' },
      }),
    ).toBe('pkg:generic/thing?arch=amd64&x-channel=stable');
  });

  it('rejects invalid and duplicate qualifier keys', () => {
    expect(() => buildPurl({ type: 'generic', name: 'x', qualifiers: { 'bad key': 'v' } })).toThrow(PurlError);
    expect(() => buildPurl({ type: 'generic', name: 'x', qualifiers: { A: '1', a: '2' } })).toThrow(/duplicate/);
  });

  it('cleans subpaths of empty, dot, and dotdot segments', () => {
    expect(buildPurl({ type: 'generic', name: 'x', subpath: './lib/../lib/util.js/' })).toBe(
      'pkg:generic/x#lib/lib/util.js',
    );
  });

  it('refuses unsupported types loudly', () => {
    expect(() => buildPurl({ type: 'deb' as never, name: 'curl' })).toThrow(/unsupported purl type/);
  });
});
