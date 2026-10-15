import { describe, expect, it } from 'vitest';
import { splitPurl } from './purl';

describe('splitPurl', () => {
  it('splits type, namespace and name, decodes, and drops qualifiers and subpath', () => {
    expect(splitPurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar#src')).toEqual({
      segments: ['maven', 'org.apache.logging.log4j', 'log4j-core'],
      version: '2.14.1',
    });
    expect(splitPurl('pkg:oci/webstack@sha256%3Aabc')).toEqual({ segments: ['oci', 'webstack'], version: 'sha256:abc' });
  });

  it('never reads an npm scope as a version', () => {
    expect(splitPurl('pkg:npm/@angular/core')).toEqual({ segments: ['npm', '@angular', 'core'] });
    expect(splitPurl('pkg:npm/@angular')).toEqual({ segments: ['npm', '@angular'] });
    expect(splitPurl('pkg:npm/%40angular/core@17.0.0')).toEqual({
      segments: ['npm', '@angular', 'core'],
      version: '17.0.0',
    });
  });

  it('rejects what is not a purl', () => {
    expect(splitPurl('cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*')).toBeUndefined();
    expect(splitPurl('pkg:')).toBeUndefined();
  });
});
