import { describe, expect, it } from 'vitest';
import { loadFixture } from '../test-fixtures';
import { detect } from './detect';

describe('detect', () => {
  it('detects SPDX 2.x JSON', () => {
    const result = detect(loadFixture('minimal.spdx.json'));
    expect(result.format).toBe('spdx2-json');
  });

  it('detects tag-value, including after leading comments', () => {
    expect(detect(loadFixture('minimal.spdx')).format).toBe('spdx2-tag-value');
    expect(detect(loadFixture('quirks.spdx')).format).toBe('spdx2-tag-value');
  });

  it('detects SPDX 2.x YAML and routes it to the JSON normalizer', () => {
    const result = detect(loadFixture('minimal.spdx.yaml'));
    expect(result).toMatchObject({ format: 'spdx2-json', serialization: 'yaml' });
  });

  it('rejects broken YAML with the parse error', () => {
    const result = detect('spdxVersion: SPDX-2.3\npackages:\n  - name: [broken');
    expect(result).toMatchObject({ format: 'unsupported', code: 'YAML_INVALID' });
  });

  it('recognizes an SBOM Lens profile and points at the import path', () => {
    const detection = detect('{"schema":"sbomlens-profile/v1","name":"x","checks":[]}');
    expect(detection).toMatchObject({ format: 'unsupported', code: 'SBOMLENS_PROFILE' });
  });

  it('routes CycloneDX JSON to the cdx parser', () => {
    const result = detect(loadFixture('cdx/minimal.cdx.json'));
    expect(result).toMatchObject({ format: 'cdx-json', serialization: 'json' });
  });

  it('routes CycloneDX XML to the same cdx parser, in JSON shape', () => {
    const result = detect(loadFixture('cdx/minimal.cdx.xml'));
    expect(result).toMatchObject({ format: 'cdx-json', serialization: 'xml' });
  });

  it('recognizes Trivy-native JSON (even when named *.spdx.json)', () => {
    const result = detect(loadFixture('negative/trivy-native.json'));
    expect(result).toMatchObject({ format: 'unsupported', code: 'TRIVY_NATIVE_NOT_SUPPORTED' });
  });

  it('routes SPDX 3.x JSON-LD to the spdx3 parser', () => {
    const result = detect(loadFixture('negative/spdx3.json'));
    expect(result).toMatchObject({ format: 'spdx3-json' });
  });

  it('rejects arbitrary text', () => {
    const result = detect(loadFixture('negative/garbage.txt'));
    expect(result).toMatchObject({ format: 'unsupported', code: 'UNRECOGNIZED_FORMAT' });
  });

  it('rejects broken JSON with the parse error', () => {
    const result = detect('{ "spdxVersion": ');
    expect(result).toMatchObject({ format: 'unsupported', code: 'JSON_INVALID' });
  });
});

describe('detect: JSON-LD contexts and the fallback message', () => {
  const graph = [{ type: 'CreationInfo', '@id': '_:ci', specVersion: '3.0.1', created: '2026-06-01T10:00:00Z' }];

  it('routes SPDX 3 whose @context is an object, or an array holding one', () => {
    for (const context of [
      { '@vocab': 'https://spdx.org/rdf/3.0.1/terms/' },
      ['https://spdx.org/rdf/3.0.1/spdx-context.jsonld', { acme: 'https://acme.example/' }],
      [{ '@import': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld' }],
    ]) {
      expect(detect(JSON.stringify({ '@context': context, '@graph': graph })).format).toBe('spdx3-json');
    }
  });

  it('names every supported format when a JSON document is none of them', () => {
    const result = detect('{"hello":"world"}');
    expect(result).toMatchObject({ format: 'unsupported', code: 'JSON_NOT_SPDX' });
    if (result.format === 'unsupported') {
      expect(result.reason).toContain('SPDX 2');
      expect(result.reason).toContain('SPDX 3');
      expect(result.reason).toContain('CycloneDX');
    }
  });
});

describe('detect: CycloneDX VEX', () => {
  it('refuses a standalone CycloneDX VEX BOM instead of loading an empty SBOM', () => {
    const vex = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      metadata: { component: { type: 'application', 'bom-ref': 'app', name: 'app' } },
      vulnerabilities: [{ id: 'CVE-2026-0001', analysis: { state: 'not_affected' }, affects: [{ ref: 'app' }] }],
    });
    const result = detect(vex);
    expect(result).toMatchObject({ format: 'unsupported', code: 'CDX_VEX_NOT_SUPPORTED' });
    if (result.format === 'unsupported') expect(result.reason).toContain('OpenVEX');
  });

  it('still loads an SBOM that carries vulnerabilities next to its components', () => {
    const sbom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [{ type: 'library', 'bom-ref': 'lib', name: 'lib' }],
      vulnerabilities: [{ id: 'CVE-2026-0001' }],
    });
    expect(detect(sbom)).toMatchObject({ format: 'cdx-json' });
  });
});

describe('detect: CycloneDX inventory nested under the subject', () => {
  it('loads a BOM whose components hang under metadata.component, vulnerabilities or not', () => {
    const nested = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      metadata: {
        component: {
          type: 'application',
          'bom-ref': 'app',
          name: 'app',
          components: [{ type: 'library', 'bom-ref': 'lib', name: 'lib' }],
        },
      },
      vulnerabilities: [{ id: 'CVE-2026-0001', affects: [{ ref: 'lib' }] }],
    });
    expect(detect(nested)).toMatchObject({ format: 'cdx-json' });
  });
});
