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

  it('recognizes CycloneDX with a helpful message', () => {
    const result = detect(loadFixture('negative/cyclonedx.json'));
    expect(result).toMatchObject({ format: 'unsupported', code: 'CYCLONEDX_NOT_SUPPORTED' });
  });

  it('recognizes Trivy-native JSON (even when named *.spdx.json)', () => {
    const result = detect(loadFixture('negative/trivy-native.json'));
    expect(result).toMatchObject({ format: 'unsupported', code: 'TRIVY_NATIVE_NOT_SUPPORTED' });
  });

  it('recognizes SPDX 3.x with a roadmap message', () => {
    const result = detect(loadFixture('negative/spdx3.json'));
    expect(result).toMatchObject({ format: 'unsupported', code: 'SPDX3_NOT_YET_SUPPORTED' });
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
