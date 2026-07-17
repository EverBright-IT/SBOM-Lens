import { describe, expect, it } from 'vitest';
import { validateComposeConfig } from './config';

/**
 * The validator is closed-world: a composer that tolerates a typo emits a
 * WRONG document, so every unknown key and every off-enum value is an error.
 */

function minimal(): Record<string, unknown> {
  return {
    schema: 'sbomloom-compose/v1',
    product: { name: 'acme-suite', version: '2.0.0', namespace: 'https://acme.example/spdx/acme-suite-2.0.0' },
    artifacts: [{ name: 'webstack', type: 'container' }],
  };
}

function errorsOf(raw: unknown): string[] {
  const result = validateComposeConfig(raw);
  return result.ok ? [] : result.errors;
}

describe('validateComposeConfig', () => {
  it('accepts a minimal config and maps type to primaryPackagePurpose', () => {
    const result = validateComposeConfig(minimal());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.product.namespace).toBe('https://acme.example/spdx/acme-suite-2.0.0');
    expect(result.config.artifacts[0].purpose).toBe('CONTAINER');
  });

  it('rejects a wrong or missing schema outright', () => {
    expect(errorsOf({ ...minimal(), schema: 'sbomloom-compose/v2' })[0]).toMatch(/schema/);
    expect(errorsOf({ product: {}, artifacts: [] })[0]).toMatch(/schema/);
    expect(errorsOf('not an object')[0]).toMatch(/object/);
  });

  it('rejects unknown keys at every level', () => {
    expect(errorsOf({ ...minimal(), extra: 1 })).toContain('unknown key "extra"');
    const cfg = minimal();
    (cfg.product as Record<string, unknown>).vendor = 'ACME';
    expect(errorsOf(cfg)).toContain('unknown key "product.vendor"');
    const cfg2 = minimal();
    (cfg2.artifacts as Record<string, unknown>[])[0].path = 'x';
    expect(errorsOf(cfg2)).toContain('unknown key "artifacts[0].path"');
  });

  it('requires product name, version, and an absolute-URI namespace', () => {
    const cfg = minimal();
    cfg.product = { name: 'x', version: '1' };
    expect(errorsOf(cfg).join()).toMatch(/product\.namespace is required/);
    (cfg.product as Record<string, unknown>).namespace = 'no-scheme/path';
    expect(errorsOf(cfg).join()).toMatch(/absolute URI/);
    (cfg.product as Record<string, unknown>).namespace = 'https://acme.example/ns#frag';
    expect(errorsOf(cfg).join()).toMatch(/without a fragment/);
  });

  it('rejects unknown artifact types but lets an explicit purpose override', () => {
    const cfg = minimal();
    (cfg.artifacts as Record<string, unknown>[])[0] = { name: 'x', type: 'flatpak' };
    expect(errorsOf(cfg).join()).toMatch(/unknown artifact type "flatpak"/);
    (cfg.artifacts as Record<string, unknown>[])[0] = { name: 'x', type: 'flatpak', purpose: 'application' };
    const result = validateComposeConfig(cfg);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.config.artifacts[0].purpose).toBe('APPLICATION');
  });

  it('rejects purposes outside the SPDX 2.3 enum', () => {
    const cfg = minimal();
    (cfg.artifacts as Record<string, unknown>[])[0] = { name: 'x', purpose: 'MODULE' };
    expect(errorsOf(cfg).join()).toMatch(/not an SPDX 2.3 primaryPackagePurpose/);
  });

  it('enforces the x- prefix for custom purl qualifiers', () => {
    const cfg = minimal();
    (cfg.artifacts as Record<string, unknown>[])[0] = {
      name: 'x',
      purl: { type: 'generic', qualifiers: { deployment_ring: 'prod' } },
    };
    expect(errorsOf(cfg).join()).toMatch(/"deployment_ring" — custom qualifiers must use the "x-" prefix/);
    (cfg.artifacts as Record<string, unknown>[])[0] = {
      name: 'x',
      purl: { type: 'generic', qualifiers: { 'x-deployment-ring': 'prod', arch: 'amd64' } },
    };
    expect(validateComposeConfig(cfg).ok).toBe(true);
  });

  it('dry-runs the purl builder so type rules fail the config, not the compose', () => {
    const cfg = minimal();
    (cfg.artifacts as Record<string, unknown>[])[0] = {
      name: 'x',
      purl: { type: 'oci', namespace: 'ghcr.io' },
    };
    expect(errorsOf(cfg).join()).toMatch(/repository_url/);
    const cfg2 = minimal();
    (cfg2.artifacts as Record<string, unknown>[])[0] = { name: 'x', purl: { type: 'maven' } };
    expect(errorsOf(cfg2).join()).toMatch(/groupId/);
    const cfg3 = minimal();
    (cfg3.artifacts as Record<string, unknown>[])[0] = { name: 'x', purl: { type: 'deb' } };
    expect(errorsOf(cfg3).join()).toMatch(/must be one of oci, generic, maven, npm/);
  });

  it('rejects duplicate artifact names and empty artifact lists', () => {
    const cfg = minimal();
    cfg.artifacts = [{ name: 'same' }, { name: 'same' }];
    expect(errorsOf(cfg).join()).toMatch(/duplicate artifact name "same"/);
    cfg.artifacts = [];
    expect(errorsOf(cfg).join()).toMatch(/non-empty array/);
  });

  it('constrains relationship edges to CONTAINS or DEPENDS_ON', () => {
    expect(errorsOf({ ...minimal(), relationshipType: 'BUNDLES' }).join()).toMatch(/CONTAINS.*DEPENDS_ON/);
    const cfg = minimal();
    (cfg.artifacts as Record<string, unknown>[])[0].relationship = 'DEPENDS_ON';
    expect(validateComposeConfig(cfg).ok).toBe(true);
  });

  it('normalizes checksums and rejects non-hex values', () => {
    const cfg = minimal();
    (cfg.artifacts as Record<string, unknown>[])[0].checksums = [
      { algorithm: 'sha-256', value: 'ABCDEF012345' },
    ];
    const result = validateComposeConfig(cfg);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.config.artifacts[0].checksums).toEqual([{ algorithm: 'SHA256', value: 'abcdef012345' }]);
    (cfg.artifacts as Record<string, unknown>[])[0].checksums = [{ algorithm: 'SHA256', value: 'not hex!' }];
    expect(errorsOf(cfg).join()).toMatch(/checksums\[0\]/);
  });
});
