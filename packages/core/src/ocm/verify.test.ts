import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { hashHex } from '../util/sha1';
import { normalizeDescriptor } from './normalize';
import { spkiFromPem } from './pem';
import { verifySignature, type SignatureNode } from './verify';

/**
 * The load-bearing tests: a descriptor and signature produced by the real
 * `ocm` CLI (v0.9.0). If our normalisation or PSS convention drifts from the
 * CLI, these break — which is the point.
 */

function fixture(name: string): string {
  return readFileSync(new URL(`../../fixtures/ocm/${name}`, import.meta.url), 'utf8');
}

const descriptor = JSON.parse(fixture('signed-descriptor.json')) as {
  component: Record<string, unknown>;
  signatures: SignatureNode[];
};
const publicKey = fixture('keys/test-rsa.pub.pem');
const signature = descriptor.signatures[0]!;
// The descriptor node the verifier normalises has no signatures block.
const root = { component: descriptor.component };

describe('normalizeDescriptor — gold value against the ocm CLI', () => {
  it('reproduces the digest the CLI recorded (jsonNormalisation/v4alpha1)', async () => {
    const bytes = normalizeDescriptor(root, 'jsonNormalisation/v4alpha1');
    const digest = await hashHex('SHA-256', bytes);
    expect(digest).toBe(signature.digest!.value);
  });

  it('refuses an unknown normalisation and a non-integer number', () => {
    expect(() => normalizeDescriptor(root, 'jsonNormalisation/v99')).toThrow();
    expect(() =>
      normalizeDescriptor({ component: { name: 'x', version: '1', value: 1.5 } }, 'jsonNormalisation/v4alpha1'),
    ).toThrow();
  });
});

describe('spkiFromPem', () => {
  it('imports a PUBLIC KEY block as SPKI', async () => {
    const spki = spkiFromPem(publicKey);
    const key = await crypto.subtle.importKey(
      'spki',
      spki as unknown as ArrayBuffer,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    expect(key.type).toBe('public');
  });
});

describe('verifySignature', () => {
  it('accepts the CLI signature as valid, with the digest matching', async () => {
    const result = await verifySignature(root, signature, publicKey);
    expect(result.verdict).toBe('valid');
    expect(result.digestMatch).toBe(true);
  });

  it('reports invalid + digest changed when a resource is tampered with', async () => {
    const tampered = structuredClone(root) as typeof root;
    const resources = tampered.component.resources as Record<string, unknown>[];
    (resources[0]!.digest as Record<string, unknown>).value = 'f'.repeat(64);
    const result = await verifySignature(tampered, signature, publicKey);
    expect(result.verdict).toBe('invalid');
    expect(result.digestMatch).toBe(false);
    expect(result.reason).toContain('does not match');
  });

  it('reports invalid when verified against the wrong key', async () => {
    // A different well-formed RSA public key (structurally valid, wrong key).
    const otherKey = [
      '-----BEGIN PUBLIC KEY-----',
      'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf',
      '9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==',
      '-----END PUBLIC KEY-----',
    ].join('\n');
    const result = await verifySignature(root, signature, otherKey);
    expect(result.verdict).toBe('invalid');
    // The digest still matches (descriptor unchanged); only the key is wrong.
    expect(result.digestMatch).toBe(true);
  });

  it('is unverifiable on an unsupported normalisation, never a false verdict', async () => {
    const weird: SignatureNode = {
      ...signature,
      digest: { ...signature.digest, normalisationAlgorithm: 'jsonNormalisation/v1' },
    };
    const result = await verifySignature(root, weird, publicKey);
    expect(result.verdict).toBe('unverifiable');
    expect(result.reason).toContain('normalisation');
  });

  it('is unverifiable on an unsupported signature algorithm', async () => {
    const weird: SignatureNode = {
      ...signature,
      signature: { ...signature.signature, algorithm: 'ed25519', mediaType: 'application/vnd.ocm.signature.ed25519' },
    };
    const result = await verifySignature(root, weird, publicKey);
    expect(result.verdict).toBe('unverifiable');
  });

  it('is unverifiable when the key cannot be imported', async () => {
    const result = await verifySignature(root, signature, 'not a pem');
    expect(result.verdict).toBe('unverifiable');
  });
});
