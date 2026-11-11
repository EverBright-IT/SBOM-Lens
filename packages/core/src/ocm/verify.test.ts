import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { detect } from '../parse/detect';
import { hashHex } from '../util/sha1';
import { normalizeDescriptor } from './normalize';
import { spkiFromPem } from './pem';
import { referenceDigestChecker, verifyRawSignatures, verifySignature, type SignatureNode } from './verify';

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

/**
 * Reference digests, again against the real CLI (v0.54.0): `ocm sign` on
 * example.org/root recorded the digest of the example.org/child it
 * references; child-swapped.yaml is the descriptor `ocm transfer
 * --overwrite` later put in its place, for which `ocm verify` reports
 * "calculated reference digest (SHA-256:991ae0af...) mismatches existing
 * digest (SHA-256:41ba5337...)".
 */
describe('referenceDigestChecker', () => {
  type Descriptor = { component: Record<string, unknown> };
  const cli = (name: string): Descriptor => {
    const detection = detect(fixture(`reference-digest/${name}`));
    if (detection.format !== 'ocm-cd') throw new Error(`${name} is not a component descriptor`);
    return detection.parsed as Descriptor;
  };
  const delivery =
    (...descriptors: Descriptor[]) =>
    (componentName: string, version: string) =>
      descriptors.filter((d) => d.component.name === componentName && d.component.version === version);

  const cv = (name: string, componentReferences: unknown[] = [], resources: unknown[] = []): Descriptor => ({
    component: { name, version: '1.0.0', provider: 'acme', resources, componentReferences },
  });
  const referenceTo = async (target: Descriptor, normalisationAlgorithm = 'jsonNormalisation/v4alpha1') => ({
    name: 'ref',
    componentName: target.component.name,
    version: target.component.version,
    digest: {
      hashAlgorithm: 'SHA-256',
      normalisationAlgorithm,
      value: await hashHex('SHA-256', normalizeDescriptor(target, 'jsonNormalisation/v4alpha1')),
    },
  });

  it('matches the digest the CLI recorded for the child it signed over', async () => {
    const signedRoot = cli('root.yaml');
    expect(await verifyRawSignatures(signedRoot, publicKey)).toMatchObject([{ verdict: 'valid' }]);
    expect(await referenceDigestChecker(delivery(cli('child.yaml')))(signedRoot)).toEqual({ verdict: 'match' });
  });

  it('reports the swapped child, as the CLI does', async () => {
    const swapped = cli('child-swapped.yaml');
    expect(await hashHex('SHA-256', normalizeDescriptor(swapped, 'jsonNormalisation/v3'))).toBe(
      '991ae0af27139348137f5c3661d62221866f5f90e00a13f2f226810e81e2090e',
    );
    const check = await referenceDigestChecker(delivery(swapped))(cli('root.yaml'));
    expect(check.verdict).toBe('mismatch');
    expect(check.reason).toContain('example.org/child@1.0.0');
  });

  it('reports a mismatch when a swapped descriptor sits next to the referenced one', async () => {
    const check = await referenceDigestChecker(delivery(cli('child.yaml'), cli('child-swapped.yaml')))(
      cli('root.yaml'),
    );
    expect(check.verdict).toBe('mismatch');
  });

  it('follows the references of every component version that matched', async () => {
    const leaf = cv('acme.org/leaf');
    const mid = cv('acme.org/mid', [await referenceTo(leaf)]);
    const top = cv('acme.org/top', [await referenceTo(mid)]);
    expect(await referenceDigestChecker(delivery(mid, leaf))(top)).toEqual({ verdict: 'match' });

    const otherLeaf = cv('acme.org/leaf', [], [{ name: 'extra', digest: { value: 'ab' } }]);
    const check = await referenceDigestChecker(delivery(mid, otherLeaf))(top);
    expect(check.verdict).toBe('mismatch');
    expect(check.reason).toContain('acme.org/leaf@1.0.0');
  });

  it('is unchecked, never a match or a mismatch, where it cannot compare', async () => {
    const leaf = cv('acme.org/leaf');
    const reference = await referenceTo(leaf);
    const check = (top: Descriptor, ...delivered: Descriptor[]) =>
      referenceDigestChecker(delivery(...delivered))(top);

    // The referenced component version is not delivered.
    expect(await check(cv('acme.org/top', [reference]))).toMatchObject({ verdict: 'unchecked' });
    // The reference records no digest.
    expect(await check(cv('acme.org/top', [{ ...reference, digest: undefined }]), leaf)).toMatchObject({
      verdict: 'unchecked',
    });
    // The digest uses a normalisation this verifier does not implement.
    expect(
      await check(cv('acme.org/top', [await referenceTo(leaf, 'jsonNormalisation/v1')]), leaf),
    ).toMatchObject({ verdict: 'unchecked' });
    // The delivered descriptor lacks the artifact digests the signed form had.
    const undigested = cv('acme.org/leaf', [], [{ name: 'data', type: 'plainText' }]);
    expect(await check(cv('acme.org/top', [reference]), undigested)).toMatchObject({
      verdict: 'unchecked',
    });
    // References that point at each other can never both hold.
    const a = cv('acme.org/a');
    const b = cv('acme.org/b', [await referenceTo(a)]);
    (a.component.componentReferences as unknown[]).push(await referenceTo(b));
    expect((await check(a, a, b)).verdict).not.toBe('match');
  });
});
