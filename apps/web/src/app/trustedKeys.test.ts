import { beforeEach, describe, expect, it } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import { addTrustedKey, loadTrustedKeys, removeTrustedKey } from './trustedKeys';

/** Pref-backed key pinning against a host stub — only prefs are exercised. */

const prefs = new Map<string, string>();

beforeEach(() => {
  prefs.clear();
  setHost({
    kind: 'web',
    caps: { catalog: false },
    fetchDocument: async () => ({ ok: false }),
    readPref: (key) => prefs.get(key) ?? null,
    persistPref: (key, value) => void prefs.set(key, value),
    secretGet: async () => null,
    secretSet: async () => {},
    exportFile: () => {},
    openExternal: () => {},
    createWorker: () => {
      throw new Error('no worker in this test');
    },
    onIngestMessage: () => {},
  } satisfies HostAdapter);
});

async function generatePem(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const b64 = btoa(String.fromCharCode(...spki));
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END PUBLIC KEY-----\n`;
}

describe('trusted signature keys', () => {
  it('round-trips a pinned key through prefs', async () => {
    const pem = await generatePem();
    expect(addTrustedKey('acme-release', pem)).toEqual({ ok: true });
    expect(loadTrustedKeys()).toEqual([{ label: 'acme-release', pem }]);
  });

  it('re-pinning a label replaces the key (rotation)', async () => {
    const first = await generatePem();
    const second = await generatePem();
    addTrustedKey('acme', first);
    addTrustedKey('acme', second);
    const keys = loadTrustedKeys();
    expect(keys).toHaveLength(1);
    expect(keys[0]!.pem).toBe(second);
  });

  it('rejects a paste that is not key-shaped, with a reason', () => {
    const outcome = addTrustedKey('junk', 'not a pem at all');
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.length).toBeGreaterThan(0);
    expect(loadTrustedKeys()).toEqual([]);
  });

  it('requires a label', async () => {
    expect(addTrustedKey('   ', await generatePem()).ok).toBe(false);
  });

  it('removes by label', async () => {
    const pem = await generatePem();
    addTrustedKey('keep', pem);
    addTrustedKey('drop', pem);
    expect(removeTrustedKey('drop').map((k) => k.label)).toEqual(['keep']);
    expect(loadTrustedKeys().map((k) => k.label)).toEqual(['keep']);
  });

  it('caps the pinned set at 16 keys', async () => {
    const pem = await generatePem();
    for (let i = 0; i < 16; i++) expect(addTrustedKey(`key-${i}`, pem).ok).toBe(true);
    expect(addTrustedKey('one-too-many', pem).ok).toBe(false);
    expect(loadTrustedKeys()).toHaveLength(16);
  });

  it('treats corrupt stored state as empty instead of throwing', () => {
    prefs.set('ocmlens.trustedKeys', '{not json');
    prefs.set('sbomlens.trustedKeys', '{not json');
    expect(loadTrustedKeys()).toEqual([]);
  });
});
