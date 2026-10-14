import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The app ships copies of core fixtures (the demo delivery and the test
 * public key). Copies drift; these tests pin them to their sources.
 */

function app(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../public/examples/${name}`, import.meta.url)));
}

function core(name: string): Uint8Array {
  return new Uint8Array(
    readFileSync(new URL(`../../../packages/core/fixtures/ocm/${name}`, import.meta.url)),
  );
}

describe('bundled demo assets', () => {
  it('demo delivery equals the committed core fixture byte-for-byte', () => {
    expect(app('ecme-delivery.ctf.tar')).toEqual(core('ecme-delivery.ctf.tar'));
  });

  it('demo public key equals the committed test key', () => {
    expect(app('ecme-public-key.pem')).toEqual(core('keys/test-rsa.pub.pem'));
  });
});
