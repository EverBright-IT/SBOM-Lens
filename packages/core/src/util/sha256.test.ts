import { describe, expect, it } from 'vitest';
import { blobSource, bufferSource, chunkedSource, windowSource } from './bytesource';
import { Sha256, sha256SourceHex } from './sha256';

async function reference(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes).buffer as ArrayBuffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function deterministicBytes(length: number, seed = 7): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed;
  for (let i = 0; i < length; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    out[i] = state & 0xff;
  }
  return out;
}

describe('Sha256 (incremental)', () => {
  it('matches the FIPS test vectors', () => {
    expect(new Sha256().digestHex()).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(new Sha256().update(new TextEncoder().encode('abc')).digestHex()).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('matches crypto.subtle for every length around the block/padding edges', async () => {
    for (let length = 0; length <= 130; length++) {
      const bytes = deterministicBytes(length, length + 1);
      expect(new Sha256().update(bytes).digestHex(), `length ${length}`).toBe(await reference(bytes));
    }
  });

  it('is split-invariant: chunk boundaries at every offset agree', async () => {
    const bytes = deterministicBytes(257);
    const expected = await reference(bytes);
    for (let split = 0; split <= bytes.length; split += 13) {
      const hash = new Sha256();
      hash.update(bytes.subarray(0, split));
      hash.update(bytes.subarray(split));
      expect(hash.digestHex(), `split ${split}`).toBe(expected);
    }
  });

  it('matches crypto.subtle on multi-chunk input', async () => {
    const bytes = deterministicBytes(3 * 1024 * 1024 + 17);
    const hash = new Sha256();
    for (let offset = 0; offset < bytes.length; offset += 65_537) {
      hash.update(bytes.subarray(offset, Math.min(offset + 65_537, bytes.length)));
    }
    expect(hash.digestHex()).toBe(await reference(bytes));
  });

  it('refuses updates after the digest was taken', () => {
    const hash = new Sha256();
    hash.digestHex();
    expect(() => hash.update(new Uint8Array(1))).toThrow();
  });
});

describe('ByteSource', () => {
  const bytes = deterministicBytes(1000);

  it('bufferSource reads ranges and clamps at EOF', async () => {
    const source = bufferSource(bytes);
    expect(await source.read(10, 5)).toEqual(bytes.subarray(10, 15));
    expect((await source.read(990, 100)).byteLength).toBe(10);
    expect((await source.read(2000, 10)).byteLength).toBe(0);
  });

  it('blobSource reads the same ranges through Blob.slice', async () => {
    const source = blobSource(new Blob([new Uint8Array(bytes)]));
    expect(source.size).toBe(1000);
    expect(await source.read(123, 77)).toEqual(bytes.subarray(123, 200));
    expect((await source.read(990, 100)).byteLength).toBe(10);
  });

  it('windowSource confines reads to its range', async () => {
    const window = windowSource(bufferSource(bytes), 100, 50);
    expect(window.size).toBe(50);
    expect(await window.read(0, 10)).toEqual(bytes.subarray(100, 110));
    expect((await window.read(45, 100)).byteLength).toBe(5);
    expect((await window.read(60, 4)).byteLength).toBe(0);
  });

  it('chunkedSource serves sequential and backward reads correctly', async () => {
    let reads = 0;
    const counted = {
      size: bytes.byteLength,
      read: (offset: number, length: number) => {
        reads++;
        return bufferSource(bytes).read(offset, length);
      },
    };
    const source = chunkedSource(counted);
    for (let offset = 0; offset + 100 <= 1000; offset += 100) {
      expect(await source.read(offset, 100)).toEqual(bytes.subarray(offset, offset + 100));
    }
    expect(reads).toBe(1); // one window fill served ten sequential reads
    expect(await source.read(50, 20)).toEqual(bytes.subarray(50, 70)); // backward
    expect((await source.read(995, 50)).byteLength).toBe(5); // EOF clamp
  });

  it('sha256SourceHex hashes a range identically to a one-shot hash', async () => {
    const big = deterministicBytes(300_000);
    const expected = await reference(big.subarray(1234, 1234 + 200_000));
    expect(await sha256SourceHex(bufferSource(big), 1234, 200_000)).toBe(expected);
    expect(await sha256SourceHex(blobSource(new Blob([new Uint8Array(big)])), 1234, 200_000)).toBe(expected);
  });
});
