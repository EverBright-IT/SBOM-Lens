import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain-JS test/fixture helper without type declarations
import { writeTar } from '../../scripts/tar-writer.mjs';
import { GunzipLimitError, gunzip, sniffContainer } from './binary';
import { readTar, readTarFrom } from './tar';
import { bufferSource } from './bytesource';

const text = (s: string) => new TextEncoder().encode(s);

describe('readTar', () => {
  it('round-trips entries written by the deterministic writer', () => {
    const tar: Uint8Array = writeTar([
      { name: 'component-descriptor.yaml', bytes: 'meta: {}\n' },
      { name: 'blobs/sha256.abc', bytes: text('BLOB') },
    ]);
    const { entries, diagnostics } = readTar(tar);
    expect(diagnostics).toHaveLength(0);
    expect(entries.map((e) => e.name)).toEqual(['blobs/sha256.abc', 'component-descriptor.yaml']);
    expect(new TextDecoder().decode(entries[0]!.bytes)).toBe('BLOB');
  });

  it('resolves PAX long names', () => {
    const longName = `deep/${'d'.repeat(120)}/file.yaml`;
    const tar: Uint8Array = writeTar([{ name: longName, bytes: 'x' }]);
    const { entries } = readTar(tar);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe(longName);
  });

  it('resolves GNU L longname headers', () => {
    // Hand-build: an 'L' entry whose data is the real name, then the file.
    const base: Uint8Array = writeTar([{ name: 'placeholder', bytes: 'DATA' }]);
    const gnuName = 'gnu/very-long-name.txt\0';
    const lHeader = base.slice(0, 512); // reuse a valid header, then patch it
    patch(lHeader, 0, 'placeholder\0');
    patch(lHeader, 124, gnuName.length.toString(8).padStart(11, '0') + '\0');
    lHeader[156] = 'L'.charCodeAt(0);
    rechecksum(lHeader);
    const lData = new Uint8Array(512);
    lData.set(text(gnuName));
    const tar = concat(lHeader, lData, base);
    const { entries } = readTar(tar);
    expect(entries[0]!.name).toBe('gnu/very-long-name.txt');
  });

  it('rejects non-tar input with TAR_CORRUPT', () => {
    const junk = new Uint8Array(1024).fill(0x41);
    const { entries, diagnostics } = readTar(junk);
    expect(entries).toHaveLength(0);
    expect(diagnostics[0]!.code).toBe('TAR_CORRUPT');
  });

  it('reports truncation and keeps earlier entries', () => {
    const tar: Uint8Array = writeTar([
      { name: 'a.txt', bytes: 'A' },
      { name: 'b.txt', bytes: 'B'.repeat(600) },
    ]);
    const cut = tar.slice(0, 512 + 512 + 512 + 100); // a.txt complete, b.txt header + partial data
    const { entries, diagnostics } = readTar(cut);
    expect(entries.map((e) => e.name)).toEqual(['a.txt']);
    expect(diagnostics.some((d) => d.code === 'TAR_TRUNCATED')).toBe(true);
  });

  it('reports each entry\'s data size and offset into the stream', () => {
    const tar: Uint8Array = writeTar([
      { name: 'blobs/sha256.abc', bytes: text('BLOB') },
      { name: 'component-descriptor.yaml', bytes: 'meta: {}\n' },
    ]);
    const { entries } = readTar(tar);
    for (const entry of entries) {
      expect(entry.size).toBe(entry.bytes.byteLength);
      // The offset must point at exactly the bytes the view exposes.
      expect(tar.subarray(entry.offset, entry.offset + entry.size)).toEqual(entry.bytes);
      expect(entry.offset % 512).toBe(0);
    }
  });

  it('has no total-bytes cap: large payloads keep every entry', () => {
    // Entries are zero-copy views, so "big" costs nothing here; what matters
    // is that a descriptor BEHIND a large blob is never dropped again.
    const tar: Uint8Array = writeTar([
      { name: 'blobs/sha256.big', bytes: new Uint8Array(4 * 1024 * 1024) },
      { name: 'component-descriptor.yaml', bytes: 'meta: {}\n' },
    ]);
    const { entries, diagnostics } = readTar(tar);
    expect(diagnostics).toHaveLength(0);
    expect(entries.map((e) => e.name)).toContain('component-descriptor.yaml');
  });

  it('skips directories and link entries with an info diagnostic', () => {
    const base: Uint8Array = writeTar([{ name: 'kept.txt', bytes: 'K' }]);
    const link = base.slice(0, 512);
    patch(link, 0, 'evil-link\0');
    patch(link, 124, '00000000000\0');
    link[156] = '2'.charCodeAt(0); // symlink
    rechecksum(link);
    const tar = concat(link, base);
    const { entries, diagnostics } = readTar(tar);
    expect(entries.map((e) => e.name)).toEqual(['kept.txt']);
    expect(diagnostics.some((d) => d.code === 'TAR_ENTRY_SKIPPED')).toBe(true);
  });
});

describe('large entry sizes (>8 GiB spellings, exercised with small values)', () => {
  function base256Field(value: number): Uint8Array {
    const field = new Uint8Array(12);
    field[0] = 0x80;
    let v = value;
    for (let i = 11; i >= 1; i--) {
      field[i] = v % 256;
      v = Math.floor(v / 256);
    }
    return field;
  }

  async function bothReaders(tar: Uint8Array) {
    const sync = readTar(tar);
    const streamed = await readTarFrom(bufferSource(tar));
    return { sync, streamed };
  }

  it('reads a GNU base-256 size field (both readers)', async () => {
    const base: Uint8Array = writeTar([{ name: 'big.bin', bytes: 'P'.repeat(2048) }]);
    const header = base.slice(0, 512);
    header.set(base256Field(2048), 124);
    rechecksum(header);
    const tar = concat(header, base.slice(512));
    const { sync, streamed } = await bothReaders(tar);
    for (const result of [sync, streamed]) {
      expect(result.diagnostics).toHaveLength(0);
      expect(result.entries[0]).toMatchObject({ name: 'big.bin', size: 2048 });
    }
  });

  it('honors a PAX size record over a zeroed header field (Go archive/tar style)', async () => {
    // Hand-build: pax 'x' header (size record) → entry header claiming size 0
    // → 2048 bytes of data → a normal trailing entry proving the offset math.
    const template: Uint8Array = writeTar([{ name: 'big.bin', bytes: 'Q'.repeat(2048) }]);
    const paxHeader = template.slice(0, 512);
    patch(paxHeader, 0, 'pax-meta\0');
    patch(paxHeader, 124, (13).toString(8).padStart(11, '0') + '\0');
    paxHeader[156] = 'x'.charCodeAt(0);
    rechecksum(paxHeader);
    const paxData = new Uint8Array(512);
    paxData.set(text('13 size=2048\n'));

    const fileHeader = template.slice(0, 512);
    patch(fileHeader, 124, '00000000000\0'); // zeroed — PAX must override
    rechecksum(fileHeader);

    const after: Uint8Array = writeTar([{ name: 'after.txt', bytes: 'ok' }]);
    const tar = concat(paxHeader, paxData, fileHeader, template.slice(512, 512 + 2048), after);
    const { sync, streamed } = await bothReaders(tar);
    for (const result of [sync, streamed]) {
      expect(result.entries.map((e) => e.name)).toEqual(['big.bin', 'after.txt']);
      expect(result.entries[0]!.size).toBe(2048);
    }
    expect(new TextDecoder().decode(sync.entries[0]!.bytes)).toBe('Q'.repeat(2048));
  });

  it('drops entries whose size exceeds what a JS number can address', async () => {
    const base: Uint8Array = writeTar([{ name: 'huge.bin', bytes: 'x' }]);
    const header = base.slice(0, 512);
    const field = new Uint8Array(12).fill(0xff);
    field[0] = 0x80 | 0x7f;
    header.set(field, 124);
    rechecksum(header);
    const tar = concat(header, base.slice(512));
    const { sync, streamed } = await bothReaders(tar);
    for (const result of [sync, streamed]) {
      expect(result.entries).toHaveLength(0);
      expect(result.diagnostics.some((d) => d.code === 'TAR_SIZE_UNSUPPORTED')).toBe(true);
    }
  });
});

describe('sniffContainer + gunzip', () => {
  it('classifies gzip, tar, zip, binary, and text', async () => {
    const tar: Uint8Array = writeTar([{ name: 'x', bytes: 'y' }]);
    expect(sniffContainer(tar)).toBe('tar');
    const gz = await compress(tar);
    expect(sniffContainer(gz)).toBe('gzip');
    expect(sniffContainer(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0]))).toBe('zip');
    expect(sniffContainer(new Uint8Array([0x00, 0x01, 0x02]))).toBe('binary');
    expect(sniffContainer(text('SPDXVersion: SPDX-2.3'))).toBe('text');
    expect(sniffContainer(text('short'))).toBe('text');
  });

  it('gunzips back to the original bytes', async () => {
    const tar: Uint8Array = writeTar([{ name: 'x', bytes: 'roundtrip' }]);
    const back = await gunzip(await compress(tar));
    expect(back).toEqual(tar);
    expect(readTar(back).entries[0]!.name).toBe('x');
  });

  it('caps decompression output: a bomb throws instead of eating RAM', async () => {
    // 1 MB of zeros compresses to ~1 KB; a 1000-byte ceiling must trip.
    const bomb = await compress(new Uint8Array(1024 * 1024));
    await expect(gunzip(bomb, 1000)).rejects.toBeInstanceOf(GunzipLimitError);
    // The same stream passes with an adequate ceiling.
    expect((await gunzip(bomb)).byteLength).toBe(1024 * 1024);
  });
});

async function compress(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function patch(block: Uint8Array, offset: number, value: string): void {
  const bytes = text(value);
  block.fill(0, offset, offset + Math.max(bytes.length, 1));
  block.set(bytes, offset);
}

function rechecksum(block: Uint8Array): void {
  block.fill(0x20, 148, 156);
  let sum = 0;
  for (const byte of block) sum += byte;
  block.set(text(sum.toString(8).padStart(6, '0') + '\0 '), 148);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
