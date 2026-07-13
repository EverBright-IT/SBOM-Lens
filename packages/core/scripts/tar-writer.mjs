/**
 * Deterministic ustar writer for fixtures and tests: entries are sorted,
 * mtime/uid/gid are zero, modes fixed — the same input always produces the
 * same bytes (committed fixtures are diffed on regeneration). Long names
 * (>100 chars) get a PAX header, matching what Go's archive/tar (the ocm
 * CLI) emits.
 */

const BLOCK = 512;
const encoder = new TextEncoder();

/** @param {Array<{name: string, bytes: Uint8Array | string}>} entries */
export function writeTar(entries) {
  const blocks = [];
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : 1));
  for (const entry of sorted) {
    const bytes = typeof entry.bytes === 'string' ? encoder.encode(entry.bytes) : entry.bytes;
    if (encoder.encode(entry.name).length > 100) {
      const record = paxRecord('path', entry.name);
      blocks.push(header('PaxHeaders.0/x', record.length, 'x'), padded(record));
    }
    const headerName = encoder.encode(entry.name).length > 100 ? entry.name.slice(0, 100) : entry.name;
    blocks.push(header(headerName, bytes.length, '0'), padded(bytes));
  }
  blocks.push(new Uint8Array(BLOCK), new Uint8Array(BLOCK));
  const total = blocks.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const block of blocks) {
    out.set(block, offset);
    offset += block.length;
  }
  return out;
}

function paxRecord(key, value) {
  // "<len> key=value\n" where len covers the whole record including itself.
  const body = ` ${key}=${value}\n`;
  let length = body.length + 1;
  while (String(length).length + body.length !== length) {
    length = String(length).length + body.length;
  }
  return encoder.encode(`${length}${body}`);
}

function header(name, size, typeflag) {
  const block = new Uint8Array(BLOCK);
  writeString(block, 0, 100, name);
  writeString(block, 100, 8, '0000644\0'); // mode
  writeString(block, 108, 8, '0000000\0'); // uid
  writeString(block, 116, 8, '0000000\0'); // gid
  writeString(block, 124, 12, size.toString(8).padStart(11, '0') + '\0');
  writeString(block, 136, 12, '00000000000\0'); // mtime 0
  writeString(block, 148, 8, '        '); // checksum placeholder (spaces)
  block[156] = typeflag.charCodeAt(0);
  writeString(block, 257, 6, 'ustar\0');
  writeString(block, 263, 2, '00'); // version
  let sum = 0;
  for (const byte of block) sum += byte;
  writeString(block, 148, 8, sum.toString(8).padStart(6, '0') + '\0 ');
  return block;
}

function padded(bytes) {
  const size = Math.ceil(bytes.length / BLOCK) * BLOCK;
  const out = new Uint8Array(size);
  out.set(bytes);
  return out;
}

function writeString(block, offset, length, text) {
  const bytes = encoder.encode(text).subarray(0, length);
  block.set(bytes, offset);
}
