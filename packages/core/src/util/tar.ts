import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';

/**
 * Hand-rolled USTAR reader — enough for OCM deliveries (the ocm CLI uses
 * Go's archive/tar, which emits POSIX ustar with PAX extensions for long
 * names) without a dependency. Entry names are opaque keys, never
 * filesystem paths; links are skipped and never followed.
 */

export interface TarEntry {
  name: string;
  /** Zero-copy view into the input buffer — copy before transferring. */
  bytes: Uint8Array;
}

export interface TarResult {
  entries: TarEntry[];
  diagnostics: Diagnostic[];
}

const BLOCK = 512;
const MAX_ENTRIES = 10_000;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

export function readTar(bytes: Uint8Array): TarResult {
  const entries: TarEntry[] = [];
  const diagnostics: Diagnostic[] = [];
  const skippedTypes = new Map<string, number>();

  let offset = 0;
  let pendingLongName: string | null = null;
  let pendingPaxPath: string | null = null;
  let totalBytes = 0;

  while (offset + BLOCK <= bytes.length) {
    const header = bytes.subarray(offset, offset + BLOCK);
    if (isZeroBlock(header)) break; // end-of-archive marker

    if (!verifyChecksum(header)) {
      // A bad checksum on the very first header means "not actually a tar".
      if (entries.length === 0 && offset === 0) {
        diagnostics.push(diag('error', 'TAR_CORRUPT', 'Not a valid tar archive (header checksum failed).'));
        return { entries: [], diagnostics };
      }
      diagnostics.push(
        diag('warning', 'TAR_BAD_CHECKSUM', `Header checksum mismatch at offset ${offset} — stopped reading.`),
      );
      break;
    }

    const size = parseOctal(header.subarray(124, 136));
    if (size === null) {
      diagnostics.push(
        diag('warning', 'TAR_SIZE_UNSUPPORTED', 'Entry with non-octal (base-256) size skipped — files >8 GiB are unsupported.'),
      );
      break; // cannot know where the next header starts
    }
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) {
      diagnostics.push(diag('warning', 'TAR_TRUNCATED', 'Archive ends mid-entry — remaining entries dropped.'));
      break;
    }

    const typeflag = String.fromCharCode(header[156]!);
    const data = bytes.subarray(dataStart, dataEnd);

    if (typeflag === 'L') {
      // GNU longname: data block holds the next entry's name.
      pendingLongName = decodeString(data).replace(/\0+$/, '');
    } else if (typeflag === 'x') {
      const path = parsePaxPath(data);
      if (path !== null) pendingPaxPath = path;
    } else if (typeflag === 'g') {
      countSkip(skippedTypes, 'pax-global');
    } else if (typeflag === '5') {
      // directory — nothing to keep
    } else if (typeflag === '0' || typeflag === '\0') {
      const name = pendingPaxPath ?? pendingLongName ?? headerName(header);
      pendingLongName = null;
      pendingPaxPath = null;
      totalBytes += size;
      if (entries.length >= MAX_ENTRIES || totalBytes > MAX_TOTAL_BYTES) {
        diagnostics.push(
          diag('warning', 'ARCHIVE_LIMIT_EXCEEDED', `Archive exceeds ${MAX_ENTRIES} entries or ${MAX_TOTAL_BYTES / (1024 * 1024)} MB — remaining entries dropped.`),
        );
        break;
      }
      entries.push({ name, bytes: data });
    } else {
      // links, sparse, fifos, … — never followed
      countSkip(skippedTypes, `type-${typeflag}`);
      pendingLongName = null;
      pendingPaxPath = null;
    }

    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
  }

  for (const [kind, count] of skippedTypes) {
    diagnostics.push(diag('info', 'TAR_ENTRY_SKIPPED', `${count} ${kind} entr${count === 1 ? 'y' : 'ies'} skipped.`));
  }
  return { entries, diagnostics };
}

function headerName(header: Uint8Array): string {
  const name = decodeString(header.subarray(0, 100)).replace(/\0.*$/, '');
  const prefix = decodeString(header.subarray(345, 500)).replace(/\0.*$/, '');
  return prefix ? `${prefix}/${name}` : name;
}

function parseOctal(field: Uint8Array): number | null {
  if ((field[0]! & 0x80) !== 0) return null; // GNU base-256
  const text = decodeString(field).replace(/\0.*$/, '').trim();
  if (text === '') return 0;
  const value = Number.parseInt(text, 8);
  return Number.isFinite(value) ? value : null;
}

function verifyChecksum(header: Uint8Array): boolean {
  const stored = parseOctal(header.subarray(148, 156));
  if (stored === null) return false;
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) {
    sum += i >= 148 && i < 156 ? 0x20 : header[i]!;
  }
  return sum === stored;
}

function isZeroBlock(block: Uint8Array): boolean {
  for (const byte of block) if (byte !== 0) return false;
  return true;
}

/** PAX records: "<len> key=value\n" — we only care about `path`. */
function parsePaxPath(data: Uint8Array): string | null {
  const text = decodeString(data);
  let index = 0;
  while (index < text.length) {
    const space = text.indexOf(' ', index);
    if (space === -1) break;
    const length = Number.parseInt(text.slice(index, space), 10);
    if (!Number.isFinite(length) || length <= 0) break;
    const record = text.slice(space + 1, index + length - 1); // strip trailing \n
    if (record.startsWith('path=')) return record.slice(5);
    index += length;
  }
  return null;
}

function decodeString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function countSkip(map: Map<string, number>, kind: string): void {
  map.set(kind, (map.get(kind) ?? 0) + 1);
}
