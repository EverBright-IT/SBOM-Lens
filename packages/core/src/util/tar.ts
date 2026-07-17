import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import type { ByteSource } from './bytesource';
import { chunkedSource } from './bytesource';

/**
 * Hand-rolled USTAR reader — enough for OCM deliveries (the ocm CLI uses
 * Go's archive/tar, which emits POSIX ustar with PAX extensions for long
 * names) without a dependency. Entry names are opaque keys, never
 * filesystem paths; links are skipped and never followed.
 */

export interface TarEntry {
  name: string;
  /** Entry data size in bytes, from the header. */
  size: number;
  /** Byte offset of the entry's data within the tar stream. */
  offset: number;
  /** Zero-copy view into the input buffer — copy before transferring. */
  bytes: Uint8Array;
}

export interface TarResult {
  entries: TarEntry[];
  diagnostics: Diagnostic[];
}

const BLOCK = 512;
// Entry-count bomb guard only. There is deliberately NO total-bytes cap:
// entries are zero-copy views into a buffer that already exists, so a cap
// here cannot save memory — it can only drop entries, and in a multi-
// component CTF the dropped tail is where the descriptors live. The real
// decompression bomb guard sits in gunzip (util/binary.ts), where new bytes
// actually materialize.
const MAX_ENTRIES = 10_000;

export function readTar(bytes: Uint8Array): TarResult {
  const entries: TarEntry[] = [];
  const diagnostics: Diagnostic[] = [];
  const skippedTypes = new Map<string, number>();

  let offset = 0;
  let pendingLongName: string | null = null;
  let pendingPaxPath: string | null = null;

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
        diag('warning', 'TAR_BAD_CHECKSUM', `Header checksum mismatch at offset ${offset}: stopped reading.`),
      );
      break;
    }

    const size = parseOctal(header.subarray(124, 136));
    if (size === null) {
      diagnostics.push(
        diag('warning', 'TAR_SIZE_UNSUPPORTED', 'Entry with non-octal (base-256) size skipped: files >8 GiB are unsupported.'),
      );
      break; // cannot know where the next header starts
    }
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > bytes.length) {
      diagnostics.push(diag('warning', 'TAR_TRUNCATED', 'Archive ends mid-entry: remaining entries dropped.'));
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
      if (entries.length >= MAX_ENTRIES) {
        diagnostics.push(
          diag('warning', 'ARCHIVE_LIMIT_EXCEEDED', `Archive exceeds ${MAX_ENTRIES} entries: remaining entries dropped.`),
        );
        break;
      }
      entries.push({ name, size, offset: dataStart, bytes: data });
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

export interface TarStreamEntry {
  name: string;
  size: number;
  /** Byte offset of the entry's data within the source. */
  offset: number;
  /** Materialized bytes; null when the entry exceeded the materialization caps. */
  bytes: Uint8Array | null;
}

export interface TarStreamResult {
  entries: TarStreamEntry[];
  diagnostics: Diagnostic[];
}

export interface TarStreamOptions {
  /** Entries larger than this are indexed (name/size/offset) but not loaded. */
  materializeEntryMax?: number;
  /** Total materialized budget; past it, further entries are index-only. */
  materializeTotalMax?: number;
}

export const MATERIALIZE_ENTRY_MAX = 64 * 1024 * 1024;
export const MATERIALIZE_TOTAL_MAX = 512 * 1024 * 1024;
// GNU longname / PAX headers hold a file NAME (kilobytes at most), but their
// size field is attacker-controlled like any other. Without a cap a hostile
// archive could make the walker materialize gigabytes for a "name".
const META_HEADER_MAX = 1024 * 1024;

/**
 * The streaming twin of readTar: walks a tar through a ByteSource without
 * ever holding the archive as one buffer. Headers ride a read-ahead window;
 * entry data is materialized straight from the source ONLY while it fits
 * the caps — everything else stays an index entry whose offset a caller can
 * hash or fetch selectively later. This is what makes a multi-GB delivery
 * openable: its structure is tiny, its blobs are not.
 */
export async function readTarFrom(source: ByteSource, options?: TarStreamOptions): Promise<TarStreamResult> {
  const entryMax = options?.materializeEntryMax ?? MATERIALIZE_ENTRY_MAX;
  const totalMax = options?.materializeTotalMax ?? MATERIALIZE_TOTAL_MAX;
  const headers = chunkedSource(source);

  const entries: TarStreamEntry[] = [];
  const diagnostics: Diagnostic[] = [];
  const skippedTypes = new Map<string, number>();

  let offset = 0;
  let pendingLongName: string | null = null;
  let pendingPaxPath: string | null = null;
  let materializedTotal = 0;
  let unmaterialized = 0;

  while (offset + BLOCK <= source.size) {
    const header = await headers.read(offset, BLOCK);
    if (header.byteLength < BLOCK || isZeroBlock(header)) break;

    if (!verifyChecksum(header)) {
      if (entries.length === 0 && offset === 0) {
        diagnostics.push(diag('error', 'TAR_CORRUPT', 'Not a valid tar archive (header checksum failed).'));
        return { entries: [], diagnostics };
      }
      diagnostics.push(
        diag('warning', 'TAR_BAD_CHECKSUM', `Header checksum mismatch at offset ${offset}: stopped reading.`),
      );
      break;
    }

    const size = parseOctal(header.subarray(124, 136));
    if (size === null) {
      diagnostics.push(
        diag('warning', 'TAR_SIZE_UNSUPPORTED', 'Entry with non-octal (base-256) size skipped: files >8 GiB are unsupported.'),
      );
      break;
    }
    const dataStart = offset + BLOCK;
    if (dataStart + size > source.size) {
      diagnostics.push(diag('warning', 'TAR_TRUNCATED', 'Archive ends mid-entry: remaining entries dropped.'));
      break;
    }

    const typeflag = String.fromCharCode(header[156]!);

    if (typeflag === 'L') {
      if (size > META_HEADER_MAX) {
        countSkip(skippedTypes, 'oversized-longname');
      } else {
        pendingLongName = decodeString(await source.read(dataStart, size)).replace(/\0+$/, '');
      }
    } else if (typeflag === 'x') {
      if (size > META_HEADER_MAX) {
        countSkip(skippedTypes, 'oversized-pax');
      } else {
        const path = parsePaxPath(await source.read(dataStart, size));
        if (path !== null) pendingPaxPath = path;
      }
    } else if (typeflag === 'g') {
      countSkip(skippedTypes, 'pax-global');
    } else if (typeflag === '5') {
      // directory — nothing to keep
    } else if (typeflag === '0' || typeflag === '\0') {
      const name = pendingPaxPath ?? pendingLongName ?? headerName(header);
      pendingLongName = null;
      pendingPaxPath = null;
      if (entries.length >= MAX_ENTRIES) {
        diagnostics.push(
          diag('warning', 'ARCHIVE_LIMIT_EXCEEDED', `Archive exceeds ${MAX_ENTRIES} entries: remaining entries dropped.`),
        );
        break;
      }
      const materialize = size <= entryMax && materializedTotal + size <= totalMax;
      if (materialize) {
        entries.push({ name, size, offset: dataStart, bytes: await source.read(dataStart, size) });
        materializedTotal += size;
      } else {
        entries.push({ name, size, offset: dataStart, bytes: null });
        unmaterialized++;
      }
    } else {
      countSkip(skippedTypes, `type-${typeflag}`);
      pendingLongName = null;
      pendingPaxPath = null;
    }

    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;
  }

  if (unmaterialized > 0) {
    diagnostics.push(
      diag(
        'info',
        'ARCHIVE_BLOBS_INDEXED',
        `${unmaterialized} large entr${unmaterialized === 1 ? 'y was' : 'ies were'} indexed without loading the content (per-entry cap ${Math.round(entryMax / (1024 * 1024))} MB).`,
      ),
    );
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
