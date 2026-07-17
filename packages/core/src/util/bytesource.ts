/**
 * Random-access byte source: the seam that lets the delivery walker read a
 * multi-GB archive without ever holding it as one buffer. A plain in-memory
 * buffer, a browser File/Blob (disk-backed, sliceable), and a window into
 * another source all satisfy it. Reads past the end return the available
 * prefix; callers check lengths, not exceptions.
 */
export interface ByteSource {
  readonly size: number;
  read(offset: number, length: number): Promise<Uint8Array>;
}

/** Zero-copy views over an existing buffer. */
export function bufferSource(bytes: Uint8Array): ByteSource {
  return {
    size: bytes.byteLength,
    read: (offset, length) =>
      Promise.resolve(bytes.subarray(Math.min(offset, bytes.byteLength), Math.min(offset + length, bytes.byteLength))),
  };
}

/**
 * A browser/Node Blob or File. Blob storage is disk-backed in browsers, so
 * slicing never pulls the whole file into memory.
 */
export function blobSource(blob: Blob): ByteSource {
  return {
    size: blob.size,
    read: async (offset, length) => {
      const end = Math.min(offset + length, blob.size);
      if (offset >= end) return new Uint8Array(0);
      return new Uint8Array(await blob.slice(offset, end).arrayBuffer());
    },
  };
}

/** A sub-range of another source (a nested archive inside a plain tar). */
export function windowSource(source: ByteSource, base: number, size: number): ByteSource {
  return {
    size,
    read: (offset, length) => {
      const clamped = Math.min(length, Math.max(0, size - offset));
      if (clamped <= 0) return Promise.resolve(new Uint8Array(0));
      return source.read(base + offset, clamped);
    },
  };
}

const CHUNK = 4 * 1024 * 1024;

/**
 * Read-ahead wrapper: tar walking issues thousands of tiny header reads, and
 * a File-backed source pays real IO latency per read. One 4 MB window turns
 * sequential 512-byte reads into ~one IO per 4 MB. Only forward-moving reads
 * benefit; anything outside the window falls through to the source.
 */
export function chunkedSource(source: ByteSource): ByteSource {
  let windowStart = -1;
  let window: Uint8Array = new Uint8Array(0);
  return {
    size: source.size,
    read: async (offset, length) => {
      if (length > CHUNK) return source.read(offset, length);
      const inWindow =
        windowStart >= 0 &&
        offset >= windowStart &&
        // Served from the window when it holds the full request, or when it
        // already reaches EOF (reloading could not produce more bytes).
        (offset + length <= windowStart + window.byteLength || windowStart + window.byteLength >= source.size);
      if (!inWindow) {
        windowStart = offset;
        window = await source.read(offset, CHUNK);
      }
      const start = offset - windowStart;
      return window.subarray(start, Math.min(start + length, window.byteLength));
    },
  };
}
