import { parse as parseYaml } from 'yaml';
import {
  parseDocument,
  readOcmDelivery,
  registerYamlParser,
  sha1Hex,
  sniffContainer,
} from '@sbomlens/core';
import type { ParseJobRequest, ParseJobResponse } from './protocol';

// YAML lives in the worker chunk only; the main bundle stays lean.
registerYamlParser(parseYaml);

/**
 * Thin shell: hashing, parsing, and archive expansion happen here so the UI
 * thread never blocks. All logic lives in core and is tested synchronously.
 * Binary sniffing runs BEFORE TextDecoder — decoding an archive as text
 * would destroy it.
 */
const scope = self as unknown as {
  onmessage: ((event: MessageEvent) => void) | null;
  postMessage: (message: ParseJobResponse, transfer?: Transferable[]) => void;
};

scope.onmessage = async (event: MessageEvent) => {
  const { id, fileName, buffer } = event.data as ParseJobRequest;
  try {
    const bytes = new Uint8Array(buffer);
    const container = sniffContainer(bytes);

    if (container === 'gzip' || container === 'tar') {
      const delivery = await readOcmDelivery(fileName, bytes);
      const extracted = delivery.extracted.map((entry) => ({
        fileName: entry.fileName,
        // Copy out of the archive buffer so each entry transfers cleanly.
        buffer: new Uint8Array(entry.bytes).buffer as ArrayBuffer,
      }));
      scope.postMessage(
        {
          id,
          ok: true,
          kind: 'expanded',
          fileName,
          documents: delivery.documents,
          extracted,
          diagnostics: delivery.diagnostics,
        },
        extracted.map((e) => e.buffer),
      );
      return;
    }

    if (container === 'zip' || container === 'binary') {
      const reason =
        container === 'zip'
          ? 'ZIP archives are not supported — repack the delivery as .tar or .tar.gz.'
          : 'Unrecognized binary file — expected SPDX text, an OCM component descriptor, or a tar/tar.gz delivery.';
      scope.postMessage({
        id,
        ok: true,
        kind: 'document',
        fileName,
        sha1: await sha1Hex(buffer),
        byteSize: buffer.byteLength,
        text: '',
        document: null,
        diagnostics: [
          {
            severity: 'error',
            code: container === 'zip' ? 'ARCHIVE_ZIP_NOT_SUPPORTED' : 'UNRECOGNIZED_BINARY',
            message: reason,
          },
        ],
      });
      return;
    }

    const sha1 = await sha1Hex(buffer);
    const text = new TextDecoder().decode(buffer);
    const { document, diagnostics } = parseDocument({
      fileName,
      text,
      sha1,
      byteSize: buffer.byteLength,
    });
    scope.postMessage({
      id,
      ok: true,
      kind: 'document',
      fileName,
      sha1,
      byteSize: buffer.byteLength,
      text,
      document,
      diagnostics,
    });
  } catch (error) {
    scope.postMessage({ id, ok: false, fileName, error: String(error) });
  }
};
