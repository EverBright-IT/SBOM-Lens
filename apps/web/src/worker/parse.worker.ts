import { parse as parseYaml } from 'yaml';
import type { ContainerKind } from '@sbomlens/core';
import { parseDocument, registerYamlParser, sha1Hex, sniffContainer } from '@sbomlens/core';
import type { DeliveryResult } from '@sbomlens/core/ocm';
import {
  blobSource,
  parseOcmComponentDescriptor,
  readOcmDelivery,
  readOcmDeliveryFrom,
  registerOcmParser,
} from '@sbomlens/core/ocm';
import { HAS_DELIVERIES } from '../app/brand';
import type { ParseJobRequest, ParseJobResponse } from './protocol';

// YAML lives in the worker chunk only; the main bundle stays lean.
registerYamlParser(parseYaml);

// Deliveries are an OCM Lens capability. HAS_DELIVERIES is a build-time
// constant, so the SPDX-only build drops this registration and every
// readOcmDelivery call below — the OCM code never reaches its bundle.
if (HAS_DELIVERIES) registerOcmParser(parseOcmComponentDescriptor);

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

/**
 * Bytes that will never become a document, with wording the product can back
 * up: a viewer without delivery support has no business explaining tar
 * layouts. gzip/tar only reach this when deliveries are off — otherwise the
 * expansion branch above already claimed them.
 */
function rejectBinary(container: ContainerKind): { code: string; message: string } | null {
  if (container === 'zip') {
    return {
      code: 'ARCHIVE_ZIP_NOT_SUPPORTED',
      message: HAS_DELIVERIES
        ? 'ZIP archives are not supported: repack the delivery as .tar or .tar.gz.'
        : 'ZIP archives are not supported: unpack it and drop the documents in.',
    };
  }
  if (!HAS_DELIVERIES && (container === 'gzip' || container === 'tar')) {
    return {
      code: 'ARCHIVE_NOT_SUPPORTED',
      message: 'Archives are not supported: unpack it and drop the documents in.',
    };
  }
  if (container === 'binary') {
    return {
      code: 'UNRECOGNIZED_BINARY',
      message: HAS_DELIVERIES
        ? 'Unrecognized binary file: expected a component descriptor, a tar/tar.gz delivery, or SPDX text.'
        : 'Unrecognized binary file: expected an SPDX document as text, JSON, or YAML.',
    };
  }
  return null;
}

function postExpanded(id: number, fileName: string, delivery: DeliveryResult): void {
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
}

scope.onmessage = async (event: MessageEvent) => {
  const { id, fileName, buffer, blob } = event.data as ParseJobRequest;
  try {
    // Blob payload: a delivery-sized file handle. Sniff the head, then walk
    // the archive through the disk-backed Blob without buffering it whole.
    // Anything that is not an archive falls through to the buffer path.
    if (blob !== undefined) {
      const head = new Uint8Array(await blob.slice(0, 512).arrayBuffer());
      const headKind = sniffContainer(head);
      if (HAS_DELIVERIES && (headKind === 'gzip' || headKind === 'tar')) {
        postExpanded(id, fileName, await readOcmDeliveryFrom(fileName, blobSource(blob)));
        return;
      }
      return handleBuffer(id, fileName, await blob.arrayBuffer());
    }
    return handleBuffer(id, fileName, buffer!);
  } catch (error) {
    scope.postMessage({ id, ok: false, fileName, error: String(error) });
  }
};

async function handleBuffer(id: number, fileName: string, buffer: ArrayBuffer): Promise<void> {
  try {
    const bytes = new Uint8Array(buffer);
    const container = sniffContainer(bytes);

    if (HAS_DELIVERIES && (container === 'gzip' || container === 'tar')) {
      postExpanded(id, fileName, await readOcmDelivery(fileName, bytes));
      return;
    }

    const rejection = rejectBinary(container);
    if (rejection) {
      scope.postMessage({
        id,
        ok: true,
        kind: 'document',
        fileName,
        sha1: await sha1Hex(buffer),
        byteSize: buffer.byteLength,
        text: '',
        document: null,
        diagnostics: [{ severity: 'error', ...rejection }],
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
}
