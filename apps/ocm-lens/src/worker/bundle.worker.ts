import { parse as parseYaml } from 'yaml';
import { registerYamlParser, sniffContainer } from '@sbomlens/core';
import {
  blobSource,
  bundleFromDescriptor,
  digestDeliveryBlob,
  extractDeliveryBlob,
  readOcmBundle,
  readOcmBundleFrom,
} from '@sbomlens/core/ocm';
import type { DigestCheckResult, WorkerRequest, WorkerResponse } from './protocol';

// YAML lives in the worker chunk only; the main bundle stays lean.
registerYamlParser(parseYaml);

/**
 * Thin shell: container sniffing, the delivery walk, and on-demand blob
 * extraction happen here so the UI thread never blocks. All logic lives in
 * core and is tested synchronously. Sniffing runs BEFORE any TextDecoder —
 * decoding an archive as text would destroy it.
 */
const scope = self as unknown as {
  onmessage: ((event: MessageEvent) => void) | null;
  postMessage: (message: WorkerResponse, transfer?: Transferable[]) => void;
};

scope.onmessage = (event: MessageEvent) => {
  void handle(event.data as WorkerRequest);
};

async function handle(job: WorkerRequest): Promise<void> {
  try {
    if (job.kind === 'extract') {
      const source = job.blob ? blobSource(job.blob) : bufferAsSource(job.buffer);
      const result = await extractDeliveryBlob(source, job.localReference);
      if (result.ok) {
        scope.postMessage({ kind: 'extract', id: job.id, bytes: result.bytes }, [
          result.bytes.buffer as ArrayBuffer,
        ]);
      } else {
        scope.postMessage({ kind: 'extract', id: job.id, bytes: null, reason: result.reason });
      }
      return;
    }

    if (job.kind === 'digests') {
      const source = job.blob ? blobSource(job.blob) : bufferAsSource(job.buffer);
      const results: DigestCheckResult[] = [];
      let done = 0;
      for (const check of job.checks) {
        const computed =
          (await digestDeliveryBlob(source, check.localReference, check.declared)) ?? 'unchecked';
        // The on-demand path never re-defers; map the type's 'pending' away.
        const verdict = computed === 'pending' ? 'unchecked' : computed;
        results.push({ cvId: check.cvId, role: check.role, index: check.index, verdict });
        done++;
        scope.postMessage({ kind: 'digests-progress', id: job.id, done, total: job.checks.length });
      }
      scope.postMessage({ kind: 'digests', id: job.id, results });
      return;
    }

    if (job.blob) {
      const head = new Uint8Array(await job.blob.slice(0, 512).arrayBuffer());
      const kind = sniffContainer(head);
      if (kind === 'tar' || kind === 'gzip') {
        // Disk-backed streaming: the delivery is read through slice().
        respondBundle(job.id, await readOcmBundleFrom(job.fileName, blobSource(job.blob), job.options));
      } else {
        respondBundle(
          job.id,
          await bundleFromDescriptor(job.fileName, new TextDecoder().decode(await job.blob.arrayBuffer())),
        );
      }
      return;
    }
    const bytes = new Uint8Array(job.buffer ?? new ArrayBuffer(0));
    const kind = sniffContainer(bytes);
    respondBundle(
      job.id,
      kind === 'tar' || kind === 'gzip'
        ? await readOcmBundle(job.fileName, bytes, job.options)
        : await bundleFromDescriptor(job.fileName, new TextDecoder().decode(bytes)),
    );
  } catch (error) {
    if (job.kind === 'extract') {
      scope.postMessage({ kind: 'extract', id: job.id, bytes: null, reason: String(error) });
    } else {
      respondBundle(job.id, {
        bundle: null,
        extracted: [],
        diagnostics: [
          { severity: 'error', code: 'BUNDLE_READ_FAILED', message: `Could not read this delivery: ${String(error)}` },
        ],
      });
    }
  }
}

function bufferAsSource(buffer: ArrayBuffer | undefined) {
  const bytes = new Uint8Array(buffer ?? new ArrayBuffer(0));
  return blobSource(new Blob([bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer]));
}

function respondBundle(
  id: number,
  result: {
    bundle: Extract<WorkerResponse, { kind: 'bundle' }>['bundle'];
    extracted: Extract<WorkerResponse, { kind: 'bundle' }>['extracted'];
    diagnostics: Extract<WorkerResponse, { kind: 'bundle' }>['diagnostics'];
  },
): void {
  scope.postMessage({ kind: 'bundle', id, ...result });
}
