import { beforeEach, describe, expect, it, vi } from 'vitest';
import { openHostPush } from './ingest';
import { useAppStore } from './store';

/**
 * Host pushes with files VS Code could not hand over (a large file whose
 * webview-resource fetch failed): the app names the file and the reason
 * instead of parsing an empty file into a misleading error.
 */

const { requests, fakeWorker } = vi.hoisted(() => {
  const requests: Array<{ kind: string; id: number; fileName?: string; files?: Array<{ fileName: string }> }> = [];
  const fakeWorker = {
    onmessage: null as ((event: MessageEvent) => void) | null,
    postMessage(message: (typeof requests)[number]) {
      requests.push(message);
      queueMicrotask(() =>
        fakeWorker.onmessage?.({
          data: {
            kind: 'bundle',
            id: message.id,
            bundle: { roots: [], componentVersions: [] },
            extracted: [],
            diagnostics: [{ severity: 'info', code: 'FROM_WORKER', message: 'walked' }],
          },
        } as MessageEvent),
      );
    },
    terminate() {},
  };
  return { requests, fakeWorker };
});

vi.mock('../host', () => ({ host: { createWorker: () => fakeWorker } }));

beforeEach(() => {
  requests.length = 0;
  useAppStore.setState({ delivery: null, loading: null, loadError: null });
});

describe('openHostPush with files the host could not read', () => {
  it('reports the file and the reason instead of opening an empty file', async () => {
    await openHostPush([{ fileName: 'gone.ctf', error: 'HTTP 404' }]);
    const { loadError, delivery } = useAppStore.getState();
    expect(delivery).toBeNull();
    expect(loadError?.fileName).toBe('gone.ctf');
    expect(loadError?.diagnostics.map((d) => d.code)).toEqual(['HOST_FILE_UNREADABLE']);
    expect(loadError?.diagnostics[0]!.message).toContain('gone.ctf');
    expect(loadError?.diagnostics[0]!.message).toContain('HTTP 404');
    expect(requests).toHaveLength(0);
  });

  it('opens the readable file and keeps the unreadable one as a finding', async () => {
    await openHostPush([
      { fileName: 'big.ctf', blob: new Blob([new Uint8Array(4)]) },
      { fileName: 'gone.ctf', error: 'Failed to fetch' },
    ]);
    expect(requests.map((r) => [r.kind, r.fileName])).toEqual([['bundle', 'big.ctf']]);
    const { delivery, loadError } = useAppStore.getState();
    expect(loadError).toBeNull();
    expect(delivery?.diagnostics.map((d) => d.code)).toEqual(['HOST_FILE_UNREADABLE', 'FROM_WORKER']);
  });

  it('sends only readable files to a multi-file job', async () => {
    await openHostPush([
      { fileName: 'a/component-descriptor.yaml', blob: new Blob(['a']) },
      { fileName: 'b/component-descriptor.yaml', blob: new Blob(['b']) },
      { fileName: 'c.ctf', error: 'HTTP 403' },
    ]);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.kind).toBe('open-many');
    expect(requests[0]!.files!.map((f) => f.fileName)).toEqual([
      'a/component-descriptor.yaml',
      'b/component-descriptor.yaml',
    ]);
    expect(useAppStore.getState().delivery?.diagnostics.map((d) => d.code)).toContain('HOST_FILE_UNREADABLE');
  });
});
