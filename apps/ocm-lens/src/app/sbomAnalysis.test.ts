import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { OcmBundle } from '@sbomlens/core/ocm';
import { loadSbomPackages, openBlob, runSbomAnalysis } from './ingest';
import { prepareAcceptanceReport } from './report';
import { useAppStore } from './store';

/**
 * The SBOM analysis runs after the delivery is open, as its own worker job:
 * the dashboard never waits for SBOM parsing, the budget decides what is
 * analysed at once, results only land in the delivery they were started
 * for, and a worker that dies does not leave the app waiting.
 */

interface Message {
  kind: string;
  id: number;
  options?: Record<string, unknown>;
  items?: { sha1: string; fileName: string; bytes: Uint8Array }[];
}

interface FakeWorker {
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(message: Message): void;
  terminate(): void;
}

const harness = vi.hoisted(() => {
  const h = {
    requests: [] as Message[],
    created: 0,
    /** What the fake worker does with a request; tests replace it. */
    handle: (() => {}) as (message: Message, worker: FakeWorker) => void,
    makeWorker(): FakeWorker {
      const worker: FakeWorker = {
        onmessage: null,
        onerror: null,
        postMessage(message) {
          h.requests.push(message);
          queueMicrotask(() => h.handle(message, worker));
        },
        terminate() {},
      };
      h.created++;
      return worker;
    },
  };
  return h;
});

vi.mock('../host', () => ({ host: { createWorker: () => harness.makeWorker() } }));

/** A delivery with one SBOM resource per entry; sizes are the SBOM byte lengths. */
function delivery(sboms: { sha1: string; size: number }[]) {
  const bundle = {
    fileName: 'd.ctf.tar',
    layout: 'ctf',
    compressed: false,
    archiveSize: 4,
    completeness: {
      transported: sboms.length,
      external: 0,
      broken: 0,
      unknown: 0,
      none: 0,
      unresolvedRefs: 0,
      airGapReady: true,
    },
    roots: [],
    shared: [],
    issues: [],
    componentVersions: [
      {
        id: 'example.org/app@1.0.0',
        name: 'example.org/app',
        version: '1.0.0',
        references: [],
        sources: [],
        diagnostics: [],
        resources: sboms.map((s, i) => ({
          role: 'resource',
          name: `sbom-${i}`,
          type: 'sbom',
          isSbom: true,
          transport: 'transported',
          raw: {},
          sbom: {
            format: 'spdx',
            fileName: `d.ctf.tar!sbom-${i}.spdx.json`,
            size: s.size,
            sha1: s.sha1,
            contentType: 'application/spdx+json',
            extractedIndex: i,
          },
        })),
      },
    ],
  } as unknown as OcmBundle;
  return {
    bundle,
    extracted: sboms.map((s, i) => ({
      fileName: `d.ctf.tar!sbom-${i}.spdx.json`,
      bytes: new Uint8Array(s.size),
    })),
    diagnostics: [],
  };
}

function respondBundle(worker: FakeWorker, id: number, sboms: { sha1: string; size: number }[]) {
  worker.onmessage?.({ data: { kind: 'bundle', id, ...delivery(sboms) } } as MessageEvent);
}

/** Answers an analysis job with progress, then one result per SBOM. */
function respondAnalysis(worker: FakeWorker, message: Message) {
  const items = message.items ?? [];
  items.forEach((_, i) =>
    worker.onmessage?.({
      data: { kind: 'sbom-progress', id: message.id, done: i + 1, total: items.length },
    } as MessageEvent),
  );
  const analyses = Object.fromEntries(
    items.map((item) => [item.sha1, { state: 'unreadable', reason: `parsed ${item.fileName}` }]),
  );
  worker.onmessage?.({ data: { kind: 'sbom-analyze', id: message.id, analyses } } as MessageEvent);
}

const SBOMS = [
  { sha1: 'a'.repeat(40), size: 10 },
  { sha1: 'b'.repeat(40), size: 20 },
  { sha1: 'c'.repeat(40), size: 100 },
];

const settled = () =>
  vi.waitFor(() => {
    expect(useAppStore.getState().sbomRun).toBeNull();
    expect(Object.keys(useAppStore.getState().delivery?.sbomAnalyses ?? {}).length).toBeGreaterThan(
      0,
    );
  });

beforeEach(() => {
  harness.requests.length = 0;
  harness.handle = (message, worker) => {
    if (message.kind === 'bundle') respondBundle(worker, message.id, SBOMS);
    if (message.kind === 'sbom-analyze') respondAnalysis(worker, message);
  };
  useAppStore.setState({
    delivery: null,
    loading: null,
    loadError: null,
    sbomRun: null,
    sbomError: null,
    packageRun: null,
    packageError: null,
  });
});

describe('SBOM analysis after opening', () => {
  it('shows the delivery first, then analyses the SBOMs that fit the budget and defers the rest', async () => {
    const runs: unknown[] = [];
    const unsubscribe = useAppStore.subscribe((s) => runs.push(s.sbomRun));
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]), { sbomBudget: 40 });

    // The walk never sees the app's budget, and the delivery is already open.
    expect(harness.requests[0]).toMatchObject({ kind: 'bundle', options: {} });
    expect(useAppStore.getState().delivery?.bundle.fileName).toBe('d.ctf.tar');

    await settled();
    unsubscribe();
    const analyze = harness.requests.find((r) => r.kind === 'sbom-analyze')!;
    expect(analyze.items!.map((i) => i.sha1)).toEqual([SBOMS[0]!.sha1, SBOMS[1]!.sha1]);
    const analyses = useAppStore.getState().delivery!.sbomAnalyses;
    expect(analyses[SBOMS[0]!.sha1]).toMatchObject({ reason: 'parsed d.ctf.tar!sbom-0.spdx.json' });
    expect(analyses[SBOMS[2]!.sha1]).toEqual({ state: 'deferred', size: 100 });
    expect(runs).toContainEqual({ done: 1, total: 2 });
    // The store keeps its bytes for downloads: the worker got copies.
    expect(useAppStore.getState().delivery!.extracted[0]!.bytes.byteLength).toBe(10);
  });

  it('analyses what the budget left out on "Analyse now"', async () => {
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]), { sbomBudget: 40 });
    await settled();
    harness.requests.length = 0;

    expect(await runSbomAnalysis()).toBe(true);
    expect(harness.requests.map((r) => [r.kind, r.items?.map((i) => i.sha1)])).toEqual([
      ['sbom-analyze', [SBOMS[2]!.sha1]],
    ]);
    expect(useAppStore.getState().delivery!.sbomAnalyses[SBOMS[2]!.sha1]).toMatchObject({
      state: 'unreadable',
    });
  });

  it('drops results that arrive after another delivery opened', async () => {
    const held: { message: Message; worker: FakeWorker }[] = [];
    const other = [{ sha1: 'd'.repeat(40), size: 5 }];
    let opened = 0;
    harness.handle = (message, worker) => {
      if (message.kind === 'bundle')
        respondBundle(worker, message.id, opened++ === 0 ? SBOMS : other);
      if (message.kind === 'sbom-analyze') {
        if (message.items?.[0]?.sha1 === SBOMS[0]!.sha1) held.push({ message, worker });
        else respondAnalysis(worker, message);
      }
    };
    await openBlob('first.ctf.tar', new Blob([new Uint8Array(4)]));
    await vi.waitFor(() => expect(held).toHaveLength(1));
    await openBlob('second.ctf.tar', new Blob([new Uint8Array(4)]));
    await vi.waitFor(() =>
      expect(useAppStore.getState().delivery?.sbomAnalyses[other[0]!.sha1]).toBeDefined(),
    );

    respondAnalysis(held[0]!.worker, held[0]!.message);
    await Promise.resolve();
    expect(Object.keys(useAppStore.getState().delivery!.sbomAnalyses)).toEqual([other[0]!.sha1]);
  });
});

describe('a worker that dies', () => {
  it('fails the open with a message, and the next job starts a fresh worker', async () => {
    harness.handle = (_message, worker) =>
      worker.onerror?.({ message: 'out of memory', preventDefault() {} } as ErrorEvent);
    await openBlob('huge.ctf.tar', new Blob([new Uint8Array(4)]));

    const { loadError, delivery } = useAppStore.getState();
    expect(delivery).toBeNull();
    expect(loadError?.diagnostics.map((d) => d.code)).toEqual(['WORKER_FAILED']);
    expect(loadError?.diagnostics[0]!.message).toContain('out of memory');
    const afterCrash = harness.created;

    harness.handle = (message, worker) => {
      if (message.kind === 'bundle') respondBundle(worker, message.id, []);
    };
    await openBlob('next.ctf.tar', new Blob([new Uint8Array(4)]));
    expect(harness.created).toBe(afterCrash + 1);
    expect(useAppStore.getState().delivery).not.toBeNull();
  });

  it('stops an SBOM analysis with a message the view can show', async () => {
    harness.handle = (message, worker) => {
      if (message.kind === 'bundle') respondBundle(worker, message.id, SBOMS.slice(0, 1));
      if (message.kind === 'sbom-analyze')
        worker.onerror?.({ message: 'out of memory', preventDefault() {} } as ErrorEvent);
    };
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]));
    await vi.waitFor(() => expect(useAppStore.getState().sbomError).toBe('out of memory'));
    expect(useAppStore.getState().sbomRun).toBeNull();
    expect(useAppStore.getState().delivery!.sbomAnalyses).toEqual({});
  });
});

/** Answers an analysis job as if every SBOM parsed. */
function respondAnalyzed(worker: FakeWorker, message: Message) {
  const analyses = Object.fromEntries(
    (message.items ?? []).map((item) => [item.sha1, { state: 'analyzed', summary: {} }]),
  );
  worker.onmessage?.({ data: { kind: 'sbom-analyze', id: message.id, analyses } } as MessageEvent);
}

/** Answers a package job with progress, then one (empty) list per SBOM. */
function respondPackages(worker: FakeWorker, message: Message) {
  const items = message.items ?? [];
  items.forEach((_, i) =>
    worker.onmessage?.({
      data: { kind: 'sbom-progress', id: message.id, done: i + 1, total: items.length },
    } as MessageEvent),
  );
  const lists = Object.fromEntries(
    items.map((item) => [
      item.sha1,
      {
        sha1: item.sha1,
        fileName: item.fileName,
        document: { elements: [] },
        subjects: [],
        omitted: { files: 0 },
      },
    ]),
  );
  worker.onmessage?.({ data: { kind: 'sbom-packages', id: message.id, lists } } as MessageEvent);
}

const packageRequests = () =>
  harness.requests
    .filter((r) => r.kind === 'sbom-packages')
    .map((r) => r.items!.map((i) => i.sha1));

describe('package lists', () => {
  beforeEach(() => {
    harness.handle = (message, worker) => {
      if (message.kind === 'bundle') respondBundle(worker, message.id, SBOMS);
      if (message.kind === 'sbom-analyze') respondAnalyzed(worker, message);
      if (message.kind === 'sbom-packages') respondPackages(worker, message);
    };
  });

  it('are read for analysed SBOMs only, once, and again for what "Analyse now" adds', async () => {
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]), { sbomBudget: 40 });
    await settled();
    // Opening alone reads no package list: the views ask for them.
    expect(packageRequests()).toEqual([]);

    expect(await loadSbomPackages()).toBe(true);
    expect(packageRequests()).toEqual([[SBOMS[0]!.sha1, SBOMS[1]!.sha1]]);
    expect(Object.keys(useAppStore.getState().delivery!.sbomPackages)).toEqual([
      SBOMS[0]!.sha1,
      SBOMS[1]!.sha1,
    ]);
    expect(useAppStore.getState().packageRun).toBeNull();

    expect(await loadSbomPackages()).toBe(true);
    expect(packageRequests()).toHaveLength(1);

    await runSbomAnalysis();
    await loadSbomPackages();
    expect(packageRequests()).toEqual([[SBOMS[0]!.sha1, SBOMS[1]!.sha1], [SBOMS[2]!.sha1]]);
  });

  it('are read once when two views ask at the same time', async () => {
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]));
    await settled();
    await Promise.all([loadSbomPackages(), loadSbomPackages()]);
    expect(packageRequests()).toHaveLength(1);
  });

  it('are dropped when they arrive after another delivery opened', async () => {
    const held: { message: Message; worker: FakeWorker }[] = [];
    const other = [{ sha1: 'd'.repeat(40), size: 5 }];
    let opened = 0;
    harness.handle = (message, worker) => {
      if (message.kind === 'bundle')
        respondBundle(worker, message.id, opened++ === 0 ? SBOMS : other);
      if (message.kind === 'sbom-analyze') respondAnalyzed(worker, message);
      if (message.kind === 'sbom-packages') held.push({ message, worker });
    };
    await openBlob('first.ctf.tar', new Blob([new Uint8Array(4)]));
    await settled();
    const first = loadSbomPackages();
    await vi.waitFor(() => expect(held).toHaveLength(1));
    await openBlob('second.ctf.tar', new Blob([new Uint8Array(4)]));
    await settled();

    respondPackages(held[0]!.worker, held[0]!.message);
    await first;
    expect(useAppStore.getState().delivery!.sbomPackages).toEqual({});
    expect(useAppStore.getState().packageRun).toBeNull();
  });

  it('stop with a message when the worker dies, and the next request starts over', async () => {
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]));
    await settled();
    harness.handle = (message, worker) => {
      if (message.kind === 'sbom-packages')
        worker.onerror?.({ message: 'out of memory', preventDefault() {} } as ErrorEvent);
    };
    expect(await loadSbomPackages()).toBe(false);
    expect(useAppStore.getState().packageError).toBe('out of memory');
    expect(useAppStore.getState().packageRun).toBeNull();
    expect(useAppStore.getState().delivery!.sbomPackages).toEqual({});

    harness.handle = (message, worker) => {
      if (message.kind === 'sbom-packages') respondPackages(worker, message);
    };
    expect(await loadSbomPackages()).toBe(true);
    expect(useAppStore.getState().packageError).toBeNull();
    expect(Object.keys(useAppStore.getState().delivery!.sbomPackages)).toHaveLength(3);
  });
});

describe('the acceptance report export', () => {
  it('declines while the SBOMs are still being analysed', async () => {
    harness.handle = (message, worker) => {
      // The analysis never answers: it is still running.
      if (message.kind === 'bundle') respondBundle(worker, message.id, SBOMS.slice(0, 1));
    };
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]));
    await vi.waitFor(() => expect(useAppStore.getState().sbomRun).not.toBeNull());
    const outcome = await prepareAcceptanceReport();
    expect(outcome.ok).toBe(false);
    expect(!outcome.ok && outcome.reason).toContain('still being analysed (0 of 1)');
    expect(harness.requests.some((r) => r.kind === 'sbom-packages')).toBe(false);
  });

  it('reads the package lists first, and declines with the reason when that fails', async () => {
    harness.handle = (message, worker) => {
      if (message.kind === 'bundle') respondBundle(worker, message.id, SBOMS);
      if (message.kind === 'sbom-analyze') respondAnalyzed(worker, message);
      if (message.kind === 'sbom-packages')
        worker.onerror?.({ message: 'out of memory', preventDefault() {} } as ErrorEvent);
    };
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]));
    await settled();
    const outcome = await prepareAcceptanceReport();
    expect(packageRequests()).toHaveLength(1);
    expect(outcome.ok).toBe(false);
    expect(!outcome.ok && outcome.reason).toContain('reading them stopped: out of memory');
  });

  it('exports once nothing is missing', async () => {
    await openBlob('d.ctf.tar', new Blob([new Uint8Array(4)]));
    await settled();
    const outcome = await prepareAcceptanceReport(new Date('2026-10-16T00:00:00Z'));
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.fileBase).toBe('d');
    expect(outcome.report.markdown).toContain('| Generated | 2026-10-16T00:00:00.000Z by OCM Lens');
    expect(outcome.report.json.sbomEvidence).toBeDefined();
  });
});
