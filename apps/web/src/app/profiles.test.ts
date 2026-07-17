import { PROFILE_SCHEMA_V1, parseDocument, sha1Hex } from '@sbomlens/core';
import { loadFixture } from '@sbomlens/core/test-fixtures';
import { beforeEach, describe, expect, it } from 'vitest';
import type { HostAdapter } from '../host/adapter';
import { setHost } from '../host/adapter';
import type { ParseJobRequest, ParseJobResponse } from '../worker/protocol';
import { ingestBuffers, ingestUrl } from './ingest';
import { initProfiles, removeProfile } from './profiles';
import { useAppStore } from './store';

/** Same fake worker as ingest.url.test.ts — real core parser, no thread. */
class FakeWorker {
  static jobs = 0;
  onmessage: ((event: { data: ParseJobResponse }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  postMessage(request: ParseJobRequest): void {
    FakeWorker.jobs++;
    void (async () => {
      const sha1 = await sha1Hex(request.buffer!);
      const text = new TextDecoder().decode(request.buffer!);
      const { document, diagnostics } = parseDocument({
        fileName: request.fileName,
        text,
        sha1,
        byteSize: request.buffer!.byteLength,
      });
      this.onmessage?.({
        data: {
          id: request.id,
          ok: true,
          kind: 'document',
          fileName: request.fileName,
          sha1,
          byteSize: request.buffer!.byteLength,
          text,
          document,
          diagnostics,
        },
      });
    })();
  }
  terminate(): void {}
}

const prefs = new Map<string, string>();
let fetchBytes: ArrayBuffer | null = null;

const fakeHost: HostAdapter = {
  kind: 'web',
  caps: { catalog: false },
  async fetchDocument() {
    return fetchBytes ? { ok: true, bytes: fetchBytes } : { ok: false };
  },
  readPref: (key) => prefs.get(key) ?? null,
  persistPref: (key, value) => void prefs.set(key, value),
  secretGet: async () => null,
  secretSet: async () => {},
  exportFile: () => {},
  openExternal: () => {},
  createWorker: () => new FakeWorker() as unknown as Worker,
  onIngestMessage: () => {},
};

const PROFILE = {
  schema: PROFILE_SCHEMA_V1,
  name: 'ACME Baseline',
  checks: [{ type: 'package-coverage', field: 'version', threshold: 95 }],
};

const bytes = (value: unknown): ArrayBuffer =>
  new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value))
    .buffer as ArrayBuffer;

describe('profile import through ingest', () => {
  beforeEach(() => {
    setHost(fakeHost);
    prefs.clear();
    FakeWorker.jobs = 0;
    useAppStore.getState().actions.clearAll();
    useAppStore.getState().actions.setProfiles([]);
    useAppStore.getState().actions.setActiveProfileId(null);
  });

  it('sifts a profile out of a mixed batch: store gains it, worker never sees it', async () => {
    const added = await ingestBuffers([
      { fileName: 'profile.json', buffer: bytes(PROFILE) },
      { fileName: 'minimal.spdx', buffer: bytes(loadFixture('minimal.spdx')) },
    ]);
    const state = useAppStore.getState();
    expect(added).toHaveLength(1);
    expect(state.ws.documents.size).toBe(1);
    expect(state.profiles).toHaveLength(1);
    expect(state.profiles[0]!.profile.name).toBe('ACME Baseline');
    expect(state.activeProfileId).toBe('user:ACME Baseline'); // imported → auto-active
    expect(state.failures).toHaveLength(0);
    expect(state.parsing.active).toBe(0);
    expect(FakeWorker.jobs).toBe(1); // only the SPDX file reached the worker
  });

  it('records failures for invalid profiles without dispatching to the worker', async () => {
    const invalid = { schema: PROFILE_SCHEMA_V1, name: 'Bad', checks: [{ type: 'nope' }] };
    await ingestBuffers([{ fileName: 'bad-profile.json', buffer: bytes(invalid) }]);
    const state = useAppStore.getState();
    expect(state.profiles).toHaveLength(0);
    expect(state.failures).toHaveLength(1);
    expect(state.failures[0]!.diagnostics[0]!.code).toBe('PROFILE_INVALID');
    expect(FakeWorker.jobs).toBe(0);
  });

  it('lets SPDX JSON that merely mentions the marker parse as a document', async () => {
    const spdx = JSON.parse(loadFixture('minimal.spdx.json')) as Record<string, unknown>;
    spdx.comment = 'see "sbomlens-profile/v1" docs';
    const added = await ingestBuffers([{ fileName: 'doc.spdx.json', buffer: bytes(spdx) }]);
    expect(added).toHaveLength(1);
    expect(useAppStore.getState().profiles).toHaveLength(0);
  });

  it('imports a profile fetched by URL', async () => {
    fetchBytes = bytes(PROFILE);
    const result = await ingestUrl('https://example.org/profile.json');
    expect(result).toEqual({ ok: true });
    expect(useAppStore.getState().profiles).toHaveLength(1);
  });

  it('persists imports, restores them, and falls back to NTIA on removal', async () => {
    await ingestBuffers([{ fileName: 'profile.json', buffer: bytes(PROFILE) }]);
    expect(prefs.get('sbomlens.profiles')).toContain('ACME Baseline');
    expect(prefs.get('sbomlens.activeProfile')).toBe('user:ACME Baseline');

    // Fresh session: store cleared, prefs survive.
    useAppStore.getState().actions.setProfiles([]);
    useAppStore.getState().actions.setActiveProfileId(null);
    initProfiles();
    let state = useAppStore.getState();
    expect(state.profiles).toHaveLength(1);
    expect(state.activeProfileId).toBe('user:ACME Baseline');

    removeProfile('user:ACME Baseline');
    state = useAppStore.getState();
    expect(state.profiles).toHaveLength(0);
    expect(state.activeProfileId).toBeNull();
    expect(prefs.get('sbomlens.profiles')).toBe('[]');
  });

  it('drops corrupt persisted prefs silently', () => {
    prefs.set('sbomlens.profiles', '{not json');
    initProfiles();
    expect(useAppStore.getState().profiles).toHaveLength(0);
  });

  it('re-importing the same name replaces instead of duplicating', async () => {
    await ingestBuffers([{ fileName: 'a.json', buffer: bytes(PROFILE) }]);
    const changed = { ...PROFILE, checks: [{ type: 'relationships' }] };
    await ingestBuffers([{ fileName: 'b.json', buffer: bytes(changed) }]);
    const state = useAppStore.getState();
    expect(state.profiles).toHaveLength(1);
    expect(state.profiles[0]!.profile.checks[0]!.type).toBe('relationships');
  });
});
