import { describe, expect, it } from 'vitest';
import type { HostToWebviewMessage } from '@sbomlens/web/vscode-protocol';
import type { BridgeContext } from './bridge';
import { buildWebviewHtml, createBridgeHandler, prefsSnapshot } from './bridge';

function makeContext(overrides: Partial<BridgeContext> = {}): {
  ctx: BridgeContext;
  calls: string[];
} {
  const calls: string[] = [];
  const ctx: BridgeContext = {
    fetchBytes: async (url) => {
      calls.push(`fetch:${url}`);
      return { ok: true, bytes: new TextEncoder().encode('data') };
    },
    secretGet: async (key) => (key === 'sbomlens.token.known' ? 'stored' : undefined),
    secretStore: async (key) => void calls.push(`store:${key}`),
    secretDelete: async (key) => void calls.push(`delete:${key}`),
    persistPref: async (key, value) => void calls.push(`pref:${key}=${value}`),
    saveFile: async (fileName) => void calls.push(`save:${fileName}`),
    openExternal: (url) => void calls.push(`open:${url}`),
    onReady: () => void calls.push('ready'),
    ...overrides,
  };
  return { ctx, calls };
}

describe('bridge handlers', () => {
  it('answers fetchUrl with a correlated fetchResult', async () => {
    const posted: HostToWebviewMessage[] = [];
    const { ctx } = makeContext();
    const handle = createBridgeHandler((m) => posted.push(m), ctx);
    await handle({ type: 'fetchUrl', id: 7, url: 'https://x/a.spdx', headers: {} });
    expect(posted[0]).toMatchObject({ type: 'fetchResult', id: 7, ok: true });
  });

  it('answers secretGet with null for unknown keys', async () => {
    const posted: HostToWebviewMessage[] = [];
    const { ctx } = makeContext();
    const handle = createBridgeHandler((m) => posted.push(m), ctx);
    await handle({ type: 'secretGet', id: 1, key: 'sbomlens.token.known' });
    await handle({ type: 'secretGet', id: 2, key: 'sbomlens.token.unknown' });
    expect(posted).toEqual([
      { type: 'secretValue', id: 1, value: 'stored' },
      { type: 'secretValue', id: 2, value: null },
    ]);
  });

  it('routes secretSet to store or delete, prefs and export to their sinks', async () => {
    const { ctx, calls } = makeContext();
    const handle = createBridgeHandler(() => {}, ctx);
    await handle({ type: 'secretSet', key: 'k', value: 'v' });
    await handle({ type: 'secretSet', key: 'k', value: null });
    await handle({ type: 'persistPref', key: 'sbomlens.sidebar', value: '400' });
    await handle({ type: 'exportFile', fileName: 'inv.csv', mime: 'text/csv', text: 'a,b' });
    await handle({ type: 'openExternal', url: 'https://spdx.dev' });
    await handle({ type: 'ready' });
    expect(calls).toEqual([
      'store:k',
      'delete:k',
      'pref:sbomlens.sidebar=400',
      'save:inv.csv',
      'open:https://spdx.dev',
      'ready',
    ]);
  });
});

describe('buildWebviewHtml', () => {
  const raw = '<!doctype html><html><head><title>x</title></head><body><script type="module" src="./assets/i.js"></script></body></html>';

  it('injects base, CSP, nonce on every script, and the pref snapshot', () => {
    const html = buildWebviewHtml(raw, {
      baseHref: 'vscode-resource://media/',
      cspSource: 'vscode-resource:',
      nonce: 'N0NCE',
      prefs: { 'sbomlens.sidebar': '400' },
    });
    expect(html).toContain('<base href="vscode-resource://media/">');
    expect(html).toContain("worker-src blob:");
    expect(html).toContain('script-src \'nonce-N0NCE\' vscode-resource:');
    expect(html).toContain('<script nonce="N0NCE" type="module" src="./assets/i.js">');
    expect(html).toContain('window.__SBOMLENS_PREFS__={"sbomlens.sidebar":"400"}');
    // the injected snippet carries exactly one nonce attribute
    expect(html).not.toContain('nonce="N0NCE" nonce=');
  });

  it('escapes closing tags inside pref values', () => {
    const html = buildWebviewHtml(raw, {
      baseHref: 'b/',
      cspSource: 'c:',
      nonce: 'n',
      prefs: { 'sbomlens.x': '</script><script>alert(1)</script>' },
    });
    expect(html).not.toContain('</script><script>alert(1)');
  });
});

describe('prefsSnapshot', () => {
  it('keeps only string values under the given prefix', () => {
    const store = new Map<string, unknown>([
      ['sbomlens.sidebar', '400'],
      ['sbomlens.count', 3],
      ['ocmlens.sidebar', '360'],
      ['other.key', 'x'],
    ]);
    const read = (k: string) => {
      const v = store.get(k);
      return typeof v === 'string' ? v : undefined;
    };
    expect(prefsSnapshot([...store.keys()], read, 'sbomlens.')).toEqual({
      'sbomlens.sidebar': '400',
    });
    expect(prefsSnapshot([...store.keys()], read, 'ocmlens.')).toEqual({
      'ocmlens.sidebar': '360',
    });
  });
});

describe('extraMessage seam', () => {
  it('lets a flavor claim messages before the shared handlers run', async () => {
    const { ctx, calls } = makeContext({
      extraMessage: async (message) => message.type === 'ocmListVersions',
    });
    const handle = createBridgeHandler(() => {}, ctx);
    await handle({ type: 'ocmListVersions', id: 1, registry: 'r', component: 'c' });
    await handle({ type: 'ready' });
    expect(calls).toEqual(['ready']); // the claimed message never hit the shared handlers
  });
});
