import { createServer } from 'node:http';
import type { IncomingHttpHeaders, RequestListener, Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import type { HostToWebviewMessage } from './protocol';
import type { BridgeContext } from './bridge';
import { buildWebviewHtml, createBridgeHandler, nodeFetchBytes, prefsSnapshot } from './bridge';

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
    saveBytes: async (fileName, bytes) => void calls.push(`bytes:${fileName}:${bytes.byteLength}`),
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

  it('routes binary exports to the byte sink, untouched', async () => {
    const { ctx, calls } = makeContext();
    const handle = createBridgeHandler(() => {}, ctx);
    await handle({ type: 'exportBytes', fileName: 'chart.tar', bytes: new Uint8Array([0, 255, 7]) });
    expect(calls).toEqual(['bytes:chart.tar:3']);
  });
});

describe('nodeFetchBytes', () => {
  const servers: Server[] = [];

  function listen(handler: RequestListener): Promise<string> {
    return new Promise((resolve) => {
      const server = createServer(handler);
      servers.push(server);
      server.listen(0, '127.0.0.1', () => {
        resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
      });
    });
  }

  afterEach(() => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      server.close();
    }
  });

  // Node's fetch repeats custom headers such as PRIVATE-TOKEN against
  // whatever address a redirect names; only Authorization is dropped.
  it.each([301, 302, 303, 307, 308])(
    'does not follow a %i to an http address, so the token never reaches the host it names',
    async (status) => {
      const foreign: IncomingHttpHeaders[] = [];
      const foreignHost = await listen((req, res) => {
        foreign.push(req.headers);
        res.end('collected');
      });
      const tokenHost = await listen((_req, res) => {
        res.writeHead(status, { location: `${foreignHost}/collect` }).end();
      });

      const result = await nodeFetchBytes(`${tokenHost}/weiter`, { 'PRIVATE-TOKEN': 'secret' });

      expect(foreign).toEqual([]);
      expect(result).toMatchObject({ ok: false, status });
    },
  );

  /** A fetch that answers per URL and records what each address was sent. */
  function scripted(answers: Record<string, () => Response>) {
    const seen: { url: string; token: string | null }[] = [];
    const fetchFn = ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = String(input);
      seen.push({ url, token: new Headers(init?.headers).get('private-token') });
      const answer = answers[url];
      return Promise.resolve(answer ? answer() : new Response('not found', { status: 404 }));
    }) as typeof fetch;
    return { fetchFn, seen };
  }

  const redirect = (location: string, status = 302) => new Response(null, { status, headers: { location } });

  it('follows an https redirect to another host, and the token stays behind', async () => {
    const { fetchFn, seen } = scripted({
      'https://git.example/pkg/a.spdx': () => redirect('https://store.example/objects/a'),
      'https://store.example/objects/a': () => new Response('SPDX'),
    });

    const result = await nodeFetchBytes('https://git.example/pkg/a.spdx', { 'PRIVATE-TOKEN': 'secret' }, fetchFn);

    expect(seen).toEqual([
      { url: 'https://git.example/pkg/a.spdx', token: 'secret' },
      { url: 'https://store.example/objects/a', token: null },
    ]);
    expect(result.ok && new TextDecoder().decode(result.bytes)).toBe('SPDX');
  });

  it('keeps the token on a redirect within the same origin', async () => {
    const { fetchFn, seen } = scripted({
      'https://git.example/old': () => redirect('/new', 301),
      'https://git.example/new': () => new Response('SPDX'),
    });

    const result = await nodeFetchBytes('https://git.example/old', { 'PRIVATE-TOKEN': 'secret' }, fetchFn);

    expect(seen.map((call) => call.token)).toEqual(['secret', 'secret']);
    expect(result.ok).toBe(true);
  });

  it('treats another port or scheme of the same host as another origin', async () => {
    const { fetchFn, seen } = scripted({
      'http://git.example/a': () => redirect('https://git.example/a'),
      'https://git.example/a': () => redirect('https://git.example:8443/a'),
      'https://git.example:8443/a': () => new Response('SPDX'),
    });

    const result = await nodeFetchBytes('http://git.example/a', { 'PRIVATE-TOKEN': 'secret' }, fetchFn);

    expect(seen.map((call) => call.token)).toEqual(['secret', null, null]);
    expect(result.ok).toBe(true);
  });

  it('gives up on a redirect loop', async () => {
    const { fetchFn, seen } = scripted({ 'https://git.example/a': () => redirect('/a') });

    const result = await nodeFetchBytes('https://git.example/a', {}, fetchFn);

    expect(seen).toHaveLength(6);
    expect(result).toMatchObject({ ok: false, status: 302 });
  });

  it('still sends the token to the address the caller named', async () => {
    const seen: IncomingHttpHeaders[] = [];
    const tokenHost = await listen((req, res) => {
      seen.push(req.headers);
      res.end('SPDX');
    });

    const result = await nodeFetchBytes(`${tokenHost}/a.spdx`, { 'PRIVATE-TOKEN': 'secret' });

    expect(seen.map((headers) => headers['private-token'])).toEqual(['secret']);
    expect(result.ok && new TextDecoder().decode(result.bytes)).toBe('SPDX');
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
