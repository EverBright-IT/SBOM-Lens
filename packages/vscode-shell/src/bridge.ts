import type {
  HostToWebviewMessage,
  WebviewToHostMessage,
} from '@sbomlens/web/vscode-protocol';

/**
 * The extension-host side of the webview bridge, dependency-injected so the
 * handlers are testable without the vscode module. Shared by every Lens
 * extension flavor.
 */
export interface BridgeContext {
  fetchBytes(
    url: string,
    headers: Record<string, string>,
  ): Promise<{ ok: boolean; status?: number; statusText?: string; bytes?: Uint8Array }>;
  secretGet(key: string): Thenable<string | undefined>;
  secretStore(key: string, value: string): Thenable<void>;
  secretDelete(key: string): Thenable<void>;
  persistPref(key: string, value: string): Thenable<void>;
  saveFile(fileName: string, text: string): Promise<void>;
  openExternal(url: string): void;
  /** Called when the webview reports ready — time to push initial documents. */
  onReady(): void;
}

export function createBridgeHandler(
  post: (message: HostToWebviewMessage) => void,
  ctx: BridgeContext,
): (message: WebviewToHostMessage) => Promise<void> {
  return async (message) => {
    switch (message.type) {
      case 'ready':
        ctx.onReady();
        break;
      case 'fetchUrl': {
        const result = await ctx.fetchBytes(message.url, message.headers);
        post({ type: 'fetchResult', id: message.id, ...result });
        break;
      }
      case 'secretGet': {
        const value = await ctx.secretGet(message.key);
        post({ type: 'secretValue', id: message.id, value: value ?? null });
        break;
      }
      case 'secretSet':
        if (message.value === null) await ctx.secretDelete(message.key);
        else await ctx.secretStore(message.key, message.value);
        break;
      case 'persistPref':
        await ctx.persistPref(message.key, message.value);
        break;
      case 'exportFile':
        await ctx.saveFile(message.fileName, message.text);
        break;
      case 'openExternal':
        ctx.openExternal(message.url);
        break;
    }
  };
}

/** Node-side fetch: no CORS in the extension host — the webview's escape hatch. */
export async function nodeFetchBytes(
  url: string,
  headers: Record<string, string>,
): Promise<{ ok: boolean; status?: number; statusText?: string; bytes?: Uint8Array }> {
  try {
    const response = await fetch(url, { headers });
    if (!response.ok) {
      return { ok: false, status: response.status, statusText: response.statusText };
    }
    return { ok: true, bytes: new Uint8Array(await response.arrayBuffer()) };
  } catch {
    return { ok: false };
  }
}

/**
 * Injects <base href>, the CSP, a nonce on every script, and the pref
 * snapshot into the built index.html. The nonce pass runs first so the
 * injected snippet keeps its single nonce. The __SBOMLENS_PREFS__ global is
 * a webview-internal name shared by both flavors' bundles — webviews are
 * isolated JS contexts, so the products can never collide on it.
 */
export function buildWebviewHtml(
  raw: string,
  opts: { baseHref: string; cspSource: string; nonce: string; prefs: Record<string, string> },
): string {
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${opts.nonce}' ${opts.cspSource}`,
    `style-src ${opts.cspSource} 'unsafe-inline'`,
    `connect-src ${opts.cspSource}`,
    "worker-src blob:",
    `img-src ${opts.cspSource} data:`,
    `font-src ${opts.cspSource}`,
  ].join('; ');
  const prefsJson = JSON.stringify(opts.prefs).replace(/</g, '\\u003c');
  const inject =
    `<base href="${opts.baseHref}">` +
    `<meta http-equiv="Content-Security-Policy" content="${csp}">` +
    `<script nonce="${opts.nonce}">window.__SBOMLENS_PREFS__=${prefsJson}</script>`;
  return raw
    .replace(/<script /g, `<script nonce="${opts.nonce}" `)
    .replace('<head>', `<head>${inject}`);
}

/** Snapshot of all persisted prefs under the flavor's namespace. */
export function prefsSnapshot(
  keys: readonly string[],
  read: (key: string) => string | undefined,
  prefPrefix: string,
): Record<string, string> {
  const prefs: Record<string, string> = {};
  for (const key of keys) {
    if (!key.startsWith(prefPrefix)) continue;
    const value = read(key);
    if (typeof value === 'string') prefs[key] = value;
  }
  return prefs;
}
