import type { HostAdapter } from './adapter';

/**
 * The browser host: plain fetch, localStorage prefs, sessionStorage secrets
 * (die with the tab by design), anchor-click downloads, module workers.
 */
export const webHost: HostAdapter = {
  kind: 'web',
  caps: { catalog: true },

  async fetchDocument(url, headers = {}) {
    let response: Response;
    try {
      response = await fetch(url, { headers });
    } catch {
      return { ok: false };
    }
    if (!response.ok) {
      return { ok: false, status: response.status, statusText: response.statusText };
    }
    return { ok: true, bytes: await response.arrayBuffer() };
  },

  readPref(key) {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  },
  persistPref(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // Quota/privacy-mode errors — prefs are a convenience.
    }
  },

  async secretGet(key) {
    try {
      return sessionStorage.getItem(key);
    } catch {
      return null;
    }
  },
  async secretSet(key, value) {
    try {
      if (value === null) sessionStorage.removeItem(key);
      else sessionStorage.setItem(key, value);
    } catch {
      // Tokens are a convenience, not a requirement.
    }
  },

  exportFile(fileName, mime, text) {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },

  openExternal(url) {
    window.open(url, '_blank', 'noopener');
  },

  createWorker() {
    // The literal new URL(...) keeps the worker visible to the bundler.
    return new Worker(new URL('../worker/parse.worker.ts', import.meta.url), { type: 'module' });
  },

  onIngestMessage() {
    // The browser has no host-initiated pushes; files arrive via drop/picker.
  },
};
