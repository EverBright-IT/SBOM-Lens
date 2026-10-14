import type { Host } from './types';

/** The browser host: module workers, localStorage, anchor downloads. */
export const webHost: Host = {
  kind: 'web',

  createWorker() {
    // The literal new URL(...) keeps the worker visible to the bundler.
    return new Worker(new URL('../worker/bundle.worker.ts', import.meta.url), { type: 'module' });
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
      // Storage unavailable (private window, blocked) - the pref does not stick.
    }
  },

  saveFile(fileName, mime, data) {
    const blob =
      typeof data === 'string'
        ? new Blob([data], { type: mime })
        : new Blob([data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer], {
            type: mime,
          });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  },

  onPush() {
    // The browser has no host that pushes files.
  },
};
