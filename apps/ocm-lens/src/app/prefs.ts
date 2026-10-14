import { host } from '../host';

/**
 * Per-user preferences, wherever the host keeps them: localStorage in the
 * browser, the extension's globalState in VS Code. Reads never throw.
 */

export function readPref(key: string): string | null {
  return host.readPref(key);
}

export function persistPref(key: string, value: string): void {
  host.persistPref(key, value);
}
