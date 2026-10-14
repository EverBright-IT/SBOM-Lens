/**
 * Per-browser preferences. The one place the app touches localStorage: when
 * stage H moves OCM Lens 2.0 into the VS Code webview, this module swaps its
 * backend for the extension bridge and nothing else changes. Reads and
 * writes never throw (private windows, blocked storage).
 */

export function readPref(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function persistPref(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage unavailable — the preference simply does not stick.
  }
}
