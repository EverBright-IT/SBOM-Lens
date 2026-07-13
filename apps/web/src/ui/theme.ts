import { pref } from '../app/brand';
import { host } from '../host/adapter';

/**
 * Three-state theme: follow the OS/host ('system') or force light/dark.
 * Applied as a .dark class on <html> (see the @custom-variant in index.css)
 * plus color-scheme for native widgets. Persisted via host prefs. In the
 * VS Code webview 'system' follows the editor theme, which the webview
 * mirrors into prefers-color-scheme.
 */

export type ThemeMode = 'system' | 'light' | 'dark';

const PREF_KEY = pref('theme');
export const THEME_ORDER: readonly ThemeMode[] = ['system', 'light', 'dark'];

let current: ThemeMode = 'system';

function systemPrefersDark(): boolean {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function apply(mode: ThemeMode): void {
  const dark = mode === 'dark' || (mode === 'system' && systemPrefersDark());
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
}

/** Call once before render — avoids a light-mode flash for dark users. */
export function initTheme(): void {
  const stored = host().readPref(PREF_KEY);
  current = stored === 'light' || stored === 'dark' ? stored : 'system';
  apply(current);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (current === 'system') apply(current);
  });
}

export function themeMode(): ThemeMode {
  return current;
}

export function setThemeMode(mode: ThemeMode): void {
  current = mode;
  host().persistPref(PREF_KEY, mode);
  apply(mode);
}
