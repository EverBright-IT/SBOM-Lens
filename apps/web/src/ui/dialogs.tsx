import { useEffect, useRef, useState } from 'react';
import { BRAND } from '../app/brand';
import { ingestUrl } from '../app/ingest';
import { useAppStore } from '../app/store';
import { rememberToken, tokenForUrl, type TokenScheme } from '../app/tokens';
import { CloseIcon } from './icons';

export function useDialog(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const handler = () => onClose();
    dialog.addEventListener('close', handler);
    return () => dialog.removeEventListener('close', handler);
  }, [onClose]);
  return ref;
}

export const dialogClass =
  'm-auto w-[32rem] max-w-[calc(100vw-2rem)] rounded-lg border border-slate-200 bg-white p-0 text-slate-900 shadow-xl backdrop:bg-slate-950/30 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100';

export function UrlDialog() {
  const open = useAppStore((s) => s.urlDialogOpen);
  const prefill = useAppStore((s) => s.urlDialogPrefill);
  const actions = useAppStore((s) => s.actions);
  const ref = useDialog(open, actions.closeUrlDialog);

  const [url, setUrl] = useState('');
  const [scheme, setScheme] = useState<TokenScheme | 'none'>('none');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setUrl(prefill);
    setError(null);
    setBusy(false);
    setScheme('none');
    setToken('');
    if (!prefill) return;
    let stale = false;
    void tokenForUrl(prefill).then((existing) => {
      if (stale || !existing) return;
      setScheme(existing.scheme);
      setToken(existing.value);
    });
    return () => {
      stale = true;
    };
  }, [open, prefill]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    await rememberToken(url, scheme === 'none' || !token ? null : { scheme, value: token });
    const result = await ingestUrl(url.trim());
    setBusy(false);
    if (result.ok) actions.closeUrlDialog();
    else setError(result.message ?? 'Failed.');
  };

  return (
    <dialog ref={ref} className={dialogClass}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="p-5"
      >
        <DialogHeader title="Open from URL" onClose={actions.closeUrlDialog} />
        <label className="mt-3 block text-xs text-slate-500 dark:text-slate-400">
          {BRAND.urlDialogLabel}
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://gitlab.example.com/api/v4/projects/.../release.spdx"
            autoFocus
            spellCheck={false}
            className="mt-1 w-full rounded border border-slate-300 bg-transparent px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-400 dark:border-slate-600"
          />
        </label>

        <div className="mt-3 grid grid-cols-[10rem_1fr] gap-2">
          <label className="block text-xs text-slate-500 dark:text-slate-400">
            Authentication
            <select
              value={scheme}
              onChange={(e) => setScheme(e.target.value as TokenScheme | 'none')}
              className="mt-1 w-full rounded border border-slate-300 bg-transparent px-1.5 py-1.5 text-xs outline-none focus:border-accent-400 dark:border-slate-600 dark:bg-slate-900"
            >
              <option value="none">None (public)</option>
              <option value="private-token">GitLab PRIVATE-TOKEN</option>
              <option value="bearer">Bearer token</option>
            </select>
          </label>
          <label className="block text-xs text-slate-500 dark:text-slate-400">
            Token — use a read-only scope; kept in this tab's session only
            <input
              value={token}
              onChange={(e) => setToken(e.target.value)}
              disabled={scheme === 'none'}
              type="password"
              autoComplete="off"
              className="mt-1 w-full rounded border border-slate-300 bg-transparent px-2 py-1.5 font-mono text-xs outline-none focus:border-accent-400 disabled:opacity-40 dark:border-slate-600"
            />
          </label>
        </div>

        {error && (
          <p className="mt-3 rounded border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            {error}
          </p>
        )}

        <p className="mt-3 text-[11px] leading-relaxed text-slate-400">
          The server must allow cross-origin requests (CORS). If the fetch is blocked, download the
          file and drop it into the window instead — nothing you load ever leaves your machine.
        </p>

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={actions.closeUrlDialog}
            className="rounded border border-slate-200 px-3 py-1.5 text-xs dark:border-slate-700"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || url.trim() === ''}
            className="rounded bg-accent-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-accent-700 disabled:opacity-50"
          >
            {busy ? 'Fetching...' : 'Fetch'}
          </button>
        </div>
      </form>
    </dialog>
  );
}

const SHORTCUTS: [string, string][] = [
  ['/', 'Focus search'],
  ['↑ ↓', 'Move selection in the tree / results'],
  ['→', 'Expand node · first child'],
  ['←', 'Collapse node · parent'],
  ['*', 'Expand entire subtree (also: Shift+click a chevron)'],
  ['Enter', 'Toggle node / open search result'],
  ['Esc', 'Clear search, close panels'],
  ['?', 'This help'],
];

export function HelpDialog() {
  const open = useAppStore((s) => s.helpOpen);
  const actions = useAppStore((s) => s.actions);
  const ref = useDialog(open, () => actions.setHelpOpen(false));

  return (
    <dialog ref={ref} className={dialogClass}>
      <div className="p-5">
        <DialogHeader title="Keyboard shortcuts" onClose={() => actions.setHelpOpen(false)} />
        <table className="mt-3 w-full text-[13px]">
          <tbody>
            {SHORTCUTS.map(([key, description]) => (
              <tr key={key} className="border-t border-slate-100 first:border-t-0 dark:border-slate-800">
                <td className="w-24 py-1.5">
                  <kbd className="rounded border border-slate-200 px-1.5 py-0.5 font-mono text-[11px] text-slate-500 dark:border-slate-700 dark:text-slate-400">
                    {key}
                  </kbd>
                </td>
                <td className="py-1.5 text-slate-600 dark:text-slate-300">{description}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-4 text-[11px] text-slate-400">
          {BRAND.name} · {BRAND.tagline}. Files are parsed locally in your browser and never
          uploaded.
        </p>
      </div>
    </dialog>
  );
}

function DialogHeader({ title, onClose }: { title: string; onClose: () => void }) {
  return (
    <div className="flex items-center justify-between">
      <h2 className="text-sm font-semibold">{title}</h2>
      <button
        type="button"
        onClick={onClose}
        className="rounded p-1 text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800"
      >
        <CloseIcon />
      </button>
    </div>
  );
}
