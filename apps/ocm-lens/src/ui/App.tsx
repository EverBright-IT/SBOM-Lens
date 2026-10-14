import { useCallback, useEffect, useRef } from 'react';
import clsx from 'clsx';
import { openFile, openFromUrl } from '../app/ingest';
import { IS_VSCODE } from '../host';
import type { MainView } from '../app/store';
import { useAppStore } from '../app/store';
import { APP_VERSION } from '../version';
import { ComponentsView } from './ComponentsView';
import { Dashboard } from './Dashboard';
import { EmptyState } from './EmptyState';
import { ResourcesView } from './ResourcesView';
import { VerifyView } from './VerifyView';

const VIEWS: { id: MainView; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'components', label: 'Components' },
  { id: 'resources', label: 'Resources' },
  { id: 'verify', label: 'Verify' },
];

/** The cube-in-a-lens mark — OCM Lens' brand, indigo via currentColor. */
export function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <circle cx="10.5" cy="10.5" r="7.5" />
      <path d="M16 16l5.5 5.5" />
      <path d="M6.7 8.6l3.8-2.1 3.8 2.1v4l-3.8 2.1-3.8-2.1z" strokeWidth="1.6" />
      <path d="M6.7 8.6l3.8 2.1 3.8-2.1M10.5 10.7v4" strokeWidth="1.6" />
    </svg>
  );
}

function ViewTabs() {
  const view = useAppStore((s) => s.view);
  const setView = useAppStore((s) => s.actions.setView);
  return (
    <nav className="flex gap-0.5 rounded border border-slate-200 p-0.5 dark:border-slate-700">
      {VIEWS.map((v) => (
        <button
          key={v.id}
          type="button"
          onClick={() => setView(v.id)}
          className={clsx(
            'rounded px-2 py-0.5 text-xs',
            view === v.id
              ? 'bg-accent-600 text-white'
              : 'text-slate-500 hover:text-accent-700 dark:text-slate-400 dark:hover:text-accent-400',
          )}
        >
          {v.label}
        </button>
      ))}
    </nav>
  );
}

export function App() {
  const delivery = useAppStore((s) => s.delivery);
  const loading = useAppStore((s) => s.loading);
  const loadError = useAppStore((s) => s.loadError);
  const view = useAppStore((s) => s.view);
  const reset = useAppStore((s) => s.actions.reset);
  const fileInput = useRef<HTMLInputElement>(null);

  // Dev/deep-link hook: ?open=<same-origin path> loads a delivery on start;
  // ?budget= / ?mat= override the walk knobs (QA for the lazy-digest path).
  useEffect(() => {
    if (IS_VSCODE) return; // the extension pushes files instead
    const params = new URLSearchParams(window.location.search);
    const open = params.get('open');
    if (!open || open.includes('//') || open.startsWith('/')) return;
    const budget = params.get('budget');
    const mat = params.get('mat');
    void openFromUrl(open, {
      ...(budget !== null ? { eagerHashBudget: Number(budget) } : {}),
      ...(mat !== null ? { materializeEntryMax: Number(mat) } : {}),
    });
  }, []);

  // Drop anywhere in the window: the gesture every viewer should honor.
  useEffect(() => {
    const over = (e: DragEvent) => e.preventDefault();
    const drop = (e: DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer?.files?.[0];
      if (file) void openFile(file);
    };
    window.addEventListener('dragover', over);
    window.addEventListener('drop', drop);
    return () => {
      window.removeEventListener('dragover', over);
      window.removeEventListener('drop', drop);
    };
  }, []);

  const pickFile = useCallback(() => fileInput.current?.click(), []);

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-3 border-b border-slate-200 px-4 py-2 dark:border-slate-800">
        <span className="flex items-center gap-2 text-accent-600 dark:text-accent-400">
          <BrandMark />
          <span className="text-[15px] font-semibold tracking-tight">
            <span className="text-slate-900 dark:text-slate-100">OCM</span>{' '}
            <span>Lens</span>
          </span>
        </span>
        {delivery && <ViewTabs />}
        {delivery && (
          <span className="min-w-0 truncate text-xs text-slate-400" title={delivery.bundle.fileName}>
            {delivery.bundle.fileName}
          </span>
        )}
        <span className="ml-auto flex items-center gap-2">
          {delivery && (
            <>
              <button
                type="button"
                onClick={pickFile}
                className="rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
              >
                Open delivery...
              </button>
              <button
                type="button"
                onClick={reset}
                className="rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
              >
                Close
              </button>
            </>
          )}
        </span>
      </header>

      <main className="min-h-0 flex-1 overflow-auto">
        {!delivery && <EmptyState onPickFile={pickFile} />}
        {delivery && view === 'dashboard' && <Dashboard />}
        {delivery && view === 'components' && <ComponentsView />}
        {delivery && view === 'resources' && <ResourcesView />}
        {delivery && view === 'verify' && <VerifyView />}
      </main>

      <footer className="flex items-center gap-3 border-t border-slate-200 px-4 py-1.5 text-xs text-slate-400 dark:border-slate-800 dark:text-slate-500">
        {loading && <span>Reading {loading}...</span>}
        {/* A failed open must be visible even while another delivery stays
            loaded — the empty state is not rendered then. */}
        {delivery && loadError && !loading && (
          <span
            className="min-w-0 truncate text-red-600 dark:text-red-400"
            title={loadError.diagnostics.map((d) => d.message).join(' · ')}
          >
            {loadError.fileName}: {loadError.diagnostics[0]?.message ?? 'could not be opened'}
          </span>
        )}
        {delivery && !loading && (
          <span>
            {delivery.bundle.componentVersions.length} component version
            {delivery.bundle.componentVersions.length === 1 ? '' : 's'}
          </span>
        )}
        <span className="ml-auto">files never leave your machine</span>
        <span>v{APP_VERSION}</span>
      </footer>

      <input
        ref={fileInput}
        type="file"
        hidden
        accept=".ctf,.tar,.tgz,.gz,.yaml,.yml,.json"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) void openFile(file);
          e.target.value = '';
        }}
      />
    </div>
  );
}
