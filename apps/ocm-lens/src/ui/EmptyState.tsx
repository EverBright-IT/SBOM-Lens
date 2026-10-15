import { openDemo, openSbomDemo } from '../app/ingest';
import { useAppStore } from '../app/store';
import { BrandMark } from './App';

export function EmptyState({ onPickFile }: { onPickFile: () => void }) {
  const loading = useAppStore((s) => s.loading);
  const loadError = useAppStore((s) => s.loadError);

  return (
    <div className="flex h-full items-center justify-center px-6">
      <div className="max-w-xl text-center">
        <div className="mb-3 flex justify-center text-accent-600 dark:text-accent-400">
          <BrandMark size={44} />
        </div>
        <h1 className="text-xl font-semibold">OCM Lens</h1>
        <p className="mx-auto mt-2 max-w-md text-sm text-slate-500 dark:text-slate-400">
          Drop an OCM delivery anywhere in this window: a CTF (<code>.ctf</code>/<code>.tar</code>/
          <code>.tgz</code>), a component archive, or a bare component descriptor. You get the
          delivery as one picture: components, artifacts, completeness, signatures.
        </p>
        <div className="mt-5 flex justify-center gap-2">
          <button
            type="button"
            onClick={onPickFile}
            className="rounded border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-200 dark:hover:border-accent-700 dark:hover:text-accent-400"
          >
            Open delivery
          </button>
          <button
            type="button"
            onClick={() => void openDemo()}
            disabled={loading !== null}
            className="rounded bg-accent-600 px-3 py-1.5 text-sm text-white hover:bg-accent-700 disabled:opacity-50"
          >
            {loading ? 'Loading...' : 'Load demo delivery'}
          </button>
          <button
            type="button"
            onClick={() => void openSbomDemo()}
            disabled={loading !== null}
            title="A delivery whose SBOMs show every binding level: by digest, by reference, by component, external, missing"
            className="rounded border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:border-accent-300 hover:text-accent-700 disabled:opacity-50 dark:border-slate-700 dark:text-slate-200 dark:hover:border-accent-700 dark:hover:text-accent-400"
          >
            SBOM demo
          </button>
        </div>
        {loadError && (
          <div className="mx-auto mt-5 max-w-md rounded border border-red-200 p-3 text-left text-xs dark:border-red-900">
            <div className="font-medium text-red-700 dark:text-red-400">
              {loadError.fileName} could not be opened as a delivery
            </div>
            <ul className="mt-1 space-y-0.5 text-slate-500 dark:text-slate-400">
              {loadError.diagnostics.slice(0, 5).map((d, i) => (
                <li key={i}>{d.message}</li>
              ))}
            </ul>
          </div>
        )}
        <p className="mt-6 text-xs text-slate-400 dark:text-slate-500">
          Everything is parsed locally in your browser. Files never leave your machine.
        </p>
      </div>
    </div>
  );
}
