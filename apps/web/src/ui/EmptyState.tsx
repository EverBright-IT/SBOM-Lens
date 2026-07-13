import { useRef } from 'react';
import { BRAND } from '../app/brand';
import { loadCatalogSource } from '../app/catalog';
import { useAppStore } from '../app/store';
import { loadExample } from './examples';
import { BrandLogo, DocumentIcon } from './icons';
import { FilePickers } from './OpenMenu';

export function EmptyState() {
  const actions = useAppStore((s) => s.actions);
  const catalog = useAppStore((s) => s.catalog);
  const filesRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);

  const button =
    'rounded-md border border-slate-200 px-3 py-1.5 text-[13px] font-medium text-slate-600 hover:border-sky-300 hover:text-sky-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-sky-700 dark:hover:text-sky-300';

  return (
    <div className="grid h-full place-items-center p-6">
      <div className="max-w-md text-center">
        <BrandLogo width={40} height={40} className="mx-auto text-sky-600 dark:text-sky-400" />
        <h1 className="mt-4 text-xl font-semibold">{BRAND.name}</h1>
        <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400">{BRAND.emptyStateHint}</p>

        <div className="mt-5 flex flex-wrap justify-center gap-2">
          <button type="button" className={button} onClick={() => filesRef.current?.click()}>
            Open files
          </button>
          <button type="button" className={button} onClick={() => folderRef.current?.click()}>
            Open folder
          </button>
          <button type="button" className={button} onClick={() => actions.openUrlDialog()}>
            From URL
          </button>
          <button
            type="button"
            className="rounded-md bg-sky-600 px-3 py-1.5 text-[13px] font-medium text-white hover:bg-sky-700"
            onClick={() => void loadExample()}
          >
            Load example
          </button>
        </div>

        {catalog && (
          <div className="mt-7 text-left">
            <h2 className="mb-2 text-center text-[11px] font-medium tracking-wide text-slate-400 uppercase">
              {catalog.title ?? BRAND.catalogHeading}
            </h2>
            <div className="space-y-1.5">
              {catalog.sources.map((source) => (
                <button
                  key={source.label}
                  type="button"
                  onClick={() => void loadCatalogSource(source)}
                  className="flex w-full items-center gap-2.5 rounded-md border border-slate-200 px-3 py-2 text-left hover:border-sky-300 dark:border-slate-700 dark:hover:border-sky-700"
                >
                  <DocumentIcon className="shrink-0 text-sky-600 dark:text-sky-400" />
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] font-medium">{source.label}</span>
                    {source.description && (
                      <span className="block truncate text-xs text-slate-400">{source.description}</span>
                    )}
                  </span>
                  <span className="ml-auto shrink-0 text-[11px] text-slate-400">
                    {source.urls.length} file{source.urls.length === 1 ? '' : 's'}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

        <p className="mt-6 text-xs text-slate-400 dark:text-slate-500">
          {BRAND.formatsNote}
          <br />
          Everything is parsed locally in your browser — files never leave your machine.
        </p>

        <FilePickers filesRef={filesRef} folderRef={folderRef} />
      </div>
    </div>
  );
}
