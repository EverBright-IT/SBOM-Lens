import { useRef, useState } from 'react';
import { loadCatalogSource } from '../app/catalog';
import { ingestFiles } from '../app/ingest';
import { useAppStore } from '../app/store';
import { loadExample } from './examples';
import { ChevronIcon } from './icons';

export function OpenMenu() {
  const [open, setOpen] = useState(false);
  const actions = useAppStore((s) => s.actions);
  const catalog = useAppStore((s) => s.catalog);
  const filesRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const profileRef = useRef<HTMLInputElement>(null);

  const item =
    'block w-full px-3 py-1.5 text-left text-[13px] hover:bg-slate-100 dark:hover:bg-slate-800';

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex h-8 items-center gap-1 rounded-md border border-slate-200 px-2.5 text-[13px] font-medium hover:border-slate-300 dark:border-slate-700 dark:hover:border-slate-600"
      >
        Open <ChevronIcon className="rotate-90 text-slate-400" />
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-30 mt-1 w-56 overflow-hidden rounded-md border border-slate-200 bg-white py-1 shadow-lg dark:border-slate-700 dark:bg-slate-900">
            <button type="button" className={item} onClick={() => { setOpen(false); filesRef.current?.click(); }}>
              Files…
            </button>
            <button type="button" className={item} onClick={() => { setOpen(false); folderRef.current?.click(); }}>
              Folder…
            </button>
            <button type="button" className={item} onClick={() => { setOpen(false); actions.openUrlDialog(); }}>
              From URL…
            </button>
            <button
              type="button"
              className={item}
              title="Import a sbomlens-profile/v1 JSON with your own minimum-elements checks"
              onClick={() => { setOpen(false); profileRef.current?.click(); }}
            >
              Compliance profile…
            </button>
            {catalog && (
              <>
                <div className="my-1 border-t border-slate-100 dark:border-slate-800" />
                <p className="px-3 pt-1 pb-0.5 text-[10px] font-medium tracking-wide text-slate-400 uppercase">
                  {catalog.title ?? 'Catalog'}
                </p>
                {catalog.sources.map((source) => (
                  <button
                    key={source.label}
                    type="button"
                    className={`${item} truncate`}
                    title={source.description}
                    onClick={() => {
                      setOpen(false);
                      void loadCatalogSource(source);
                    }}
                  >
                    {source.label}
                  </button>
                ))}
              </>
            )}
            <div className="my-1 border-t border-slate-100 dark:border-slate-800" />
            <button type="button" className={item} onClick={() => { setOpen(false); void loadExample(); }}>
              Load example
            </button>
          </div>
        </>
      )}

      <FilePickers filesRef={filesRef} folderRef={folderRef} profileRef={profileRef} />
    </div>
  );
}

export function FilePickers({
  filesRef,
  folderRef,
  profileRef,
}: {
  filesRef: React.RefObject<HTMLInputElement | null>;
  folderRef: React.RefObject<HTMLInputElement | null>;
  profileRef?: React.RefObject<HTMLInputElement | null>;
}) {
  const onChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = [...(e.target.files ?? [])];
    e.target.value = '';
    void ingestFiles(files);
  };
  return (
    <>
      <input ref={filesRef} type="file" hidden multiple accept=".spdx,.json,.yaml,.yml,.tar,.tgz,.gz,.ctf" onChange={onChange} />
      <input ref={folderRef} type="file" hidden onChange={onChange} {...({ webkitdirectory: '' } as object)} />
      {profileRef && <input ref={profileRef} type="file" hidden accept=".json" onChange={onChange} />}
    </>
  );
}
