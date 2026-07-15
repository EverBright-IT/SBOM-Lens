import clsx from 'clsx';
import { useEffect, useRef, useState } from 'react';
import { useSearchResults } from '../app/selectors';
import { useAppStore } from '../app/store';
import { FacetChips } from './FacetChips';
import { revealElement } from './navigate';
import { FileIcon, FunnelIcon, PackageIcon, SearchIcon } from './icons';
import { formatCount } from './nodeInfo';

export const SEARCH_INPUT_ID = 'sbomlens-search';

const PLACEHOLDERS = {
  explore: 'Search packages across all documents…',
  map: 'Highlight documents in the map…',
  inventory: 'Filter the inventory…',
  conflicts: 'Search packages across all documents…',
  diff: 'Search packages across all documents…',
} as const;

export function SearchBar() {
  const query = useAppStore((s) => s.query);
  const view = useAppStore((s) => s.view);
  const treeFilter = useAppStore((s) => s.treeFilter);
  const actions = useAppStore((s) => s.actions);
  const [value, setValue] = useState(query);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Debounce keystrokes into the store query.
  useEffect(() => {
    const handle = setTimeout(() => actions.setQuery(value), 120);
    return () => clearTimeout(handle);
  }, [value, actions]);

  useEffect(() => {
    if (query === '') setValue('');
  }, [query]);

  // The results dropdown belongs to the explore view; in the other views the
  // query filters the view itself. With the in-place tree filter on, the tree
  // takes over and the dropdown stays closed.
  const open = view === 'explore' && !treeFilter && query.trim() !== '';
  const { hits, total } = useSearchResults(open ? query.trim() : '');

  useEffect(() => setActiveIndex(0), [query]);

  const pick = (index: number) => {
    const hit = hits[index];
    if (!hit) return;
    revealElement(hit.element.id);
    actions.setQuery('');
    setValue('');
    inputRef.current?.blur();
  };

  return (
    <div className="relative min-w-0 flex-1">
      <div className="flex h-8 items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-2.5 focus-within:border-accent-400 focus-within:ring-2 focus-within:ring-accent-100 dark:border-slate-700 dark:bg-slate-900 dark:focus-within:border-accent-600 dark:focus-within:ring-accent-950">
        <SearchIcon className="shrink-0 text-slate-400" />
        <input
          id={SEARCH_INPUT_ID}
          ref={inputRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              actions.setQuery('');
              setValue('');
              inputRef.current?.blur();
              return;
            }
            if (e.key === 'Enter' && view === 'explore' && treeFilter) {
              // Hand the keyboard over to the filtered tree.
              e.preventDefault();
              document.querySelector<HTMLElement>('[role="tree"]')?.focus();
              return;
            }
            if (!open) return;
            if (e.key === 'ArrowDown') {
              e.preventDefault();
              setActiveIndex((i) => Math.min(i + 1, hits.length - 1));
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              setActiveIndex((i) => Math.max(i - 1, 0));
            } else if (e.key === 'Enter') {
              e.preventDefault();
              pick(activeIndex);
            }
          }}
          placeholder={PLACEHOLDERS[view]}
          spellCheck={false}
          autoComplete="off"
          className="min-w-0 flex-1 bg-transparent text-[13px] outline-none placeholder:text-slate-400"
        />
        {view === 'explore' && (
          <button
            type="button"
            title={
              treeFilter
                ? 'Tree filter on — matches shown in place. Click for the results dropdown.'
                : 'Filter the tree in place instead of the results dropdown'
            }
            aria-pressed={treeFilter}
            onClick={() => {
              actions.setTreeFilter(!treeFilter);
              inputRef.current?.focus();
            }}
            className={clsx(
              'shrink-0 rounded p-0.5',
              treeFilter
                ? 'bg-accent-100 text-accent-700 dark:bg-accent-900/50 dark:text-accent-300'
                : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-300',
            )}
          >
            <FunnelIcon />
          </button>
        )}
        {!open && value === '' && (
          <kbd className="rounded border border-slate-200 px-1 font-mono text-[10px] text-slate-400 dark:border-slate-700">
            /
          </kbd>
        )}
      </div>

      {open && (
        <div
          className="absolute inset-x-0 top-9 z-30 overflow-hidden rounded-md border border-slate-200 bg-white shadow-lg dark:border-slate-700 dark:bg-slate-900"
          onMouseDown={(e) => e.preventDefault() /* keep input focus */}
        >
          <div className="border-b border-slate-100 px-3 py-2 dark:border-slate-800">
            <FacetChips />
          </div>
          <div className="max-h-80 overflow-auto">
            {hits.length === 0 && (
              <p className="px-3 py-4 text-center text-xs text-slate-400">No matches.</p>
            )}
            {hits.slice(0, 100).map((hit, i) => {
              const doc = useAppStore.getState().ws.documents.get(hit.docId);
              const Icon = hit.element.kind === 'file' ? FileIcon : PackageIcon;
              return (
                <button
                  key={hit.element.id}
                  type="button"
                  onClick={() => pick(i)}
                  onMouseEnter={() => setActiveIndex(i)}
                  className={clsx(
                    'flex w-full items-center gap-2 px-3 py-1.5 text-left text-[13px]',
                    i === activeIndex && 'bg-accent-50 dark:bg-accent-900/30',
                  )}
                >
                  <Icon className="shrink-0 text-slate-400" />
                  <span className="truncate">{hit.element.name}</span>
                  {hit.element.version && (
                    <span className="shrink-0 font-mono text-[11px] text-slate-400">
                      {hit.element.version}
                    </span>
                  )}
                  <span className="min-w-0 flex-1" />
                  <span className="max-w-40 shrink-0 truncate text-[11px] text-slate-400 dark:text-slate-500">
                    {doc?.document.name}
                  </span>
                </button>
              );
            })}
          </div>
          <div className="border-t border-slate-100 px-3 py-1.5 text-[11px] text-slate-400 dark:border-slate-800">
            {formatCount(total)} match{total === 1 ? '' : 'es'}
            {total > 100 && ' — refine the query to narrow down'}
          </div>
        </div>
      )}
    </div>
  );
}
