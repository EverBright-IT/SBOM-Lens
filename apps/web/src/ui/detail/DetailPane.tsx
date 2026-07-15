import clsx from 'clsx';
import { Fragment } from 'react';
import { PATH_SEP } from '@sbomlens/core';
import { useAppStore } from '../../app/store';
import { describeTarget, lookupDoc, lookupElement, targetFromKey } from '../nodeInfo';
import { Chip } from './FieldRow';
import { DocumentDetail } from './DocumentDetail';
import { ElementDetail } from './ElementDetail';
import { PlaceholderDetail } from './PlaceholderDetail';
import { SourceView } from './SourceView';

export function DetailPane() {
  const ws = useAppStore((s) => s.ws);
  const selection = useAppStore((s) => s.selection);
  const detailTab = useAppStore((s) => s.detailTab);
  const actions = useAppStore((s) => s.actions);

  if (!selection) {
    return (
      <div className="grid h-full place-items-center text-sm text-slate-400 dark:text-slate-600">
        Select a node to inspect it — or press / to search.
      </div>
    );
  }

  const { target } = selection;
  const info = describeTarget(ws, target);
  const hasSource = target.kind !== 'placeholder';

  return (
    <div className="flex h-full min-w-0 flex-col">
      <header className="shrink-0 border-b border-slate-100 px-4 pt-3 pb-0 dark:border-slate-800/80">
        {selection.path && <Breadcrumb path={selection.path} />}
        <div className="flex items-baseline gap-2">
          <h2 className="truncate text-lg font-semibold">{info.title}</h2>
          {info.version && (
            <span className="shrink-0 font-mono text-sm text-slate-400">{info.version}</span>
          )}
          {target.kind === 'element' && (() => {
            const found = lookupElement(ws, target.elementId);
            return found ? (
              <span className="flex shrink-0 gap-1">
                <Chip>{found.element.kind}</Chip>
                {found.element.purpose && <Chip>{found.element.purpose}</Chip>}
              </span>
            ) : null;
          })()}
          {target.kind === 'document' && <Chip tone="accent">document</Chip>}
          {target.kind === 'document' &&
            ws.documents.get(target.docId)?.document.spec.model === 'ocm' && (
              <Chip tone="accent">component version</Chip>
            )}
        </div>

        <nav className="mt-2 flex gap-4 text-[13px]">
          {(['overview', 'source'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              disabled={tab === 'source' && !hasSource}
              onClick={() => actions.setDetailTab(tab)}
              className={clsx(
                '-mb-px border-b-2 pb-1.5 capitalize disabled:opacity-40',
                detailTab === tab
                  ? 'border-accent-500 font-medium text-accent-700 dark:text-accent-300'
                  : 'border-transparent text-slate-400 hover:text-slate-600 dark:hover:text-slate-300',
              )}
            >
              {tab}
            </button>
          ))}
        </nav>
      </header>

      <div className={clsx('min-h-0 flex-1', detailTab === 'overview' && 'overflow-auto p-4')}>
        {detailTab === 'source' ? (
          <SourceView ws={ws} target={target} />
        ) : (
          <OverviewBody hasTreePath={selection.path !== null} />
        )}
      </div>
    </div>
  );
}

function OverviewBody({ hasTreePath }: { hasTreePath: boolean }) {
  const ws = useAppStore((s) => s.ws);
  const selection = useAppStore((s) => s.selection);
  if (!selection) return null;
  const { target } = selection;

  switch (target.kind) {
    case 'document': {
      const loaded = lookupDoc(ws, target.docId);
      return loaded ? <DocumentDetail ws={ws} loaded={loaded} /> : <Missing />;
    }
    case 'element':
    case 'cycle': {
      const found = lookupElement(ws, target.elementId);
      return found ? (
        <ElementDetail ws={ws} element={found.element} loaded={found.loaded} hasTreePath={hasTreePath} />
      ) : (
        <Missing />
      );
    }
    case 'placeholder':
      return <PlaceholderDetail ws={ws} target={target} />;
    case 'extraRefs': {
      const loaded = lookupDoc(ws, target.docId);
      return loaded ? (
        <div>
          <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">
            External documents referenced by <strong>{loaded.document.name}</strong> without any
            relationship — typically scan reports or attestations.
          </p>
          <DocumentDetail ws={ws} loaded={loaded} />
        </div>
      ) : (
        <Missing />
      );
    }
  }
}

function Breadcrumb({ path }: { path: string }) {
  const ws = useAppStore((s) => s.ws);
  const actions = useAppStore((s) => s.actions);
  const keys = path.split(PATH_SEP);

  return (
    <div className="mb-1 flex min-w-0 items-center gap-1 overflow-hidden text-xs text-slate-400 dark:text-slate-500">
      {keys.map((key, i) => {
        const target = targetFromKey(key);
        const title = target ? describeTarget(ws, target).title : '…';
        const prefixPath = keys.slice(0, i + 1).join(PATH_SEP);
        const isLast = i === keys.length - 1;
        return (
          <Fragment key={i}>
            {i > 0 && <span className="shrink-0 text-slate-300 dark:text-slate-700">›</span>}
            {isLast || !target ? (
              <span className="max-w-40 truncate">{title}</span>
            ) : (
              <button
                type="button"
                className="max-w-40 truncate hover:text-accent-700 hover:underline dark:hover:text-accent-400"
                onClick={() => actions.select({ path: prefixPath, target })}
              >
                {title}
              </button>
            )}
          </Fragment>
        );
      })}
    </div>
  );
}

function Missing() {
  return <p className="text-sm text-slate-400">This node is no longer in the workspace.</p>;
}
