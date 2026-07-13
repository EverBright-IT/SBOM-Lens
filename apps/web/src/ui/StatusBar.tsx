import { version } from '../../package.json';
import { BRAND } from '../app/brand';
import { fetchAllReferences } from '../app/autofetch';
import { useWorkspaceStats } from '../app/selectors';
import { useAppStore } from '../app/store';
import { LinkIcon, WarningIcon } from './icons';
import { formatCount } from './nodeInfo';

export function StatusBar() {
  const stats = useWorkspaceStats();
  const parsing = useAppStore((s) => s.parsing);
  const refFetch = useAppStore((s) => s.refFetch);
  const diagnosticsOpen = useAppStore((s) => s.diagnosticsOpen);
  const actions = useAppStore((s) => s.actions);

  const diagnosticsTotal =
    stats.diagnostics.errors + stats.diagnostics.warnings + stats.diagnostics.infos;

  return (
    <footer className="flex h-7 shrink-0 items-center gap-4 border-t border-slate-200 bg-slate-50 px-3 text-[11px] text-slate-500 tabular-nums dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400">
      <button
        type="button"
        title="Manage documents"
        onClick={() => actions.setManageOpen(true)}
        className="hover:text-slate-700 hover:underline dark:hover:text-slate-200"
      >
        {formatCount(stats.documents)} document{stats.documents === 1 ? '' : 's'}
      </button>
      <span>{formatCount(stats.packages)} packages</span>
      {stats.files > 0 && <span>{formatCount(stats.files)} files</span>}
      {stats.unresolvedStructural > 0 && (
        <span className="text-amber-600 dark:text-amber-400">
          {stats.unresolvedStructural} unresolved reference{stats.unresolvedStructural === 1 ? '' : 's'}
        </span>
      )}
      {stats.unresolvedStructural > 0 && refFetch === null && (
        <button
          type="button"
          title="Download every referenced document recursively until the cascade is complete"
          onClick={() => void fetchAllReferences()}
          className="flex items-center gap-1 rounded border border-sky-300 px-1.5 py-px font-medium text-sky-700 hover:bg-sky-50 dark:border-sky-700 dark:text-sky-300 dark:hover:bg-sky-950"
        >
          <LinkIcon width={11} height={11} /> Fetch all
        </button>
      )}

      <span className="flex-1" />

      {refFetch !== null ? (
        <span className="text-sky-600 dark:text-sky-400">
          Resolving references {refFetch.done}/{refFetch.total}…
        </span>
      ) : (
        parsing.active > 0 && (
          <span className="text-sky-600 dark:text-sky-400">
            Parsing {parsing.total - parsing.active + 1}/{parsing.total}…
          </span>
        )
      )}

      {diagnosticsTotal > 0 && (
        <button
          type="button"
          onClick={() => actions.setDiagnosticsOpen(!diagnosticsOpen)}
          className="flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-slate-200/60 dark:hover:bg-slate-800"
        >
          <WarningIcon
            className={
              stats.diagnostics.errors > 0
                ? 'text-red-500'
                : stats.diagnostics.warnings > 0
                  ? 'text-amber-500'
                  : 'text-slate-400'
            }
          />
          {formatCount(diagnosticsTotal)}
        </button>
      )}

      <span className="hidden text-slate-300 sm:inline dark:text-slate-600">
        files never leave your machine
      </span>
      <a
        href={BRAND.changelogUrl}
        target="_blank"
        rel="noreferrer"
        title={`${BRAND.name} changelog`}
        className="hover:text-slate-600 hover:underline dark:hover:text-slate-300"
      >
        v{version}
      </a>
    </footer>
  );
}
