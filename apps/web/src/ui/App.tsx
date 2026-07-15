import clsx from 'clsx';
import { useEffect, useRef, useState } from 'react';
import { initCatalog } from '../app/catalog';
import { initProfiles } from '../app/profiles';
import { host } from '../host/adapter';
import { useVersionConflicts } from '../app/selectors';
import { useAppStore } from '../app/store';
import { DiagnosticsDrawer } from './DiagnosticsDrawer';
import { EmptyState } from './EmptyState';
import { HelpDialog, UrlDialog } from './dialogs';
import { BrandLogo, GitHubIcon, GitLabIcon, MoonIcon, SunIcon, SystemThemeIcon } from './icons';
import { BRAND, pref } from '../app/brand';
import { OpenMenu } from './OpenMenu';
import { THEME_ORDER, setThemeMode, themeMode, type ThemeMode } from './theme';
import { DropOverlay, Toasts } from './overlays';
import { SEARCH_INPUT_ID, SearchBar } from './SearchBar';
import { StatusBar } from './StatusBar';
import { DetailPane } from './detail/DetailPane';
import { ManageDocumentsDialog } from './ManageDocumentsDialog';
import { RemoveDialog } from './RemoveDialog';
import { DocumentMap } from './tree/DocumentMap';
import { WorkspaceTree } from './tree/WorkspaceTree';
import { ConflictsView } from './views/ConflictsView';
import { DiffView } from './views/DiffView';
import { InventoryView } from './views/InventoryView';
import { MapView } from './views/MapView';

const SIDEBAR_KEY = pref('sidebarWidth');

const ICON_BUTTON =
  'grid size-8 shrink-0 place-items-center rounded-md text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-300';

const THEME_LABEL: Record<ThemeMode, string> = {
  system: 'Theme: follow system',
  light: 'Theme: light',
  dark: 'Theme: dark',
};

function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(themeMode);
  const cycle = () => {
    // themeMode() is the module truth — immune to rapid-click stale state.
    const next = THEME_ORDER[(THEME_ORDER.indexOf(themeMode()) + 1) % THEME_ORDER.length]!;
    setThemeMode(next);
    setMode(next);
  };
  const Icon = mode === 'light' ? SunIcon : mode === 'dark' ? MoonIcon : SystemThemeIcon;
  return (
    <button
      type="button"
      title={`${THEME_LABEL[mode]} — click to switch`}
      aria-label={THEME_LABEL[mode]}
      onClick={cycle}
      className={ICON_BUTTON}
    >
      <Icon />
    </button>
  );
}

export function App() {
  const hasDocuments = useAppStore((s) => s.ws.documents.size > 0);
  const actions = useAppStore((s) => s.actions);

  // A deployment may ship a catalog of preconfigured SBOM sources.
  useEffect(() => {
    initProfiles();
    if (host().caps.catalog) void initCatalog();
  }, []);

  // Global shortcuts: '/' focuses search, '?' toggles help, Esc closes panels.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      const typing =
        target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT';
      if (event.key === '/' && !typing) {
        event.preventDefault();
        document.getElementById(SEARCH_INPUT_ID)?.focus();
      } else if (event.key === '?' && !typing) {
        event.preventDefault();
        useAppStore.getState().actions.setHelpOpen(!useAppStore.getState().helpOpen);
      } else if (event.key === 'Escape') {
        actions.setDiagnosticsOpen(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [actions]);

  return (
    <div className="grid h-full grid-rows-[auto_minmax(0,1fr)_auto]">
      <header className="flex h-12 shrink-0 items-center gap-3 border-b border-slate-200 px-3 dark:border-slate-800">
        <div className="flex shrink-0 items-center gap-1.5 font-semibold">
          <BrandLogo className="text-accent-600 dark:text-accent-400" />
          <span>
            {BRAND.namePrefix} <span className="text-accent-600 dark:text-accent-400">{BRAND.nameAccent}</span>
          </span>
        </div>
        <ViewSwitcher />
        <SearchBar />
        <OpenMenu />
        <ThemeToggle />
        <span className="flex shrink-0 items-center">
          <a
            href="https://gitlab.com/everbrightit-group/sbom-lens"
            target="_blank"
            rel="noreferrer"
            title="Source on GitLab"
            className={ICON_BUTTON}
          >
            <GitLabIcon />
          </a>
          <a
            href="https://github.com/EverBrightIT/SBOM-Lens"
            target="_blank"
            rel="noreferrer"
            title="Mirror on GitHub"
            className={ICON_BUTTON}
          >
            <GitHubIcon />
          </a>
        </span>
        <button
          type="button"
          title="Keyboard shortcuts (?)"
          onClick={() => actions.setHelpOpen(true)}
          className="grid size-8 shrink-0 place-items-center rounded-md border border-slate-200 text-sm text-slate-400 hover:border-slate-300 hover:text-slate-600 dark:border-slate-700 dark:hover:border-slate-600 dark:hover:text-slate-300"
        >
          ?
        </button>
      </header>

      <div className="relative min-h-0">
        {hasDocuments ? <ActiveView /> : <EmptyState />}
        <DiagnosticsDrawer />
      </div>

      <StatusBar />

      <DropOverlay />
      <Toasts />
      <HelpDialog />
      <UrlDialog />
      <RemoveDialog />
      <ManageDocumentsDialog />
    </div>
  );
}

function ActiveView() {
  const view = useAppStore((s) => s.view);
  switch (view) {
    case 'map':
      return <MapView />;
    case 'inventory':
      return <InventoryView />;
    case 'conflicts':
      return <ConflictsView />;
    case 'diff':
      return <DiffView />;
    default:
      return <Workspace />;
  }
}

const VIEWS = [
  ['explore', 'Explore'],
  ['map', 'Map'],
  ['inventory', 'Inventory'],
  ['conflicts', 'Conflicts'],
  ['diff', 'Diff'],
] as const;

function ViewSwitcher() {
  const view = useAppStore((s) => s.view);
  const hasDocuments = useAppStore((s) => s.ws.documents.size > 0);
  const actions = useAppStore((s) => s.actions);
  const conflictCount = useVersionConflicts().length;
  if (!hasDocuments) return null;

  return (
    <nav className="flex h-8 shrink-0 items-center rounded-md border border-slate-200 p-0.5 dark:border-slate-700">
      {VIEWS.map(([key, label]) => (
        <button
          key={key}
          type="button"
          onClick={() => actions.setView(key)}
          className={clsx(
            'flex h-full items-center gap-1 rounded-[5px] px-2.5 text-[12px] font-medium',
            view === key
              ? 'bg-accent-100 text-accent-900 dark:bg-accent-900/50 dark:text-accent-100'
              : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200',
          )}
        >
          {label}
          {key === 'conflicts' && conflictCount > 0 && (
            <span className="rounded-full bg-amber-100 px-1.5 text-[10px] font-semibold text-amber-800 tabular-nums dark:bg-amber-900/60 dark:text-amber-200">
              {conflictCount}
            </span>
          )}
        </button>
      ))}
    </nav>
  );
}

const SIDEBAR_MIN = 220;
const SIDEBAR_MAX = 800;
const SIDEBAR_DEFAULT = 320;
const clampSidebar = (width: number) => Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, width));

function Workspace() {
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const stored = Number(host().readPref(SIDEBAR_KEY));
    return Number.isFinite(stored) && stored > 0 ? clampSidebar(stored) : SIDEBAR_DEFAULT;
  });

  const commit = (width: number) => {
    setSidebarWidth(width);
    host().persistPref(SIDEBAR_KEY, String(width));
  };

  return (
    <div className="flex h-full min-h-0">
      <aside
        style={{ width: sidebarWidth }}
        className="flex shrink-0 flex-col border-r border-slate-200 dark:border-slate-800"
      >
        <div className="min-h-0 flex-1">
          <WorkspaceTree />
        </div>
        <DocumentMap />
      </aside>
      <SplitHandle current={sidebarWidth} onResize={setSidebarWidth} onCommit={commit} />
      <main className="min-w-0 flex-1">
        <DetailPane />
      </main>
    </div>
  );
}

/**
 * Draggable divider between tree sidebar and detail pane. Pointer capture
 * keeps the drag alive when the cursor leaves the handle; arrow keys resize
 * without a mouse; double-click resets. Width persists on release only.
 */
function SplitHandle({
  current,
  onResize,
  onCommit,
}: {
  current: number;
  onResize: (width: number) => void;
  onCommit: (width: number) => void;
}) {
  const dragging = useRef<{ startX: number; startWidth: number } | null>(null);

  const widthAt = (clientX: number) =>
    dragging.current
      ? clampSidebar(dragging.current.startWidth + clientX - dragging.current.startX)
      : current;

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize sidebar — drag, arrow keys, double-click to reset"
      aria-valuemin={SIDEBAR_MIN}
      aria-valuemax={SIDEBAR_MAX}
      aria-valuenow={current}
      tabIndex={0}
      title="Drag to resize — double-click to reset"
      className="group -mx-1 flex w-2.5 shrink-0 cursor-col-resize touch-none items-center justify-center outline-none hover:bg-accent-200/30 active:bg-accent-300/30 focus-visible:bg-accent-200/40 dark:hover:bg-accent-800/20 dark:active:bg-accent-800/30 dark:focus-visible:bg-accent-800/30"
      onPointerDown={(event) => {
        event.preventDefault();
        event.currentTarget.setPointerCapture(event.pointerId);
        dragging.current = { startX: event.clientX, startWidth: current };
      }}
      onPointerMove={(event) => {
        if (dragging.current) onResize(widthAt(event.clientX));
      }}
      onPointerUp={(event) => {
        if (!dragging.current) return;
        onCommit(widthAt(event.clientX));
        dragging.current = null;
      }}
      onPointerCancel={() => {
        dragging.current = null;
      }}
      onDoubleClick={() => onCommit(SIDEBAR_DEFAULT)}
      onKeyDown={(event) => {
        const step = event.shiftKey ? 64 : 16;
        if (event.key === 'ArrowLeft') onCommit(clampSidebar(current - step));
        else if (event.key === 'ArrowRight') onCommit(clampSidebar(current + step));
        else if (event.key === 'Home') onCommit(SIDEBAR_MIN);
        else if (event.key === 'End') onCommit(SIDEBAR_MAX);
        else return;
        event.preventDefault();
      }}
    >
      <span className="h-8 w-1 rounded-full bg-slate-200 group-hover:bg-accent-400 group-active:bg-accent-500 group-focus-visible:bg-accent-400 dark:bg-slate-700 dark:group-hover:bg-accent-500" />
    </div>
  );
}
