import type { DocumentId } from '../model/ids';
import { splitRefKey } from '../workspace/resolve';
import type { WorkspaceState } from '../workspace/workspace';
import type { VersionOccurrence } from './conflicts';
import { NO_VERSION, packageKey } from './conflicts';

/**
 * Compares two cascades (a document plus everything reachable through its
 * resolved external references) package by package — the "what changed
 * between release 1.1 and 1.2" question, across document boundaries.
 */

export interface DiffSide {
  versions: string[];
  occurrences: VersionOccurrence[];
}

export interface DiffEntry {
  key: string;
  name: string;
  side: DiffSide;
}

export interface DiffChange {
  key: string;
  name: string;
  a: DiffSide;
  b: DiffSide;
}

export interface CascadeDiff {
  added: DiffEntry[];
  removed: DiffEntry[];
  changed: DiffChange[];
  unchanged: number;
  aDocCount: number;
  bDocCount: number;
}

/**
 * The document plus every document reachable via resolved refs (cycle-safe).
 * Docs in `exclude` are never entered — used by removal planning to ask
 * "what remains reachable once these documents are gone".
 */
export function reachableDocs(
  ws: WorkspaceState,
  root: DocumentId,
  exclude?: ReadonlySet<DocumentId>,
): DocumentId[] {
  const visited = new Set<DocumentId>();
  const queue: DocumentId[] = [root];
  while (queue.length > 0) {
    const docId = queue.shift()!;
    if (visited.has(docId) || !ws.documents.has(docId) || exclude?.has(docId)) continue;
    visited.add(docId);
    for (const [key, resolution] of ws.resolutions) {
      if (resolution.status !== 'resolved') continue;
      if (splitRefKey(key).docId !== docId) continue;
      if (!visited.has(resolution.targetDocId)) queue.push(resolution.targetDocId);
    }
  }
  return [...visited];
}

interface SideEntry {
  name: string;
  versions: Set<string>;
  occurrences: VersionOccurrence[];
}

function collectSide(ws: WorkspaceState, docIds: readonly DocumentId[]): Map<string, SideEntry> {
  const entries = new Map<string, SideEntry>();
  for (const docId of docIds) {
    const loaded = ws.documents.get(docId);
    if (!loaded) continue;
    for (const element of loaded.document.elements) {
      if (element.kind !== 'package') continue;
      const key = packageKey(element);
      let entry = entries.get(key);
      if (!entry) {
        entry = { name: element.name, versions: new Set(), occurrences: [] };
        entries.set(key, entry);
      }
      entry.versions.add(element.version ?? NO_VERSION);
      entry.occurrences.push({ element, docId, docName: loaded.document.name });
    }
  }
  return entries;
}

export function diffCascades(ws: WorkspaceState, aRoot: DocumentId, bRoot: DocumentId): CascadeDiff {
  const aDocs = reachableDocs(ws, aRoot);
  const bDocs = reachableDocs(ws, bRoot);
  const a = collectSide(ws, aDocs);
  const b = collectSide(ws, bDocs);

  const added: DiffEntry[] = [];
  const removed: DiffEntry[] = [];
  const changed: DiffChange[] = [];
  let unchanged = 0;

  for (const [key, entry] of b) {
    if (!a.has(key)) added.push({ key, name: entry.name, side: toSide(entry) });
  }
  for (const [key, entry] of a) {
    const other = b.get(key);
    if (!other) {
      removed.push({ key, name: entry.name, side: toSide(entry) });
    } else if (!sameVersions(entry.versions, other.versions)) {
      changed.push({ key, name: entry.name, a: toSide(entry), b: toSide(other) });
    } else {
      unchanged++;
    }
  }

  const byName = (x: { name: string }, y: { name: string }) => x.name.localeCompare(y.name);
  added.sort(byName);
  removed.sort(byName);
  changed.sort(byName);
  return { added, removed, changed, unchanged, aDocCount: aDocs.length, bDocCount: bDocs.length };
}

function toSide(entry: SideEntry): DiffSide {
  return {
    versions: [...entry.versions].sort((x, y) => x.localeCompare(y, undefined, { numeric: true })),
    occurrences: entry.occurrences,
  };
}

function sameVersions(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

/** Human-readable summary, e.g. for release notes. */
export function diffToMarkdown(diff: CascadeDiff, aName: string, bName: string): string {
  const lines = [
    `## SBOM diff: ${aName} → ${bName}`,
    '',
    `${diff.added.length} added · ${diff.removed.length} removed · ${diff.changed.length} version-changed · ${diff.unchanged} unchanged`,
    '',
  ];
  const section = (title: string, entries: readonly DiffEntry[]) => {
    if (entries.length === 0) return;
    lines.push(`### ${title} (${entries.length})`, '');
    for (const entry of entries) lines.push(`- **${entry.name}** ${entry.side.versions.join(' / ')}`);
    lines.push('');
  };
  section('Added', diff.added);
  section('Removed', diff.removed);
  if (diff.changed.length > 0) {
    lines.push(`### Version changes (${diff.changed.length})`, '');
    for (const change of diff.changed) {
      lines.push(`- **${change.name}** ${change.a.versions.join(' / ')} → ${change.b.versions.join(' / ')}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}
