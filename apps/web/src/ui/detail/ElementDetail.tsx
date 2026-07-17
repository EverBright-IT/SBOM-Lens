import type { LoadedDocument, SbomElement, WorkspaceState } from '@sbomlens/core';
import { collectElementSubtree, makeElementId } from '@sbomlens/core';
import { HAS_DELIVERIES } from '../../app/brand';
import { useAppStore } from '../../app/store';
import { revealElement, selectTarget } from '../navigate';
import { RevealIcon } from '../icons';
import { CopyButton, FieldRow, Section } from './FieldRow';
import { OcmElementSections } from './OcmSections';
import { RelationshipList } from './RelationshipList';
import { VexElementSection } from './VexSection';
import { docsFor } from './specDocs';

const FILE_LIST_CAP = 200;

export function ElementDetail({
  ws,
  element,
  loaded,
  hasTreePath,
}: {
  ws: WorkspaceState;
  element: SbomElement;
  loaded: LoadedDocument;
  hasTreePath: boolean;
}) {
  const containedFiles = filesContained(loaded, element);
  const D = docsFor(loaded.document);
  const P = D.package;
  const F = D.file;
  const isFile = element.kind === 'file';

  return (
    <div className="space-y-3">
      <Section title="Details">
        <FieldRow label="Version" value={element.version} info={P.versionInfo} />
        <FieldRow label="Purpose" value={element.purpose} info={P.primaryPackagePurpose} />
        <FieldRow label="Supplier" value={element.supplier} info={P.supplier} />
        <FieldRow label="Originator" value={element.originator} info={P.originator} />
        <FieldRow
          label="Download location"
          value={element.downloadLocation}
          mono
          info={P.downloadLocation}
        />
        <FieldRow
          label="License concluded"
          value={element.licenseConcluded}
          info={(isFile ? F : P).licenseConcluded}
        />
        <FieldRow label="License declared" value={element.licenseDeclared} info={P.licenseDeclared} />
        <FieldRow
          label="Copyright"
          value={element.copyright}
          info={(isFile ? F : P).copyrightText}
        />
        <FieldRow label="Description" value={element.description} info={P.description} />
        <FieldRow label="Comment" value={element.comment} info={(isFile ? F : P).comment} />
        <FieldRow label="SPDXID" value={element.spdxId} mono copyable info={P.SPDXID} />
        <FieldRow label="Document" value={loaded.document.name} />
      </Section>

      <VexElementSection elementId={element.id} />

      {element.purl && (
        <Section title="Package URL">
          <div className="flex items-center gap-1 font-mono text-xs break-all text-accent-700 dark:text-accent-400">
            {element.purl}
            <CopyButton text={element.purl} />
          </div>
        </Section>
      )}

      {element.externalRefs && element.externalRefs.length > 0 && (
        <Section
          title={`External references (${element.externalRefs.length})`}
          info={P.externalRefs}
        >
          <div className="space-y-1">
            {element.externalRefs.map((ref, i) => (
              <div key={i} className="flex items-baseline gap-2 text-xs">
                <span className="shrink-0 text-slate-400 dark:text-slate-500">{ref.type}</span>
                <span className="min-w-0 font-mono break-all text-slate-600 dark:text-slate-300">
                  {ref.locator}
                </span>
                <CopyButton text={ref.locator} />
              </div>
            ))}
          </div>
        </Section>
      )}

      {element.checksums && element.checksums.length > 0 && !element.ocm && (
        <Section title="Checksums" info={(isFile ? F : P).checksums}>
          {element.checksums.map((c, i) => (
            <div key={i} className="flex items-baseline gap-2 font-mono text-xs">
              <span className="w-16 shrink-0 text-slate-400 dark:text-slate-500">{c.algorithm}</span>
              <span className="break-all text-slate-600 dark:text-slate-300">{c.value}</span>
              <CopyButton text={c.value} />
            </div>
          ))}
        </Section>
      )}

      {HAS_DELIVERIES && <OcmElementSections element={element} />}

      <RelationshipList ws={ws} loaded={loaded} spdxId={element.spdxId} />

      {containedFiles.length > 0 && (
        <Section title={`Files (${containedFiles.length})`}>
          <div className="max-h-64 space-y-px overflow-auto">
            {containedFiles.slice(0, FILE_LIST_CAP).map((file) => (
              <button
                key={file.spdxId}
                type="button"
                onClick={() => selectTarget({ kind: 'element', elementId: file.id })}
                className="block w-full truncate text-left font-mono text-xs text-slate-500 hover:text-accent-700 dark:text-slate-400 dark:hover:text-accent-400"
              >
                {file.name}
              </button>
            ))}
            {containedFiles.length > FILE_LIST_CAP && (
              <p className="pt-1 text-xs text-slate-400">
                … and {containedFiles.length - FILE_LIST_CAP} more (use search to narrow down)
              </p>
            )}
          </div>
        </Section>
      )}

      <div className="flex flex-wrap gap-2">
        {element.kind === 'package' && <SubtreeInventoryButton ws={ws} element={element} loaded={loaded} />}
        {!hasTreePath && (
          <button
            type="button"
            onClick={() => revealElement(makeElementId(loaded.document.id, element.spdxId))}
            className="inline-flex items-center gap-1.5 rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
          >
            <RevealIcon /> Reveal in tree
          </button>
        )}
      </div>
    </div>
  );
}

function SubtreeInventoryButton({
  ws,
  element,
  loaded,
}: {
  ws: WorkspaceState;
  element: SbomElement;
  loaded: LoadedDocument;
}) {
  const actions = useAppStore((s) => s.actions);
  return (
    <button
      type="button"
      title="Filter the Inventory to this package and everything reachable below it, across resolved sub-SBOM boundaries"
      onClick={() => {
        const rootId = makeElementId(loaded.document.id, element.spdxId);
        const { ids, capped } = collectElementSubtree(ws, rootId);
        const rootLabel = element.version ? `${element.name} ${element.version}` : element.name;
        actions.setInventoryScope({ rootId, rootLabel, ids, capped });
        actions.setView('inventory');
        actions.toast(
          `Inventory scoped to ${ids.size} sub-component${ids.size === 1 ? '' : 's'} of ${rootLabel}` +
            (capped ? ' (capped)' : ''),
          'info',
        );
      }}
      className="rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
    >
      Show sub-components in Inventory
    </button>
  );
}

function filesContained(loaded: LoadedDocument, element: SbomElement): SbomElement[] {
  if (element.kind !== 'package') return [];
  const edges = loaded.indexes.outgoing.get(element.spdxId) ?? [];
  const files: SbomElement[] = [];
  for (const edge of edges) {
    if (edge.type !== 'CONTAINS' || edge.to.kind !== 'local') continue;
    const index = loaded.indexes.elementBySpdxId.get(edge.to.spdxId);
    if (index === undefined) continue;
    const target = loaded.document.elements[index]!;
    if (target.kind === 'file') files.push(target);
  }
  return files;
}
