import { useMemo } from 'react';
import type { DocumentId, LoadedDocument, ProfileCheckResult, WorkspaceState } from '@sbomlens/core';
import {
  documentIssues,
  evaluateProfile,
  profileReportToMarkdown,
  reachableDocs,
  refKey,
} from '@sbomlens/core';
import { HAS_DELIVERIES } from '../../app/brand';
import {
  builtinProfileName,
  extraBuiltinProfiles,
  removeProfile,
  setActiveProfile,
  useActiveProfile,
} from '../../app/profiles';
import { useAppStore } from '../../app/store';
import { host } from '../../host/adapter';
import { CheckIcon, CloseIcon } from '../icons';
import { selectTarget } from '../navigate';
import { formatBytes, formatCount } from '../nodeInfo';
import { Chip, FieldRow, Section } from './FieldRow';
import { OcmDocumentSections } from './OcmSections';
import { VexDocumentsSection } from './VexSection';
import { AcceptanceReportSection } from './AcceptanceSection';
import { docsFor } from './specDocs';

export function DocumentDetail({ ws, loaded }: { ws: WorkspaceState; loaded: LoadedDocument }) {
  const actions = useAppStore((s) => s.actions);
  const doc = loaded.document;
  const D = docsFor(doc).document;
  const diagnosticCount = doc.diagnostics.length;

  return (
    <div className="space-y-3">
      <Section title="Document">
        <FieldRow
          label="Namespace"
          value={doc.namespace ?? undefined}
          mono
          copyable
          info={D.documentNamespace}
        />
        <FieldRow
          label="Spec"
          value={`${doc.spec.version} (${doc.spec.serialization})`}
          info={D.spdxVersion}
        />
        <FieldRow label="Created" value={doc.created} info={D.created} />
        <FieldRow
          label="Creators"
          value={doc.creators.join(' · ') || undefined}
          info={D.creators}
        />
        <FieldRow label="Data license" value={doc.dataLicense} info={D.dataLicense} />
        <FieldRow label="Comment" value={doc.comment} info={D.comment} />
        <FieldRow
          label="Contents"
          value={`${formatCount(loaded.indexes.packageCount)} packages · ${formatCount(loaded.indexes.fileCount)} files · ${formatCount(doc.relationships.length)} relationships`}
        />
        <FieldRow
          label="Source file"
          value={`${loaded.source.fileName} (${formatBytes(loaded.source.byteSize)})`}
        />
        <FieldRow label="SHA-1" value={loaded.source.sha1} mono copyable />
        {diagnosticCount > 0 && (
          <div className="grid grid-cols-[9rem_1fr] items-baseline gap-x-3 py-1">
            <div className="text-xs text-slate-400 dark:text-slate-500">Diagnostics</div>
            <button
              type="button"
              className="w-fit text-[13px] text-amber-700 hover:underline dark:text-amber-400"
              onClick={() => actions.setDiagnosticsOpen(true)}
            >
              {diagnosticCount} parser note{diagnosticCount === 1 ? '' : 's'}
            </button>
          </div>
        )}
      </Section>

      {HAS_DELIVERIES && <OcmDocumentSections doc={doc} />}

      {doc.externalDocumentRefs.length > 0 && (
        <Section
          title={`External documents (${doc.externalDocumentRefs.length})`}
          info={D.externalDocumentRefs}
        >
          <div className="space-y-1.5">
            {doc.externalDocumentRefs.map((ref) => (
              <ExternalRefRow key={ref.docRef} ws={ws} docId={doc.id} docRef={ref.docRef} uri={ref.uri} />
            ))}
          </div>
        </Section>
      )}

      <QualitySection ws={ws} loaded={loaded} />

      <VexDocumentsSection />
      <AcceptanceReportSection />

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          title="Show every package of this document and all documents reachable through its resolved references"
          onClick={() => {
            const cascade = reachableDocs(ws, doc.id);
            actions.setFacetDocs(cascade);
            actions.setView('inventory');
            actions.toast(
              `Inventory filtered to ${cascade.length} document${cascade.length === 1 ? '' : 's'} of this cascade`,
              'info',
            );
          }}
          className="rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-300 dark:hover:border-accent-700 dark:hover:text-accent-400"
        >
          Show cascade in Inventory
        </button>
        <button
          type="button"
          onClick={() => actions.requestRemoval([doc.id])}
          className="rounded border border-slate-200 px-2 py-1 text-xs text-slate-500 hover:border-red-300 hover:text-red-700 dark:border-slate-700 dark:text-slate-400 dark:hover:border-red-800 dark:hover:text-red-400"
        >
          Remove from workspace…
        </button>
      </div>
    </div>
  );
}

/** Factual coverage against the active compliance profile — no invented score. */
function QualitySection({ ws, loaded }: { ws: WorkspaceState; loaded: LoadedDocument }) {
  const actions = useAppStore((s) => s.actions);
  const profiles = useAppStore((s) => s.profiles);
  const activeProfileId = useAppStore((s) => s.activeProfileId);
  const profile = useActiveProfile(loaded.document.spec.model);
  const report = useMemo(() => evaluateProfile(ws, loaded, profile), [ws, loaded, profile]);
  const issues = useMemo(() => documentIssues(ws, loaded), [ws, loaded]);
  if (report.packagesTotal === 0) return null;

  const booleans = report.results.filter((r) => r.kind === 'boolean');
  const coverages = report.results.filter((r) => r.coverage);
  const issueParts = [
    issues.unresolvedStructuralRefs > 0 &&
      `${issues.unresolvedStructuralRefs} unresolved external reference(s)`,
    issues.danglingLocalRefs > 0 && `${issues.danglingLocalRefs} dangling relationship target(s)`,
    issues.duplicateSpdxIds > 0 && `${issues.duplicateSpdxIds} duplicate SPDXID(s)`,
  ].filter(Boolean);

  const exportReport = () => {
    const stamp = new Date().toISOString().slice(0, 10);
    host().exportFile(
      `sbom-quality-${stamp}.md`,
      'text/markdown',
      profileReportToMarkdown(report, {
        docName: loaded.document.name,
        sourceFileName: loaded.source.fileName,
        issues,
        generatedAt: stamp,
      }),
    );
  };

  const extraBuiltins = extraBuiltinProfiles(loaded.document.spec.model);
  // The active id may not resolve for THIS document's model (a BSI builtin
  // on an OCM descriptor, a catalog profile not yet loaded) — the report
  // falls back to the model builtin, so the select must show that too
  // instead of rendering blank.
  const selectableIds = new Set([...extraBuiltins.map((b) => b.id), ...profiles.map((p) => p.id)]);
  const selectValue = activeProfileId && selectableIds.has(activeProfileId) ? activeProfileId : 'builtin';
  const sectionActions = (
    <>
      {(profiles.length > 0 || extraBuiltins.length > 0) && (
        <select
          value={selectValue}
          onChange={(e) => setActiveProfile(e.target.value === 'builtin' ? null : e.target.value)}
          className="max-w-44 rounded border border-slate-200 bg-transparent px-1 py-0.5 text-[11px] text-slate-600 outline-none focus:border-accent-400 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
        >
          <option value="builtin">{builtinProfileName(loaded.document.spec.model)}</option>
          {extraBuiltins.map((b) => (
            <option key={b.id} value={b.id}>
              {b.profile.name}
            </option>
          ))}
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.profile.name}
              {p.origin === 'catalog' ? ' · catalog' : ''}
            </option>
          ))}
        </select>
      )}
      {activeProfileId !== null && !activeProfileId.startsWith('builtin:') && (
        <button
          type="button"
          title="Remove this imported profile"
          onClick={() => {
            removeProfile(activeProfileId);
            actions.toast('Profile removed. Back to the builtin profile', 'info');
          }}
          className="rounded px-1 text-slate-400 hover:text-red-600 dark:hover:text-red-400"
        >
          ×
        </button>
      )}
      <button
        type="button"
        title="Export this report as Markdown"
        onClick={exportReport}
        className="rounded border border-slate-200 px-1.5 py-0.5 text-[10px] text-slate-500 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-400 dark:hover:border-accent-700 dark:hover:text-accent-400"
      >
        Export
      </button>
    </>
  );

  return (
    <Section title={`Quality: ${report.profileName}`} actions={sectionActions}>
      {report.gatedFailed > 0 && (
        <p className="mb-2 text-xs text-amber-700 dark:text-amber-400">
          {report.gatedFailed} of {report.gatedPassed + report.gatedFailed} gated checks failing
        </p>
      )}
      <div className="grid gap-x-8 gap-y-0.5 sm:grid-cols-2">
        {booleans.map((result) => (
          <div key={result.id} className="flex items-center gap-1.5 text-xs" title={result.actual}>
            {result.pass ? (
              <CheckIcon className="shrink-0 text-emerald-500" />
            ) : (
              <CloseIcon className="shrink-0 text-amber-500" />
            )}
            <span className={result.pass ? 'text-slate-600 dark:text-slate-300' : 'text-slate-400'}>
              {result.label}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-1.5">
        {coverages.map((result) => (
          <Meter key={result.id} result={result} />
        ))}
      </div>
      <p className="mt-2 text-[11px] text-slate-400">
        Across {formatCount(report.packagesTotal)} package{report.packagesTotal === 1 ? '' : 's'} in this document.
      </p>
      {issueParts.length > 0 && (
        <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">{issueParts.join(' · ')}</p>
      )}
    </Section>
  );
}

function Meter({ result }: { result: ProfileCheckResult }) {
  const { satisfied, total, percent, threshold } = result.coverage!;
  const gated = threshold !== undefined;
  const failing = gated && !result.pass;
  return (
    <div className="grid grid-cols-[11rem_1fr_8rem] items-center gap-x-3 text-xs">
      <span
        className={`truncate ${failing ? 'text-amber-700 dark:text-amber-400' : 'text-slate-500 dark:text-slate-400'}`}
        title={result.label}
      >
        {result.label}
      </span>
      <span className="h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
        <span
          className={`block h-full rounded-full ${
            failing ? 'bg-amber-400/90' : percent === 100 ? 'bg-emerald-400/80' : 'bg-accent-400/80'
          }`}
          style={{ width: `${percent}%` }}
        />
      </span>
      <span
        className={`text-right tabular-nums ${failing ? 'text-amber-700 dark:text-amber-400' : 'text-slate-400'}`}
        title={gated ? `Requires at least ${threshold}%` : undefined}
      >
        {formatCount(satisfied)}/{formatCount(total)} · {percent}%{gated ? ` · ≥${threshold}%` : ''}
      </span>
    </div>
  );
}

function ExternalRefRow({
  ws,
  docId,
  docRef,
  uri,
}: {
  ws: WorkspaceState;
  docId: DocumentId;
  docRef: string;
  uri: string;
}) {
  const resolution = ws.resolutions.get(refKey(docId, docRef));
  const target =
    resolution?.status === 'resolved' ? ws.documents.get(resolution.targetDocId) : undefined;

  return (
    <div className="flex min-w-0 items-center gap-2 text-xs">
      <button
        type="button"
        className="max-w-64 shrink-0 truncate text-left font-mono text-accent-700 hover:underline dark:text-accent-400"
        title={uri}
        onClick={() =>
          selectTarget(
            target
              ? { kind: 'document', docId: target.document.id }
              : { kind: 'placeholder', owningDocId: docId, docRef, spdxId: null },
          )
        }
      >
        {docRef}
      </button>
      {target ? (
        <Chip tone="accent">
          {resolution!.status === 'resolved' ? `resolved · ${resolution!.method}` : ''}
        </Chip>
      ) : (
        <Chip tone={resolution?.status === 'unresolved' && resolution.structural ? 'warn' : 'neutral'}>
          {resolution?.status === 'unresolved' && !resolution.structural
            ? 'informational · not loaded'
            : 'not loaded'}
        </Chip>
      )}
      <span className="min-w-0 truncate text-slate-400 dark:text-slate-500" title={uri}>
        {uri}
      </span>
    </div>
  );
}
