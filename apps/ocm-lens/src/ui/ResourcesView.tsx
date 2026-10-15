import { useMemo, useState } from 'react';
import clsx from 'clsx';
import type { OcmArtifact, OcmCv, OcmTransport } from '@sbomlens/core/ocm';
import { useSbomEvidence } from '../app/evidence';
import { extractBlob, runDigestChecks } from '../app/ingest';
import { saveBytes } from '../app/download';
import { useAppStore } from '../app/store';
import { BUTTON_SECONDARY, Chip, KV, Section, formatBytes } from './bits';
import { TransportChip } from './ComponentsView';
import { BindingChip, CoverageChip, artifactAt, bindingExplanation, downloadSbom as saveSbom } from './sbomBits';

/**
 * Every artifact of the delivery in one filterable table — "what actually
 * ships?" across all component versions — with the artifact detail (access
 * spec, digest verdict, content previews, download) alongside.
 */

interface Row {
  cv: OcmCv;
  artifact: OcmArtifact;
  role: 'resource' | 'source';
  index: number;
}

const TRANSPORTS: OcmTransport[] = ['transported', 'external', 'broken', 'unknown', 'none'];

export function ResourcesView() {
  const delivery = useAppStore((s) => s.delivery);
  const selectedArtifact = useAppStore((s) => s.selectedArtifact);
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const [q, setQ] = useState('');
  const [transportFilter, setTransportFilter] = useState<Set<OcmTransport>>(new Set());
  const [includeSources, setIncludeSources] = useState(false);
  const [sbomGapsOnly, setSbomGapsOnly] = useState(false);
  const evidence = useSbomEvidence();
  const coverage = useMemo(
    () => new Map((evidence?.coverage ?? []).map((row) => [`${row.artifact.cvId}\u0000${row.artifact.index}`, row])),
    [evidence],
  );

  const rows = useMemo(() => {
    if (!delivery) return [];
    const all: Row[] = [];
    for (const cv of delivery.bundle.componentVersions) {
      cv.resources.forEach((artifact, index) => all.push({ cv, artifact, role: 'resource', index }));
      if (includeSources) {
        cv.sources.forEach((artifact, index) => all.push({ cv, artifact, role: 'source', index }));
      }
    }
    const needle = q.trim().toLowerCase();
    return all.filter((row) => {
      if (transportFilter.size > 0 && !transportFilter.has(row.artifact.transport)) return false;
      if (sbomGapsOnly) {
        const gap = coverage.get(`${row.cv.id}\u0000${row.index}`);
        if (row.role !== 'resource' || !gap?.expected || gap.status === 'bound') return false;
      }
      if (!needle) return true;
      return (
        row.artifact.name.toLowerCase().includes(needle) ||
        (row.artifact.type ?? '').toLowerCase().includes(needle) ||
        row.cv.id.toLowerCase().includes(needle)
      );
    });
  }, [delivery, q, transportFilter, includeSources, sbomGapsOnly, coverage]);

  if (!delivery) return null;

  const selectedRow =
    selectedArtifact &&
    rows.find(
      (r) =>
        r.cv.id === selectedArtifact.cvId &&
        r.role === selectedArtifact.role &&
        r.index === selectedArtifact.index,
    );
  const fallbackSelected = selectedArtifact
    ? (() => {
        const cv = delivery.bundle.componentVersions.find((c) => c.id === selectedArtifact.cvId);
        const artifact =
          selectedArtifact.role === 'resource'
            ? cv?.resources[selectedArtifact.index]
            : cv?.sources[selectedArtifact.index];
        return cv && artifact
          ? { cv, artifact, role: selectedArtifact.role, index: selectedArtifact.index }
          : null;
      })()
    : null;
  const detail = selectedRow ?? fallbackSelected;

  const toggleTransport = (t: OcmTransport) =>
    setTransportFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });

  return (
    <div className="flex h-full min-h-0">
      <div className="min-w-0 flex-1 overflow-auto p-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter by name, type, component..."
            className="w-64 rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none focus:border-accent-400 dark:border-slate-700"
          />
          {TRANSPORTS.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => toggleTransport(t)}
              className={clsx(
                'rounded border px-1.5 py-0.5 text-[11px]',
                transportFilter.has(t)
                  ? 'border-accent-400 bg-accent-50 text-accent-700 dark:bg-accent-950 dark:text-accent-300'
                  : 'border-slate-200 text-slate-500 dark:border-slate-700 dark:text-slate-400',
              )}
            >
              {t}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setSbomGapsOnly((v) => !v)}
            title="Artifacts that ship software without a bound SBOM"
            className={clsx(
              'rounded border px-1.5 py-0.5 text-[11px]',
              sbomGapsOnly
                ? 'border-accent-400 bg-accent-50 text-accent-700 dark:bg-accent-950 dark:text-accent-300'
                : 'border-slate-200 text-slate-500 dark:border-slate-700 dark:text-slate-400',
            )}
          >
            SBOM gaps
          </button>
          <label className="ml-2 flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
            <input
              type="checkbox"
              checked={includeSources}
              onChange={(e) => setIncludeSources(e.target.checked)}
            />
            sources
          </label>
          <span className="ml-auto text-xs text-slate-400">{rows.length} artifact(s)</span>
        </div>

        <div className="overflow-hidden rounded-md border border-slate-200 dark:border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs text-slate-500 dark:bg-slate-900 dark:text-slate-400">
              <tr>
                <th className="px-3 py-1.5 font-medium">Artifact</th>
                <th className="px-3 py-1.5 font-medium">Component</th>
                <th className="px-3 py-1.5 font-medium">Type</th>
                <th className="px-3 py-1.5 font-medium">Transport</th>
                <th className="px-3 py-1.5 font-medium">Size</th>
                <th className="px-3 py-1.5 font-medium">Integrity</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const isSelected =
                  selectedArtifact?.cvId === row.cv.id &&
                  selectedArtifact.role === row.role &&
                  selectedArtifact.index === row.index;
                return (
                  <tr
                    key={`${row.cv.id}:${row.role}:${row.index}`}
                    onClick={() => selectArtifact({ cvId: row.cv.id, role: row.role, index: row.index })}
                    className={clsx(
                      'cursor-pointer border-t border-slate-100 dark:border-slate-800/60',
                      isSelected
                        ? 'bg-accent-50 dark:bg-accent-950'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-900',
                    )}
                  >
                    <td className="px-3 py-1.5 font-medium">
                      {row.artifact.name}
                      {row.role === 'source' && <span className="ml-1 text-xs text-slate-400">(source)</span>}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                      {row.cv.id}
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">{row.artifact.type ?? '-'}</td>
                    <td className="px-3 py-1.5">
                      <TransportChip transport={row.artifact.transport} />
                    </td>
                    <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">
                      {row.artifact.blob ? formatBytes(row.artifact.blob.size) : '-'}
                    </td>
                    <td className="px-3 py-1.5">
                      {row.artifact.blob?.digestCheck === 'match' && <Chip tone="ok">digest ok</Chip>}
                      {row.artifact.blob?.digestCheck === 'mismatch' && <Chip tone="danger">mismatch</Chip>}
                      {row.artifact.blob?.digestCheck === 'unchecked' && <Chip>not checkable</Chip>}
                      {row.artifact.blob?.digestCheck === 'pending' && <Chip tone="warn">not checked yet</Chip>}
                      {(row.artifact.isSbom || row.artifact.sbom) && <Chip tone="accent">SBOM</Chip>}
                      {row.role === 'resource' &&
                        (() => {
                          const cell = coverage.get(`${row.cv.id}\u0000${row.index}`);
                          return cell && (cell.expected || cell.status === 'bound') ? <CoverageChip row={cell} /> : null;
                        })()}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {rows.length === 0 && (
            <p className="px-3 py-4 text-center text-xs text-slate-400">Nothing matches the filter.</p>
          )}
        </div>
      </div>

      {detail && (
        <aside className="w-96 shrink-0 overflow-auto border-l border-slate-200 p-3 dark:border-slate-800">
          <ArtifactDetail row={detail} />
        </aside>
      )}
    </div>
  );
}

function ArtifactDetail({ row }: { row: Row }) {
  const delivery = useAppStore((s) => s.delivery);
  const sourceRef = useAppStore((s) => s.sourceRef);
  const selectCv = useAppStore((s) => s.actions.selectCv);
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const [busy, setBusy] = useState(false);
  const [checkingDigest, setCheckingDigest] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const { artifact, cv } = row;

  const checkThisDigest = async () => {
    setCheckingDigest(true);
    try {
      await runDigestChecks([{ cvId: cv.id, role: row.role, index: row.index }]);
    } finally {
      setCheckingDigest(false);
    }
  };
  const localReference =
    typeof artifact.access?.raw.localReference === 'string'
      ? artifact.access.raw.localReference
      : typeof artifact.access?.raw.filename === 'string'
        ? artifact.access.raw.filename
        : undefined;

  const downloadBlob = async () => {
    if (!localReference) return;
    setBusy(true);
    setDownloadError(null);
    try {
      const bytes = await extractBlob(localReference);
      if (!bytes) {
        setDownloadError('The blob could not be read back from the archive.');
      } else {
        saveBytes(artifact.name, artifact.blob?.mediaType ?? 'application/octet-stream', bytes);
      }
    } finally {
      setBusy(false);
    }
  };

  const downloadSbom = () => {
    if (delivery) saveSbom(delivery, artifact);
  };

  return (
    <div>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div>
          <div className="font-medium">{artifact.name}</div>
          <button
            type="button"
            onClick={() => selectCv(cv.id)}
            className="font-mono text-xs text-slate-400 hover:text-accent-700 dark:hover:text-accent-400"
          >
            {cv.id}
          </button>
        </div>
        <button type="button" onClick={() => selectArtifact(null)} className="text-slate-400" aria-label="Close">
          ✕
        </button>
      </div>

      <div className="mb-3 flex flex-wrap gap-1">
        <TransportChip transport={artifact.transport} />
        {artifact.type && <Chip>{artifact.type}</Chip>}
        {artifact.relation && <Chip>{artifact.relation}</Chip>}
        {artifact.version && <Chip>v{artifact.version}</Chip>}
      </div>

      <Section title="Access">
        <KV label="Type" mono>
          {artifact.access?.type ?? '-'}
        </KV>
        {artifact.location && (
          <KV label="Location" mono>
            {artifact.location}
          </KV>
        )}
        {artifact.extraIdentity &&
          Object.entries(artifact.extraIdentity).map(([k, v]) => (
            <KV key={k} label={`extraIdentity ${k}`} mono>
              {v}
            </KV>
          ))}
        {artifact.access && (
          <details className="mt-1">
            <summary className="cursor-pointer text-xs text-slate-400">Raw access node</summary>
            <pre className="mt-1 overflow-auto rounded border border-slate-100 p-1.5 font-mono text-[11px] dark:border-slate-800">
              {JSON.stringify(artifact.access.raw, null, 1)}
            </pre>
          </details>
        )}
      </Section>

      {artifact.digest && (
        <Section title="Declared digest">
          <KV label="Hash" mono>
            {artifact.digest.hashAlgorithm ?? '-'}
          </KV>
          <KV label="Normalisation" mono>
            {artifact.digest.normalisationAlgorithm ?? '-'}
          </KV>
          <KV label="Value" mono>
            {artifact.digest.value ?? '-'}
          </KV>
          {artifact.blob?.digestCheck && (
            <div className="mt-1 flex items-center gap-2">
              {artifact.blob.digestCheck === 'match' && (
                <Chip tone="ok">delivered bytes match this digest</Chip>
              )}
              {artifact.blob.digestCheck === 'mismatch' && (
                <Chip tone="danger">delivered bytes DO NOT match this digest</Chip>
              )}
              {artifact.blob.digestCheck === 'unchecked' && <Chip>could not be checked</Chip>}
              {artifact.blob.digestCheck === 'pending' && (
                <>
                  <Chip tone="warn">deferred — not checked yet</Chip>
                  <button
                    type="button"
                    disabled={checkingDigest || !sourceRef}
                    onClick={() => void checkThisDigest()}
                    className={BUTTON_SECONDARY}
                  >
                    {checkingDigest ? 'Checking...' : 'Check digest'}
                  </button>
                </>
              )}
            </div>
          )}
        </Section>
      )}

      {artifact.blob && (
        <Section title="Content">
          <KV label="Kind">{artifact.blob.kind}</KV>
          <KV label="Size">{formatBytes(artifact.blob.size)}</KV>
          {artifact.blob.mediaType && (
            <KV label="Media type" mono>
              {artifact.blob.mediaType}
            </KV>
          )}
          {artifact.blob.notInspected && (
            <p className="mt-1 text-xs text-slate-400">
              Too large for content inspection — the digest verdict above is still real (hashed off the
              archive).
            </p>
          )}
          {artifact.blob.previews?.map((p) => (
            <details key={p.name} className="mt-1.5" open={artifact.blob!.previews!.length === 1}>
              <summary className="cursor-pointer font-mono text-xs text-slate-500 dark:text-slate-400">
                {p.name}
                {p.truncated ? ' (truncated)' : ''}
              </summary>
              <pre className="mt-1 max-h-60 overflow-auto rounded border border-slate-100 p-1.5 font-mono text-[11px] dark:border-slate-800">
                {p.text}
              </pre>
            </details>
          ))}
          {artifact.blob.files && artifact.blob.files.length > 0 && (
            <details className="mt-1.5">
              <summary className="cursor-pointer text-xs text-slate-400">
                {artifact.blob.files.length} file(s){artifact.blob.filesTruncated ? ' (truncated)' : ''}
              </summary>
              <ul className="mt-1 max-h-48 overflow-auto font-mono text-[11px] text-slate-500 dark:text-slate-400">
                {artifact.blob.files.map((f) => (
                  <li key={f.name} className="flex justify-between gap-2">
                    <span className="min-w-0 truncate">{f.name}</span>
                    <span>{formatBytes(f.size)}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
          {artifact.blob.oci && (
            <div className="mt-1.5">
              <div className="text-xs text-slate-400">OCI layers</div>
              <ul className="mt-0.5 space-y-0.5 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                {artifact.blob.oci.layers.map((layer, i) => (
                  <li key={i} className="flex justify-between gap-2">
                    <span className="min-w-0 truncate">{layer.digest ?? layer.mediaType ?? `layer ${i}`}</span>
                    {typeof layer.size === 'number' && <span>{formatBytes(layer.size)}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Section>
      )}

      {row.role === 'resource' && <SbomSection cvId={cv.id} index={row.index} />}

      <div className="flex flex-wrap gap-2">
        {artifact.transport === 'transported' && localReference && (
          <button
            type="button"
            disabled={busy || !sourceRef}
            onClick={() => void downloadBlob()}
            className={BUTTON_SECONDARY}
            title={sourceRef ? 'Re-reads the archive and saves this blob' : 'Source not available for re-reading'}
          >
            {busy ? 'Extracting...' : 'Download blob'}
          </button>
        )}
        {artifact.sbom && (
          <button type="button" onClick={downloadSbom} className={BUTTON_SECONDARY}>
            Download SBOM ({artifact.sbom.format})
          </button>
        )}
      </div>
      {downloadError && <p className="mt-2 text-xs text-red-600 dark:text-red-400">{downloadError}</p>}
      {artifact.sbom && (
        <p className="mt-2 text-xs text-slate-400">
          For deep SBOM analysis (cascades, licenses, VEX), open the downloaded file in SBOM Lens.
        </p>
      )}
    </div>
  );
}

/** What the SBOM evidence says about one resource: its own binding, or its coverage. */
function SbomSection({ cvId, index }: { cvId: string; index: number }) {
  const evidence = useSbomEvidence();
  const delivery = useAppStore((s) => s.delivery);
  const selectSbom = useAppStore((s) => s.actions.selectSbom);
  if (!evidence || !delivery) return null;
  const open = (ref: { cvId: string; index: number }) => selectSbom({ cvId: ref.cvId, role: 'resource', index: ref.index });

  const occurrence = evidence.sboms.find((s) => s.at.cvId === cvId && s.at.index === index);
  if (occurrence) {
    return (
      <Section
        title="SBOM evidence"
        action={
          <button type="button" onClick={() => open(occurrence.at)} className="text-xs text-accent-700 hover:underline dark:text-accent-400">
            Details
          </button>
        }
      >
        {occurrence.binding ? (
          <>
            <div className="mb-1.5">
              <BindingChip binding={occurrence.binding} />
            </div>
            {bindingExplanation(occurrence.binding, delivery.bundle).map((line) => (
              <p key={line} className="mb-1 text-sm text-slate-600 dark:text-slate-300">
                {line}
              </p>
            ))}
          </>
        ) : (
          <p className="text-sm text-slate-600 dark:text-slate-300">
            {occurrence.presence === 'external'
              ? 'Declared with an external access: not part of this delivery, so not analysed.'
              : occurrence.presence === 'deferred'
                ? 'Not analysed at load time (size budget); analyse it in the SBOMs view.'
                : 'Could not be read as an SBOM.'}
          </p>
        )}
      </Section>
    );
  }

  const row = evidence.coverage.find((r) => r.artifact.cvId === cvId && r.artifact.index === index);
  if (!row || (!row.expected && row.status === 'missing')) return null;
  return (
    <Section title="SBOM evidence">
      <div className="mb-1.5">
        <CoverageChip row={row} />
      </div>
      {row.sboms.map((ref) => (
        <button
          key={`${ref.cvId}:${ref.index}`}
          type="button"
          onClick={() => open(ref)}
          className="mr-2 text-sm text-accent-700 hover:underline dark:text-accent-400"
        >
          {artifactAt(delivery.bundle, ref)?.name}
        </button>
      ))}
      {row.status === 'missing' && (
        <p className="text-sm text-slate-600 dark:text-slate-300">
          This artifact ships software, but the delivery carries no SBOM for it.
        </p>
      )}
    </Section>
  );
}
