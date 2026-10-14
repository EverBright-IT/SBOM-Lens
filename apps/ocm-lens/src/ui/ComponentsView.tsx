import { useMemo, useState } from 'react';
import clsx from 'clsx';
import type { OcmBundle, OcmCv, OcmCvId, OcmLabel } from '@sbomlens/core/ocm';
import { useAppStore } from '../app/store';
import { BUTTON_SECONDARY, Chip, KV, Section, formatBytes } from './bits';

/**
 * The reference graph as primary navigation: roots first, unlimited depth,
 * diamonds marked instead of duplicated-and-hidden, cycle edges shown but
 * not followed. The right pane is the component version in the spec's own
 * vocabulary.
 */

export function ComponentsView() {
  const delivery = useAppStore((s) => s.delivery);
  const selectedCv = useAppStore((s) => s.selectedCv);
  if (!delivery) return null;
  const bundle = delivery.bundle;
  const cv = bundle.componentVersions.find((c) => c.id === selectedCv) ?? bundle.componentVersions[0];

  return (
    <div className="flex h-full min-h-0">
      <aside className="w-80 shrink-0 overflow-auto border-r border-slate-200 p-2 dark:border-slate-800">
        <ReferenceTree bundle={bundle} />
      </aside>
      <div className="min-w-0 flex-1 overflow-auto p-4">{cv && <CvDetail bundle={bundle} cv={cv} />}</div>
    </div>
  );
}

function ReferenceTree({ bundle }: { bundle: OcmBundle }) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const byId = useMemo(
    () => new Map(bundle.componentVersions.map((cv) => [cv.id, cv])),
    [bundle],
  );

  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <div className="space-y-0.5 text-sm">
      {bundle.roots.map((rootId) => (
        <TreeNode
          key={rootId}
          bundle={bundle}
          byId={byId}
          cvId={rootId}
          depth={0}
          pathKey={rootId}
          collapsed={collapsed}
          toggle={toggle}
        />
      ))}
    </div>
  );
}

function TreeNode({
  bundle,
  byId,
  cvId,
  viaRef,
  depth,
  pathKey,
  collapsed,
  toggle,
}: {
  bundle: OcmBundle;
  byId: Map<OcmCvId, OcmCv>;
  cvId: OcmCvId;
  viaRef?: string;
  depth: number;
  pathKey: string;
  collapsed: Set<string>;
  toggle: (key: string) => void;
}) {
  const selectedCv = useAppStore((s) => s.selectedCv);
  const selectCv = useAppStore((s) => s.actions.selectCv);
  const cv = byId.get(cvId);
  if (!cv) return null;
  const children = cv.references;
  const isCollapsed = collapsed.has(pathKey);
  const isShared = bundle.shared.includes(cvId);

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => selectCv(cvId)}
        onKeyDown={(e) => e.key === 'Enter' && selectCv(cvId)}
        className={clsx(
          'flex cursor-pointer items-center gap-1.5 rounded px-1.5 py-1',
          selectedCv === cvId
            ? 'bg-accent-50 text-accent-900 dark:bg-accent-950 dark:text-accent-100'
            : 'hover:bg-slate-50 dark:hover:bg-slate-900',
        )}
        style={{ paddingLeft: `${depth * 14 + 6}px` }}
      >
        {children.length > 0 ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              toggle(pathKey);
            }}
            className="w-4 shrink-0 text-slate-400"
            aria-label={isCollapsed ? 'Expand' : 'Collapse'}
          >
            {isCollapsed ? '▸' : '▾'}
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}
        <span className="min-w-0 truncate">
          <span className="font-medium">{cv.name}</span>{' '}
          <span className="text-slate-400">{cv.version}</span>
        </span>
        <span className="ml-auto flex shrink-0 gap-1">
          {viaRef === undefined && depth === 0 && <Chip tone="accent">root</Chip>}
          {isShared && <Chip title="Referenced by more than one component">shared</Chip>}
          {(cv.signatures?.length ?? 0) > 0 && <Chip>signed</Chip>}
        </span>
      </div>
      {!isCollapsed &&
        children.map((ref, i) => {
          const childKey = `${pathKey}>${ref.name}#${i}`;
          if (ref.cyclic) {
            return (
              <div
                key={childKey}
                className="flex items-center gap-1.5 px-1.5 py-1 text-xs text-slate-400"
                style={{ paddingLeft: `${(depth + 1) * 14 + 6}px` }}
              >
                <span className="w-4 shrink-0" />↺ {ref.componentName}@{ref.version}
                <Chip tone="warn" title="This edge closes a reference cycle; the graph is shown with the cycle broken here">
                  cycle
                </Chip>
              </div>
            );
          }
          if (!ref.target) {
            return (
              <div
                key={childKey}
                className="flex items-center gap-1.5 px-1.5 py-1 text-xs text-slate-400"
                style={{ paddingLeft: `${(depth + 1) * 14 + 6}px` }}
              >
                <span className="w-4 shrink-0" />→ {ref.componentName}@{ref.version}
                <Chip tone="warn" title="The referenced component version is not part of this bundle">
                  not in bundle
                </Chip>
              </div>
            );
          }
          return (
            <TreeNode
              key={childKey}
              bundle={bundle}
              byId={byId}
              cvId={ref.target}
              viaRef={ref.name}
              depth={depth + 1}
              pathKey={childKey}
              collapsed={collapsed}
              toggle={toggle}
            />
          );
        })}
    </div>
  );
}

function LabelRows({ labels }: { labels: OcmLabel[] }) {
  return (
    <>
      {labels.map((label) => (
        <KV key={label.name} label={label.name} mono>
          {typeof label.value === 'string' ? label.value : JSON.stringify(label.value)}
          {label.signing && (
            <span className="ml-1.5">
              <Chip tone="accent">signing</Chip>
            </span>
          )}
        </KV>
      ))}
    </>
  );
}

function CvDetail({ bundle, cv }: { bundle: OcmBundle; cv: OcmCv }) {
  const selectCv = useAppStore((s) => s.actions.selectCv);
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const setView = useAppStore((s) => s.actions.setView);
  const verification = useAppStore((s) => s.verification);
  const cvEntries = verification?.entries.filter((e) => e.cvId === cv.id) ?? [];

  return (
    <div className="mx-auto max-w-3xl">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <h1 className="text-lg font-semibold">
          {cv.name} <span className="font-normal text-slate-400">{cv.version}</span>
        </h1>
        <Chip>{`OCM-CD/${cv.schemaVersion}`}</Chip>
        {bundle.roots.includes(cv.id) && <Chip tone="accent">root</Chip>}
        {bundle.shared.includes(cv.id) && <Chip>shared</Chip>}
      </div>

      <Section title="Component version">
        <KV label="Identity" mono>
          {cv.id}
        </KV>
        {cv.provider?.name && <KV label="Provider">{cv.provider.name}</KV>}
        {cv.creationTime && (
          <KV label="Creation time" mono>
            {cv.creationTime}
          </KV>
        )}
        <KV label="Descriptor" mono>
          {cv.serialization} · {formatBytes(cv.byteSize)} · sha1 {cv.sha1.slice(0, 12)}…
        </KV>
        {cv.labels && cv.labels.length > 0 && <LabelRows labels={cv.labels} />}
      </Section>

      {cv.repositoryContexts && cv.repositoryContexts.length > 0 && (
        <Section title="Repository contexts">
          {cv.repositoryContexts.map((ctx, i) => (
            <KV key={i} label={ctx.type ?? 'context'} mono>
              {ctx.baseUrl ?? '-'}
              {ctx.subPath ? `/${ctx.subPath}` : ''}
            </KV>
          ))}
        </Section>
      )}

      {(cv.signatures?.length ?? 0) > 0 && (
        <Section
          title={`Signatures (${cv.signatures!.length})`}
          action={
            <button type="button" onClick={() => setView('verify')} className={BUTTON_SECONDARY}>
              Verify delivery...
            </button>
          }
        >
          <div className="space-y-1.5">
            {cv.signatures!.map((sig, i) => {
              const entry = cvEntries.find((e) => e.name === (sig.name ?? `signature ${i + 1}`));
              return (
                <div key={i} className="rounded border border-slate-100 px-2.5 py-1.5 dark:border-slate-800">
                  <div className="flex items-center gap-2 text-sm">
                    <span className="font-medium">{sig.name ?? `signature ${i + 1}`}</span>
                    {entry ? (
                      entry.verdict === 'valid' ? (
                        <Chip tone="ok">valid{entry.keyLabel ? ` · ${entry.keyLabel}` : ''}</Chip>
                      ) : entry.verdict === 'invalid' ? (
                        <Chip tone="danger">invalid</Chip>
                      ) : (
                        <Chip tone="warn">unverifiable</Chip>
                      )
                    ) : (
                      <Chip>not verified</Chip>
                    )}
                  </div>
                  {entry?.reason && <p className="mt-0.5 text-xs text-slate-400">{entry.reason}</p>}
                  <div className="mt-1 text-xs text-slate-400">
                    {sig.algorithm ?? '-'} · {sig.digest?.normalisationAlgorithm ?? '-'}
                  </div>
                </div>
              );
            })}
          </div>
        </Section>
      )}

      <Section title={`Resources (${cv.resources.length})`}>
        {cv.resources.length === 0 ? (
          <p className="text-xs text-slate-400">None.</p>
        ) : (
          <div className="overflow-hidden rounded-md border border-slate-200 dark:border-slate-800">
            <table className="w-full text-sm">
              <tbody>
                {cv.resources.map((r, index) => (
                  <tr
                    key={index}
                    onClick={() => selectArtifact({ cvId: cv.id, role: 'resource', index })}
                    className="cursor-pointer border-t border-slate-100 first:border-t-0 hover:bg-slate-50 dark:border-slate-800/60 dark:hover:bg-slate-900"
                  >
                    <td className="px-3 py-1.5 font-medium">{r.name}</td>
                    <td className="px-3 py-1.5 text-slate-400">{r.type ?? '-'}</td>
                    <td className="px-3 py-1.5">
                      <TransportChip transport={r.transport} />
                    </td>
                    <td className="px-3 py-1.5">
                      {r.blob?.digestCheck === 'match' && <Chip tone="ok">digest ok</Chip>}
                      {r.blob?.digestCheck === 'mismatch' && <Chip tone="danger">digest mismatch</Chip>}
                      {r.sbom && <Chip tone="accent">SBOM</Chip>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {cv.sources.length > 0 && (
        <Section title={`Sources (${cv.sources.length})`}>
          {cv.sources.map((s, index) => (
            <div key={index} className="flex items-center gap-2 py-0.5 text-sm">
              <button
                type="button"
                onClick={() => selectArtifact({ cvId: cv.id, role: 'source', index })}
                className="font-medium hover:text-accent-700 dark:hover:text-accent-400"
              >
                {s.name}
              </button>
              <span className="text-xs text-slate-400">{s.type ?? ''}</span>
            </div>
          ))}
        </Section>
      )}

      <Section title={`References (${cv.references.length})`}>
        {cv.references.length === 0 ? (
          <p className="text-xs text-slate-400">This component version aggregates nothing.</p>
        ) : (
          <div className="space-y-1">
            {cv.references.map((ref, i) => (
              <div key={i} className="flex items-center gap-2 text-sm">
                <span className="text-slate-400">{ref.name}</span>
                <span className="font-mono text-xs">
                  {ref.componentName}@{ref.version}
                </span>
                {ref.cyclic && <Chip tone="warn">cycle</Chip>}
                {ref.target ? (
                  <button
                    type="button"
                    onClick={() => selectCv(ref.target!)}
                    className="text-xs text-accent-700 hover:underline dark:text-accent-400"
                  >
                    open →
                  </button>
                ) : (
                  <Chip tone="warn">not in bundle</Chip>
                )}
                {ref.digest?.value && <Chip title={`Digest: ${ref.digest.value}`}>digest recorded</Chip>}
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Descriptor source">
        <details>
          <summary className="cursor-pointer text-xs text-slate-400 hover:text-accent-700 dark:hover:text-accent-400">
            Show the verbatim descriptor ({formatBytes(cv.byteSize)})
          </summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded border border-slate-100 p-2 font-mono text-xs dark:border-slate-800">
            {cv.text}
          </pre>
        </details>
      </Section>
    </div>
  );
}

export function TransportChip({ transport }: { transport: string }) {
  if (transport === 'transported') return <Chip tone="ok">transported</Chip>;
  if (transport === 'external') return <Chip tone="warn">external</Chip>;
  if (transport === 'broken') return <Chip tone="danger">broken</Chip>;
  if (transport === 'none') return <Chip>no access</Chip>;
  return <Chip tone="warn">unknown</Chip>;
}
