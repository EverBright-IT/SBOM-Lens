import type { SbomDocument, SbomElement } from '@sbomlens/core';
import type { OcmDigest, OcmLabel } from '@sbomlens/core/ocm';
import { Chip, CopyButton, FieldRow, Section } from './FieldRow';

/**
 * OCM-native detail sections, rendered only when the parser attached `ocm`
 * extension data — SPDX documents never see any of this. Field vocabulary
 * follows the component-descriptor spec (access, digest triple, labels,
 * repository contexts, signatures).
 */

export function OcmElementSections({ element }: { element: SbomElement }) {
  const ocm = element.ocm;
  if (!ocm) return null;
  return (
    <>
      {(ocm.type || ocm.relation || ocm.extraIdentity) && (
        <Section title="OCM identity">
          <FieldRow label="Artifact type" value={ocm.type} />
          <FieldRow label="Relation" value={ocm.relation} />
          {ocm.extraIdentity && (
            <FieldRow
              label="Extra identity"
              value={Object.entries(ocm.extraIdentity)
                .map(([k, v]) => `${k}=${v}`)
                .join(' · ')}
              mono
            />
          )}
        </Section>
      )}

      {ocm.access && (
        <Section title={`Access — ${ocm.access.type ?? 'unknown'}`}>
          {Object.entries(ocm.access.raw)
            .filter(([key]) => key !== 'type')
            .map(([key, value]) => (
              <FieldRow
                key={key}
                label={key}
                value={typeof value === 'string' ? value : JSON.stringify(value)}
                mono
                copyable={typeof value === 'string'}
              />
            ))}
          {Object.keys(ocm.access.raw).length <= 1 && (
            <p className="text-xs text-slate-400">No further access fields.</p>
          )}
        </Section>
      )}

      {ocm.digest && <DigestRows digest={ocm.digest} title="Digest" />}

      {ocm.labels && <LabelSection labels={ocm.labels} />}
    </>
  );
}

export function OcmDocumentSections({ doc }: { doc: SbomDocument }) {
  const ocm = doc.ocm;
  if (!ocm) return null;
  return (
    <>
      {(ocm.labels || ocm.repositoryContexts) && (
        <Section title="Component">
          {ocm.repositoryContexts?.map((ctx, i) => (
            <FieldRow
              key={i}
              label={i === 0 ? 'Repository context' : ''}
              value={[ctx.type, ctx.baseUrl, ctx.subPath].filter(Boolean).join(' · ')}
              mono
            />
          ))}
          {ocm.labels && <LabelRows labels={ocm.labels} />}
        </Section>
      )}

      {ocm.signatures && (
        <Section title={`Signatures (${ocm.signatures.length})`}>
          <div className="space-y-2">
            {ocm.signatures.map((sig, i) => (
              <div key={i} className="rounded border border-slate-100 px-2.5 py-1.5 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <span className="min-w-0 truncate text-[13px] font-medium">{sig.name ?? `signature ${i + 1}`}</span>
                  <Chip>not verified</Chip>
                </div>
                <FieldRow label="Algorithm" value={sig.algorithm} mono />
                <FieldRow label="Media type" value={sig.mediaType} mono />
                <FieldRow label="Issuer" value={sig.issuer} mono />
                {sig.digest && <DigestRows digest={sig.digest} inline />}
                {sig.value && (
                  <div className="grid grid-cols-[9rem_1fr] items-baseline gap-x-3 py-1">
                    <div className="text-xs text-slate-400 dark:text-slate-500">Signature</div>
                    <div className="flex min-w-0 items-baseline gap-1 font-mono text-xs">
                      <span className="truncate" title={sig.value}>
                        {sig.value.length > 48 ? `${sig.value.slice(0, 48)}…` : sig.value}
                      </span>
                      <CopyButton text={sig.value} />
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}

function DigestRows({ digest, title, inline }: { digest: OcmDigest; title?: string; inline?: boolean }) {
  const rows = (
    <>
      <FieldRow label="Hash algorithm" value={digest.hashAlgorithm} mono />
      <FieldRow label="Normalisation" value={digest.normalisationAlgorithm} mono />
      <FieldRow label="Digest value" value={digest.value} mono copyable />
    </>
  );
  if (inline) return rows;
  return <Section title={title ?? 'Digest'}>{rows}</Section>;
}

function LabelSection({ labels }: { labels: OcmLabel[] }) {
  return (
    <Section title={`Labels (${labels.length})`}>
      <LabelRows labels={labels} />
    </Section>
  );
}

function LabelRows({ labels }: { labels: OcmLabel[] }) {
  return (
    <div className="space-y-0.5">
      {labels.map((label) => (
        <div key={label.name} className="grid grid-cols-[9rem_1fr] items-baseline gap-x-3 py-1">
          <div className="min-w-0 truncate text-xs text-slate-400 dark:text-slate-500" title={label.name}>
            {label.name}
          </div>
          <div className="flex min-w-0 items-baseline gap-1.5 text-[13px]">
            <span className="break-words whitespace-pre-wrap [overflow-wrap:anywhere] font-mono text-xs">
              {typeof label.value === 'string' ? label.value : JSON.stringify(label.value, null, 1)}
            </span>
            {label.signing && <Chip tone="accent">signing</Chip>}
          </div>
        </div>
      ))}
    </div>
  );
}
