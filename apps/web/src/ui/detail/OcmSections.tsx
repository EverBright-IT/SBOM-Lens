import { useEffect, useState } from 'react';
import type { SbomDocument, SbomElement } from '@sbomlens/core';
import type { OcmBlobInfo, OcmDigest, OcmLabel, OcmSignatureInfo, SignatureResult } from '@sbomlens/core/ocm';
import { verifyDocumentSignatures } from '@sbomlens/core/ocm';
import { host } from '../../host/adapter';
import { formatBytes } from '../nodeInfo';
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
        <Section title={`Access: ${ocm.access.type ?? 'unknown'}`}>
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

      {ocm.blob && <ArtifactContentSection blob={ocm.blob} elementName={element.name} />}

      {ocm.labels && <LabelSection labels={ocm.labels} />}
    </>
  );
}

const BLOB_KIND_LABEL: Record<OcmBlobInfo['kind'], string> = {
  'helm-chart': 'Helm chart',
  'oci-artifact': 'OCI artifact set',
  tar: 'tar archive',
  json: 'JSON',
  yaml: 'YAML',
  text: 'text',
  binary: 'binary',
};

const EXPORT_EXTENSION: Partial<Record<OcmBlobInfo['kind'], string>> = {
  json: 'json',
  yaml: 'yaml',
  text: 'txt',
};

/**
 * What the delivery physically ships for this artifact: kind, size, capped
 * previews, and the verdict of checking the declared digest against the
 * actual bytes. All of it was inspected inside the worker — the raw blob
 * never reaches this thread.
 */
function ArtifactContentSection({ blob, elementName }: { blob: OcmBlobInfo; elementName: string }) {
  const digestChip =
    blob.digestCheck === 'match' ? (
      <Chip tone="ok">digest match</Chip>
    ) : blob.digestCheck === 'mismatch' ? (
      <Chip tone="danger">digest mismatch</Chip>
    ) : blob.digestCheck === 'unchecked' ? (
      <Chip>digest unchecked</Chip>
    ) : null;

  const exportExtension = EXPORT_EXTENSION[blob.kind];
  const content = blob.previews?.[0];

  return (
    <Section title="Artifact content" actions={digestChip}>
      <FieldRow
        label="Content"
        value={`${BLOB_KIND_LABEL[blob.kind]}, ${formatBytes(blob.size)}${blob.compressed ? ' (gzip-compressed)' : ''}`}
      />
      <FieldRow label="Media type" value={blob.mediaType} mono />
      {blob.digestCheck === 'mismatch' && (
        <p className="py-1 text-xs text-red-600 dark:text-red-400">
          The blob bytes in this delivery do not match the digest declared in the component descriptor.
        </p>
      )}

      {blob.oci && blob.oci.layers.length > 0 && (
        <table className="mt-1 w-full table-fixed text-left font-mono text-xs">
          <thead>
            <tr className="text-slate-400 dark:text-slate-500">
              <th className="w-[45%] py-0.5 pr-3 font-normal">layer digest</th>
              <th className="w-[4.5rem] py-0.5 pr-3 font-normal">size</th>
              <th className="py-0.5 font-normal">media type</th>
            </tr>
          </thead>
          <tbody>
            {blob.oci.layers.map((layer, i) => (
              <tr key={i} className="border-t border-slate-100 dark:border-slate-800">
                <td className="py-1 pr-3">
                  <span className="flex min-w-0 items-baseline gap-1">
                    <span className="truncate" title={layer.digest}>
                      {layer.digest}
                    </span>
                    {layer.digest && <CopyButton text={layer.digest} />}
                  </span>
                </td>
                <td className="py-1 pr-3 whitespace-nowrap">{layer.size !== undefined ? formatBytes(layer.size) : ''}</td>
                <td className="py-1 break-words [overflow-wrap:anywhere]">{layer.mediaType}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {blob.files && blob.files.length > 0 && (
        <details className="mt-1">
          <summary className="cursor-pointer text-xs text-slate-500 select-none dark:text-slate-400">
            {blob.files.length}
            {blob.filesTruncated ? '+' : ''} files
          </summary>
          <ul className="mt-1 max-h-48 overflow-auto font-mono text-xs">
            {blob.files.map((file) => (
              <li key={file.name} className="flex justify-between gap-3 py-px">
                <span className="min-w-0 truncate" title={file.name}>
                  {file.name}
                </span>
                <span className="shrink-0 text-slate-400 dark:text-slate-500">{formatBytes(file.size)}</span>
              </li>
            ))}
          </ul>
          {blob.filesTruncated && (
            <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">Only the first {blob.files.length} entries are listed.</p>
          )}
        </details>
      )}

      {blob.previews?.map((preview) => (
        <details key={preview.name} className="mt-1" open={blob.previews!.length === 1 && preview.text.length < 2000}>
          <summary className="cursor-pointer text-xs text-slate-500 select-none dark:text-slate-400">
            {preview.name}
            {preview.truncated ? ' (truncated preview)' : ''}
          </summary>
          <pre className="mt-1 max-h-64 overflow-y-auto rounded bg-slate-50 p-2 font-mono text-xs break-words whitespace-pre-wrap [overflow-wrap:anywhere] dark:bg-slate-900">
            {preview.text}
          </pre>
        </details>
      ))}

      {exportExtension && content && (
        <button
          type="button"
          className="mt-2 rounded border border-slate-200 px-2 py-0.5 text-xs text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800"
          onClick={() =>
            host().exportFile(
              `${elementName.replace(/[^A-Za-z0-9._-]/g, '-')}.${exportExtension}`,
              'text/plain',
              content.text,
            )
          }
        >
          Export {blob.kind === 'json' ? 'JSON' : blob.kind === 'yaml' ? 'YAML' : 'text'}
          {content.truncated ? ' (truncated)' : ''}
        </button>
      )}
    </Section>
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

      {ocm.signatures && <SignatureSection doc={doc} signatures={ocm.signatures} />}
    </>
  );
}

/**
 * Signatures with client-side verification. Paste a public key (PEM) or a
 * certificate and OCM Lens recomputes the normalised digest and checks the
 * RSA signature with crypto.subtle: no server, no upload. Honest by design:
 * a gap it cannot bridge shows "unverifiable" with a reason, never a false
 * green or red.
 */
function SignatureSection({ doc, signatures }: { doc: SbomDocument; signatures: OcmSignatureInfo[] }) {
  const [open, setOpen] = useState(false);
  const [pem, setPem] = useState('');
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<SignatureResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Results belong to the document they were computed for; drop them on switch.
  useEffect(() => {
    setResults(null);
    setError(null);
    setOpen(false);
    setPem('');
  }, [doc.id]);

  const verdictFor = (name: string | undefined, index: number): SignatureResult | undefined =>
    results?.find((r) => r.name === (name ?? 'signature')) ?? results?.[index];

  const runVerify = async () => {
    setBusy(true);
    setError(null);
    try {
      setResults(await verifyDocumentSignatures(doc, pem));
    } catch {
      setError('Could not verify against this key. Check that it is a PEM public key or certificate.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section
      title={`Signatures (${signatures.length})`}
      actions={
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="rounded border border-slate-200 px-1.5 py-0.5 text-[10px] text-slate-500 hover:border-accent-300 hover:text-accent-700 dark:border-slate-700 dark:text-slate-400 dark:hover:border-accent-700 dark:hover:text-accent-400"
        >
          {open ? 'Close' : 'Verify...'}
        </button>
      }
    >
      {open && (
        <div className="mb-2 space-y-1.5 rounded border border-slate-100 p-2 dark:border-slate-800">
          <label className="block text-xs text-slate-500 dark:text-slate-400">
            Public key or certificate (PEM). Nothing is uploaded: the check runs in your browser.
          </label>
          <textarea
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            spellCheck={false}
            rows={4}
            placeholder="-----BEGIN PUBLIC KEY-----"
            className="w-full resize-y rounded border border-slate-200 bg-transparent p-1.5 font-mono text-xs outline-none focus:border-accent-400 dark:border-slate-700 dark:bg-slate-900"
          />
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={busy || pem.trim().length === 0}
              onClick={() => void runVerify()}
              className="rounded bg-accent-600 px-2 py-0.5 text-xs text-white hover:bg-accent-700 disabled:opacity-40"
            >
              {busy ? 'Verifying...' : 'Verify'}
            </button>
            {results && (
              <span className="text-xs text-slate-400">
                Chain is NOT validated: a certificate is used only for its public key.
              </span>
            )}
          </div>
          {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
        </div>
      )}

      <div className="space-y-2">
        {signatures.map((sig, i) => {
          const result = verdictFor(sig.name, i);
          return (
            <div key={i} className="rounded border border-slate-100 px-2.5 py-1.5 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <span className="min-w-0 truncate text-[13px] font-medium">{sig.name ?? `signature ${i + 1}`}</span>
                <SignatureChip result={result} />
              </div>
              {result?.reason && (
                <p className="py-0.5 text-xs text-slate-500 dark:text-slate-400">{result.reason}</p>
              )}
              <FieldRow label="Algorithm" value={sig.algorithm} mono />
              <FieldRow label="Media type" value={sig.mediaType} mono />
              <FieldRow label="Issuer" value={sig.issuer} mono />
              {sig.digest && <DigestRows digest={sig.digest} inline />}
              {sig.value && (
                <div className="grid grid-cols-[9rem_1fr] items-baseline gap-x-3 py-1">
                  <div className="text-xs text-slate-400 dark:text-slate-500">Signature</div>
                  <div className="flex min-w-0 items-baseline gap-1 font-mono text-xs">
                    <span className="truncate" title={sig.value}>
                      {sig.value.length > 48 ? `${sig.value.slice(0, 48)}...` : sig.value}
                    </span>
                    <CopyButton text={sig.value} />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Section>
  );
}

function SignatureChip({ result }: { result?: SignatureResult }) {
  if (!result) return <Chip>not verified</Chip>;
  if (result.verdict === 'valid') return <Chip tone="ok">valid</Chip>;
  if (result.verdict === 'invalid') return <Chip tone="danger">invalid</Chip>;
  return <Chip tone="warn">unverifiable</Chip>;
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
