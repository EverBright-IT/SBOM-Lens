import { useEffect, useState } from 'react';
import { acceptanceReport, digestSummary } from '@sbomlens/core/ocm';
import { saveBytes } from '../app/download';
import { runDigestChecks } from '../app/ingest';
import { useAppStore } from '../app/store';
import { addTrustedKey, loadTrustedKeys, removeTrustedKey } from '../app/trustedKeys';
import { runVerification } from '../app/verifyRun';
import { APP_VERSION } from '../version';
import { BUTTON_PRIMARY, BUTTON_SECONDARY, Chip, Section, formatBytes } from './bits';

/**
 * "Lieferung prüfen": one place that answers whether the delivery is intact
 * — blob digests (checked at load time, aggregated here), signatures
 * (verified against pinned or pasted keys), and the exportable acceptance
 * report that documents the answer.
 */

export function VerifyView() {
  const delivery = useAppStore((s) => s.delivery);
  const verification = useAppStore((s) => s.verification);
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const selectCv = useAppStore((s) => s.actions.selectCv);
  const [trusted, setTrusted] = useState(loadTrustedKeys);
  const [pem, setPem] = useState('');
  const [label, setLabel] = useState('');
  const [keyError, setKeyError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [digestRun, setDigestRun] = useState<{ done: number; total: number } | null>(null);

  const bundle = delivery?.bundle ?? null;
  const signedCvs = bundle?.componentVersions.filter((cv) => (cv.signatures?.length ?? 0) > 0) ?? [];

  // Auto-verify with pinned keys whenever the delivery or the key set changes.
  useEffect(() => {
    if (!bundle || signedCvs.length === 0) return;
    let cancelled = false;
    setRunning(true);
    void runVerification().finally(() => {
      if (!cancelled) setRunning(false);
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- rerun on delivery/key changes only
  }, [bundle, trusted]);

  if (!delivery || !bundle) return null;
  const digests = digestSummary(bundle);

  const checkDeferred = async () => {
    setDigestRun({ done: 0, total: bundle.digestsDeferred?.blobs ?? 0 });
    try {
      await runDigestChecks(undefined, (done, total) => setDigestRun({ done, total }));
    } finally {
      setDigestRun(null);
    }
  };

  const verifyWithPasted = async () => {
    setRunning(true);
    try {
      await runVerification(pem);
    } finally {
      setRunning(false);
    }
  };

  const pinKey = () => {
    const outcome = addTrustedKey(label, pem);
    if (!outcome.ok) {
      setKeyError(outcome.error);
      return;
    }
    setKeyError(null);
    setLabel('');
    setPem('');
    setTrusted(loadTrustedKeys());
  };

  const exportReport = (format: 'markdown' | 'json') => {
    const report = acceptanceReport({
      bundle,
      signatures: verification?.entries,
      toolVersion: APP_VERSION,
      generatedAt: new Date().toISOString(),
    });
    const base = bundle.fileName.replace(/\.(ctf|tar|tgz|gz|yaml|yml|json)+$/i, '');
    if (format === 'markdown') saveBytes(`${base}.acceptance.md`, 'text/markdown', report.markdown);
    else saveBytes(`${base}.acceptance.json`, 'application/json', JSON.stringify(report.json, null, 2));
  };

  const findArtifact = (cvId: string, artifactName: string) => {
    const cv = bundle.componentVersions.find((c) => c.id === cvId);
    if (!cv) return;
    const index = cv.resources.findIndex((r) => r.name === artifactName);
    if (index >= 0) selectArtifact({ cvId, role: 'resource', index });
    else {
      const sourceIndex = cv.sources.findIndex((s) => s.name === artifactName);
      if (sourceIndex >= 0) selectArtifact({ cvId, role: 'source', index: sourceIndex });
    }
  };

  return (
    <div className="mx-auto max-w-3xl p-4">
      <div className="mb-4 flex items-center gap-2">
        <h1 className="text-lg font-semibold">Verify delivery</h1>
        {running && <span className="text-xs text-slate-400">verifying...</span>}
        <span className="ml-auto flex gap-2">
          <button type="button" onClick={() => exportReport('markdown')} className={BUTTON_SECONDARY}>
            Export report (Markdown)
          </button>
          <button type="button" onClick={() => exportReport('json')} className={BUTTON_SECONDARY}>
            JSON
          </button>
        </span>
      </div>

      <Section title="Integrity — blob digests">
        {bundle.digestsDeferred && (
          <div className="mb-2 flex items-center gap-2 rounded border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-sm dark:border-amber-800 dark:bg-amber-950">
            <span className="text-amber-800 dark:text-amber-300">
              {bundle.digestsDeferred.blobs} blob digest check(s) deferred at load (
              {formatBytes(bundle.digestsDeferred.bytes)} to read).
            </span>
            {digestRun ? (
              <span className="ml-auto flex items-center gap-2 text-xs text-amber-800 dark:text-amber-300">
                <progress value={digestRun.done} max={digestRun.total} className="h-2 w-28" />
                {digestRun.done}/{digestRun.total}
              </span>
            ) : (
              <button type="button" onClick={() => void checkDeferred()} className={`${BUTTON_PRIMARY} ml-auto`}>
                Check now
              </button>
            )}
          </div>
        )}
        <p className="text-sm">
          {digests.checked === 0 && digests.unchecked === 0 ? (
            'No resources with bytes in this bundle.'
          ) : digests.mismatch.length === 0 ? (
            <>
              <Chip tone="ok">all match</Chip>{' '}
              <span className="text-slate-500 dark:text-slate-400">
                {digests.match} declared digest(s) match the delivered bytes
                {digests.unchecked > 0 ? `; ${digests.unchecked} declared but not checkable` : ''}.
              </span>
            </>
          ) : (
            <>
              <Chip tone="danger">{digests.mismatch.length} mismatch(es)</Chip>{' '}
              <span className="text-slate-500 dark:text-slate-400">
                the delivered bytes do not match the descriptor:
              </span>
            </>
          )}
        </p>
        {digests.mismatch.length > 0 && (
          <ul className="mt-1.5 space-y-0.5 text-sm">
            {digests.mismatch.map((m, i) => (
              <li key={i}>
                <button
                  type="button"
                  onClick={() => findArtifact(m.cvId, m.artifact)}
                  className="font-mono text-xs text-red-700 hover:underline dark:text-red-400"
                >
                  {m.cvId}: {m.artifact} →
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`Signatures (${signedCvs.length} signed component version(s))`}>
        {signedCvs.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            This delivery carries no signatures. Component and artifact digests above are the available
            integrity evidence.
          </p>
        ) : (
          <div className="space-y-2">
            {signedCvs.map((cv) => {
              const entries = verification?.entries.filter((e) => e.cvId === cv.id) ?? [];
              return (
                <div key={cv.id} className="rounded border border-slate-100 px-2.5 py-1.5 dark:border-slate-800">
                  <button
                    type="button"
                    onClick={() => selectCv(cv.id)}
                    className="font-mono text-xs text-slate-500 hover:text-accent-700 dark:text-slate-400 dark:hover:text-accent-400"
                  >
                    {cv.id}
                  </button>
                  {cv.signatures!.map((sig, i) => {
                    const entry = entries.find((e) => e.name === (sig.name ?? `signature ${i + 1}`));
                    return (
                      <div key={i} className="mt-1 flex items-center gap-2 text-sm">
                        <span className="font-medium">{sig.name ?? `signature ${i + 1}`}</span>
                        <span className="text-xs text-slate-400">{sig.algorithm ?? ''}</span>
                        {entry ? (
                          entry.verdict === 'valid' ? (
                            <Chip tone="ok">valid{entry.keyLabel ? ` · ${entry.keyLabel}` : ''}</Chip>
                          ) : entry.verdict === 'invalid' ? (
                            <Chip tone="danger" title={entry.reason}>
                              invalid
                            </Chip>
                          ) : (
                            <Chip tone="warn" title={entry.reason}>
                              unverifiable
                            </Chip>
                          )
                        ) : (
                          <Chip>not verified</Chip>
                        )}
                        {entry?.reason && entry.verdict !== 'valid' && (
                          <span className="text-xs text-slate-400">{entry.reason}</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        )}
      </Section>

      {signedCvs.length > 0 && (
        <Section title="Keys">
          {trusted.length > 0 && (
            <div className="mb-2">
              <div className="mb-0.5 text-xs text-slate-400">Pinned keys verify every delivery automatically.</div>
              {trusted.map((key) => (
                <div key={key.label} className="flex items-center gap-2 py-0.5 text-sm">
                  <span className="font-mono text-xs">{key.label}</span>
                  <button
                    type="button"
                    onClick={() => setTrusted(removeTrustedKey(key.label))}
                    className="text-xs text-slate-400 hover:text-red-600 dark:hover:text-red-400"
                  >
                    remove
                  </button>
                </div>
              ))}
            </div>
          )}
          <textarea
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            spellCheck={false}
            rows={4}
            placeholder="-----BEGIN PUBLIC KEY----- (or a certificate; used only for its key, chain NOT validated)"
            className="w-full resize-y rounded border border-slate-200 bg-transparent p-1.5 font-mono text-xs outline-none focus:border-accent-400 dark:border-slate-700"
          />
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={running || pem.trim().length === 0}
              onClick={() => void verifyWithPasted()}
              className={BUTTON_PRIMARY}
            >
              Verify with this key
            </button>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Label, e.g. ecme-release"
              className="w-44 rounded border border-slate-200 bg-transparent px-1.5 py-1 text-xs outline-none focus:border-accent-400 dark:border-slate-700"
            />
            <button
              type="button"
              disabled={pem.trim().length === 0 || label.trim().length === 0}
              onClick={pinKey}
              className={BUTTON_SECONDARY}
            >
              Pin key
            </button>
            <span className="text-xs text-slate-400">Nothing is uploaded: checks run in your browser.</span>
          </div>
          {keyError && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{keyError}</p>}
        </Section>
      )}
    </div>
  );
}
