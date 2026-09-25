import type { CryptoElementExt, LoadedDocument } from '@sbomlens/core';
import { selectTarget } from '../navigate';
import { FieldRow, Section } from './FieldRow';

/**
 * CBOM detail: what a CycloneDX cryptographic asset states, rendered only
 * when the parser attached `crypto`. Field names follow cryptoProperties;
 * nothing here judges an algorithm, that is the crypto profiles' job and
 * they cite their sources.
 */
export function CryptoSection({ crypto, loaded }: { crypto: CryptoElementExt; loaded: LoadedDocument }) {
  const a = crypto.algorithm;
  const c = crypto.certificate;
  const m = crypto.material;
  const p = crypto.protocol;
  const nameOf = (ref: string) => loaded.document.elements.find((e) => e.spdxId === ref)?.name ?? ref;
  const refLink = (ref: string) => {
    const target = loaded.document.elements.find((e) => e.spdxId === ref);
    return target ? (
      <button
        type="button"
        onClick={() => selectTarget({ kind: 'element', elementId: target.id })}
        className="text-accent-700 hover:underline dark:text-accent-400"
      >
        {target.name}
      </button>
    ) : (
      <span className="font-mono">{ref}</span>
    );
  };

  return (
    <>
      <Section title={`Cryptographic asset: ${crypto.assetType ?? 'kind not stated'}`}>
        <FieldRow label="Asset type" value={crypto.assetType} />
        <FieldRow label="OID" value={crypto.oid} mono copyable />
        {a && (
          <>
            <FieldRow label="Primitive" value={a.primitive} />
            <FieldRow label="Family" value={a.family} />
            <FieldRow label="Parameter set" value={a.parameterSet} />
            <FieldRow label="Curve" value={a.ellipticCurve ?? a.curve} mono />
            <FieldRow label="Mode" value={a.mode} />
            <FieldRow label="Padding" value={a.padding} />
            <FieldRow label="Execution environment" value={a.executionEnvironment} />
            <FieldRow label="Platform" value={a.implementationPlatform} />
            <FieldRow label="Functions" value={a.cryptoFunctions?.join(', ')} />
            <FieldRow label="Certification" value={a.certificationLevel?.join(', ')} />
            <FieldRow
              label="Security level"
              value={
                a.classicalSecurityLevel !== undefined || a.nistQuantumSecurityLevel !== undefined
                  ? [
                      a.classicalSecurityLevel !== undefined ? `classical ${a.classicalSecurityLevel} bits` : undefined,
                      a.nistQuantumSecurityLevel !== undefined ? `NIST quantum category ${a.nistQuantumSecurityLevel}` : undefined,
                    ]
                      .filter(Boolean)
                      .join(' · ')
                  : undefined
              }
            />
          </>
        )}
        {c && (
          <>
            <FieldRow label="Subject" value={c.subjectName} mono copyable />
            <FieldRow label="Issuer" value={c.issuerName} mono />
            <FieldRow label="Serial number" value={c.serialNumber} mono copyable />
            <FieldRow label="Valid from" value={c.notValidBefore} />
            <FieldRow label="Valid until" value={c.notValidAfter} />
            <FieldRow label="Format" value={[c.certificateFormat, c.fileExtension].filter(Boolean).join(' · ') || undefined} />
            <FieldRow label="Lifecycle state" value={c.states?.join(', ')} />
            <FieldRow label="Fingerprint" value={c.fingerprint ? `${c.fingerprint.algorithm ?? ''} ${c.fingerprint.value ?? ''}`.trim() : undefined} mono copyable />
            <FieldRow label="Revoked" value={c.revocationDate} />
          </>
        )}
        {m && (
          <>
            <FieldRow label="Material type" value={m.type} />
            <FieldRow label="Identifier" value={m.id} mono copyable />
            <FieldRow label="Lifecycle state" value={m.state} />
            <FieldRow label="Size" value={m.size !== undefined ? `${m.size} bits` : undefined} />
            <FieldRow label="Format" value={m.format} />
            <FieldRow label="Created" value={m.creationDate} />
            <FieldRow label="Activated" value={m.activationDate} />
            <FieldRow label="Expires" value={m.expirationDate} />
            <FieldRow label="Secured by" value={m.securedBy ? [m.securedBy.mechanism, m.securedBy.algorithmRef ? `algorithm ${nameOf(m.securedBy.algorithmRef)}` : undefined].filter(Boolean).join(' · ') : undefined} />
          </>
        )}
        {p && (
          <>
            <FieldRow label="Protocol" value={p.type} />
            <FieldRow label="Version" value={p.version} />
          </>
        )}
      </Section>

      {p?.cipherSuites && p.cipherSuites.length > 0 && (
        <Section title={`Cipher suites (${p.cipherSuites.length})`}>
          <div className="space-y-1">
            {p.cipherSuites.map((suite, i) => (
              <div key={i} className="text-xs">
                <span className="font-mono text-slate-700 dark:text-slate-200">{suite.name ?? '(unnamed suite)'}</span>
                {suite.identifiers && suite.identifiers.length > 0 && (
                  <span className="ml-2 font-mono text-[10px] text-slate-400">{suite.identifiers.join(',')}</span>
                )}
                {suite.algorithms && suite.algorithms.length > 0 && (
                  <div className="mt-0.5 flex flex-wrap gap-x-2 text-slate-500 dark:text-slate-400">
                    {suite.algorithms.map((ref) => (
                      <span key={ref}>{refLink(ref)}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {crypto.related && crypto.related.length > 0 && (
        <Section title={`Related cryptographic assets (${crypto.related.length})`}>
          <div className="space-y-1">
            {crypto.related.map((rel, i) => (
              <div key={i} className="flex items-baseline gap-2 text-xs">
                <span className="shrink-0 text-slate-400 dark:text-slate-500">{rel.type}</span>
                <span className="min-w-0 break-all">{refLink(rel.ref)}</span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}
