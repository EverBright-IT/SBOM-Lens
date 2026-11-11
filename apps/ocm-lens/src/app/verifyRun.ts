import type { AcceptanceSignatureEntry, SignatureResult } from '@sbomlens/core/ocm';
import { ocmCvId, referenceDigestChecker, verifyRawSignatures } from '@sbomlens/core/ocm';
import { loadTrustedKeys } from './trustedKeys';
import { useAppStore } from './store';

/**
 * One verification run over every signed component version: pinned keys
 * first (the first key that validates a signature vouches for it, by
 * label), then an optionally pasted key for whatever is still open. A
 * non-matching key never paints red on its own — "invalid" only surfaces
 * when SOME key was tried and the best outcome for that signature is a
 * cryptographic failure, which the entry's reason explains.
 *
 * A signature covers the component versions its descriptor references only
 * through the reference digests it records. It is called valid only when
 * those digests match what this delivery carries, all the way down: a
 * swapped component version below a signed one turns the verdict invalid,
 * one that cannot be compared turns it unverifiable.
 */
export async function runVerification(manualPem?: string): Promise<void> {
  const { delivery, actions } = useAppStore.getState();
  if (!delivery) return;
  const keys = loadTrustedKeys();
  const entries: AcceptanceSignatureEntry[] = [];

  // Duplicates included: a reference that could mean two different
  // descriptors is not one the signature vouches for.
  const delivered = new Map<string, Record<string, unknown>[]>();
  for (const cv of delivery.bundle.componentVersions) {
    const id = ocmCvId(cv.name, cv.version);
    delivered.set(id, [...(delivered.get(id) ?? []), cv.raw]);
  }
  const checkReferences = referenceDigestChecker(
    (componentName, version) => delivered.get(ocmCvId(componentName, version)) ?? [],
  );

  for (const cv of delivery.bundle.componentVersions) {
    const signatureCount = cv.signatures?.length ?? 0;
    if (signatureCount === 0) continue;

    const perKey: { label: string; results: SignatureResult[] }[] = [];
    for (const key of keys) {
      try {
        perKey.push({ label: key.label, results: await verifyRawSignatures(cv.raw, key.pem) });
      } catch {
        // An unimportable pinned key is skipped; pin-time validation catches most.
      }
    }
    let manual: SignatureResult[] | null = null;
    if (manualPem && manualPem.trim().length > 0) {
      try {
        manual = await verifyRawSignatures(cv.raw, manualPem);
      } catch {
        manual = null;
      }
    }

    const covered = async (entry: AcceptanceSignatureEntry): Promise<AcceptanceSignatureEntry> => {
      if (entry.verdict !== 'valid') return entry;
      const references = await checkReferences(cv.raw);
      if (references.verdict === 'match') return entry;
      return {
        ...entry,
        verdict: references.verdict === 'mismatch' ? 'invalid' : 'unverifiable',
        reason: references.reason,
      };
    };

    for (let i = 0; i < signatureCount; i++) {
      const name = cv.signatures![i]!.name ?? `signature ${i + 1}`;
      const pinnedValid = perKey
        .map((k) => ({ label: k.label, result: k.results[i] }))
        .find((k) => k.result?.verdict === 'valid');
      if (pinnedValid) {
        entries.push(await covered({ cvId: cv.id, name, verdict: 'valid', keyLabel: pinnedValid.label }));
        continue;
      }
      if (manual?.[i]) {
        const r = manual[i]!;
        entries.push(
          await covered({ cvId: cv.id, name, verdict: r.verdict, reason: r.reason, keyLabel: 'pasted key' }),
        );
        continue;
      }
      entries.push({
        cvId: cv.id,
        name,
        verdict: 'unverifiable',
        reason:
          keys.length > 0 ? 'no pinned key matches this signature' : 'no key available — pin or paste one',
      });
    }
  }

  actions.setVerification({ at: new Date().toISOString(), entries });
}
