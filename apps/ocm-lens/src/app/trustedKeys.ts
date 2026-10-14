import { KeyImportError, spkiFromPem } from '@sbomlens/core/ocm';
import { persistPref, readPref } from './prefs';

/**
 * Pinned signature keys: PEM public keys (or certificates, used for their
 * key only) the user has decided to trust. Every delivery is verified
 * against them automatically. Ported from OCM Lens 1.x — the pref key is
 * deliberately the same (`ocmlens.trustedKeys`), so keys pinned in 1.x on
 * this origin keep working after the 2.0 switch.
 *
 * Public keys are not secrets, so prefs are the right home.
 */
export interface TrustedKey {
  label: string;
  pem: string;
}

const STORE_PREF = 'ocmlens.trustedKeys';
const MAX_KEYS = 16;
const MAX_TOTAL_BYTES = 64 * 1024;

export function loadTrustedKeys(): TrustedKey[] {
  const raw = readPref(STORE_PREF);
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (k): k is TrustedKey =>
        typeof k === 'object' &&
        k !== null &&
        typeof (k as TrustedKey).label === 'string' &&
        typeof (k as TrustedKey).pem === 'string',
    );
  } catch {
    return [];
  }
}

function save(keys: TrustedKey[]): void {
  persistPref(STORE_PREF, JSON.stringify(keys));
}

/** Pinning an existing label replaces that key — how a rotated key updates. */
export function addTrustedKey(label: string, pem: string): { ok: true } | { ok: false; error: string } {
  const name = label.trim();
  if (name.length === 0) return { ok: false, error: 'The key needs a label.' };
  try {
    spkiFromPem(pem);
  } catch (error) {
    return {
      ok: false,
      error: error instanceof KeyImportError ? error.message : 'Not a PEM public key or certificate.',
    };
  }
  const keys = loadTrustedKeys().filter((k) => k.label !== name);
  keys.push({ label: name, pem });
  if (keys.length > MAX_KEYS) {
    return { ok: false, error: `At most ${MAX_KEYS} pinned keys; remove one first.` };
  }
  if (JSON.stringify(keys).length > MAX_TOTAL_BYTES) {
    return { ok: false, error: 'Pinned keys exceed the 64 KB budget; remove one first.' };
  }
  save(keys);
  return { ok: true };
}

export function removeTrustedKey(label: string): TrustedKey[] {
  const keys = loadTrustedKeys().filter((k) => k.label !== label);
  save(keys);
  return keys;
}
