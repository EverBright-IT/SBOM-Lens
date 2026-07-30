import { KeyImportError, spkiFromPem } from '@sbomlens/core/ocm';
import { host } from '../host/adapter';
import { pref } from './brand';

/**
 * Pinned signature keys: PEM public keys (or certificates, used for their
 * key only) the user has decided to trust. Documents whose signatures
 * verify against a pinned key show a green chip without any manual paste.
 *
 * Public keys are not secrets, so they live in prefs (VS Code globalState /
 * browser localStorage), namespaced per product like every other pref.
 * Imported only by the OCM detail UI, so the SBOM bundle never carries it.
 */
export interface TrustedKey {
  label: string;
  pem: string;
}

const STORE_PREF = 'trustedKeys';
const MAX_KEYS = 16;
const MAX_TOTAL_BYTES = 64 * 1024;

export function loadTrustedKeys(): TrustedKey[] {
  const raw = host().readPref(pref(STORE_PREF));
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
  host().persistPref(pref(STORE_PREF), JSON.stringify(keys));
}

/**
 * Pin a key. The label is the user's name for it ("acme-release"); pinning
 * an existing label replaces that key, which is how a rotated key updates.
 * The PEM must decode to something key-shaped now — a paste that could
 * never verify anything should fail here, not silently at load time.
 */
export function addTrustedKey(label: string, pem: string): { ok: true } | { ok: false; error: string } {
  const name = label.trim();
  if (name.length === 0) return { ok: false, error: 'The key needs a label.' };
  try {
    spkiFromPem(pem);
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof KeyImportError
          ? error.message
          : 'Not a PEM public key or certificate.',
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
