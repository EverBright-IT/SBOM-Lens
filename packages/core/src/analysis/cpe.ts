/**
 * Conservative CPE normalisation for VEX matching — the CPE sibling of
 * purlMatchKey. BSI-CERT advisories frequently identify products by CPE
 * rather than purl, so CSAF (and OpenVEX identifiers) may name a product
 * only this way, and SPDX inventories carry CPEs as SECURITY external
 * references.
 *
 * Deliberately NOT a full NIST IR 7696 matcher: no wildcards beyond the
 * version, no update/edition/target comparison, no version ranges. Both
 * sides normalise to part:vendor:product plus an optional concrete version;
 * anything the normalisation cannot pin down is unmatchable rather than
 * guessed.
 */

export interface CpeMatchKey {
  /** `part:vendor:product`, lowercase, unescaped/decoded. */
  key: string;
  /** Concrete version; undefined covers every version (ANY). */
  version?: string;
}

/**
 * Parses a CPE 2.3 formatted string (`cpe:2.3:a:vendor:product:version:...`)
 * or a CPE 2.2 URI (`cpe:/a:vendor:product:version:...`). Returns undefined
 * for anything else, for wildcarded vendor/product (matching "every product
 * of a vendor" is a guess, not a statement), and for non-a/h/o parts.
 */
export function cpeMatchKey(cpe: string): CpeMatchKey | undefined {
  const lower = cpe.trim().toLowerCase();
  let components: string[];
  if (lower.startsWith('cpe:2.3:')) {
    components = splitEscaped(lower.slice('cpe:2.3:'.length)).map(unescape23);
  } else if (lower.startsWith('cpe:/')) {
    components = lower
      .slice('cpe:/'.length)
      .split(':')
      .map((c) => decodeComponent(c));
  } else {
    return undefined;
  }

  const [part, vendor, product, version] = components;
  if (part !== 'a' && part !== 'h' && part !== 'o') return undefined;
  if (!isConcrete(vendor) || !isConcrete(product)) return undefined;

  const key = `${part}:${vendor}:${product}`;
  const v = version === undefined || version === '' || version === '*' || version === '-' ? undefined : version;
  return v !== undefined ? { key, version: v } : { key };
}

/** Split a 2.3 formatted string on ':' while honouring backslash escapes. */
function splitEscaped(text: string): string[] {
  const parts: string[] = [];
  let current = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '\\' && i + 1 < text.length) {
      current += ch + text[i + 1]!;
      i++;
    } else if (ch === ':') {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}

/** `\x` → `x` (2.3 quoting). Underscores stand for spaces in practice — kept. */
function unescape23(component: string): string {
  return component.replace(/\\(.)/g, '$1');
}

function decodeComponent(component: string): string {
  try {
    return decodeURIComponent(component);
  } catch {
    return component;
  }
}

/** Concrete = present and not a wildcard; a `*`/`?` inside is a pattern. */
function isConcrete(component: string | undefined): component is string {
  if (component === undefined || component === '' || component === '*' || component === '-') return false;
  // Unescaped pattern characters make this a wildcard expression, not a name.
  return !/(?<!\\)[*?]/.test(component);
}
