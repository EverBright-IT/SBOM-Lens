import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';

/**
 * Shared plumbing for the spec lints (SPDX 2.x, SPDX 3.x, CycloneDX), modelled
 * on the OCM one in parse/ocm/validate.ts: hand-rolled checks instead of a
 * schema engine, so the messages are human sentences and the parser stays
 * tolerant. Two rules hold everywhere:
 *
 *   1. Everything is a WARNING. A document never fails its lint; it loads and
 *      the findings sit next to it.
 *   2. Per-item findings aggregate into ONE diagnostic (count plus the first
 *      three subjects). A BOM with 4000 packages must not produce 4000 rows.
 *
 * Codes carry the `_SCHEMA_` infix, which is what `isSpecFinding` keys on to
 * tell "your document violates the spec" apart from "the parser had trouble".
 */

/** Codes with this infix are spec findings, not parser notes. */
const SPEC_LINT_INFIX = '_SCHEMA_';

export function isSpecFinding(code: string): boolean {
  return code.includes(SPEC_LINT_INFIX);
}

export interface SpecLint {
  /** Collected findings, in emission order. */
  readonly diagnostics: Diagnostic[];
  /** One finding about the document as a whole. */
  warn(code: string, message: string): void;
  /**
   * One finding about `subjects` items. Emits nothing when the list is empty;
   * `render` receives the count and a ready-made "a, b, c, ..." sample.
   */
  warnAll(code: string, subjects: string[], render: (count: number, sample: string) => string): void;
}

export function createLint(): SpecLint {
  const diagnostics: Diagnostic[] = [];
  return {
    diagnostics,
    warn(code, message) {
      diagnostics.push(diag('warning', code, message));
    },
    warnAll(code, subjects, render) {
      if (subjects.length === 0) return;
      diagnostics.push(diag('warning', code, render(subjects.length, sample(subjects))));
    },
  };
}

/** "a, b, c, ..." — the first three subjects, so a message stays readable. */
export function sample(subjects: string[]): string {
  return `${subjects.slice(0, 3).join(', ')}${subjects.length > 3 ? ', ...' : ''}`;
}

/**
 * Hex digest lengths of the hash algorithms SPDX 2.3 (§ 7.10), SPDX 3 and
 * CycloneDX name. Keys are normalised (uppercase, separators stripped), so one
 * table serves `SHA3-256`, `sha3_256`, and `SHA3256` alike. Algorithms with
 * variable output (MD6, BLAKE3) map to `undefined`: the name is legal, the
 * length carries no expectation.
 */
const HEX_LENGTHS: Record<string, number | undefined> = {
  MD2: 32,
  MD4: 32,
  MD5: 32,
  MD6: undefined,
  SHA1: 40,
  SHA224: 56,
  SHA256: 64,
  SHA384: 96,
  SHA512: 128,
  SHA3256: 64,
  SHA3384: 96,
  SHA3512: 128,
  BLAKE2B256: 64,
  BLAKE2B384: 96,
  BLAKE2B512: 128,
  BLAKE3: undefined,
  ADLER32: 8,
};

const HEX = /^[0-9a-fA-F]+$/;

/**
 * Why this (algorithm, value) pair cannot be a digest, or undefined when it is
 * plausible. Unknown algorithm names are reported, since a consumer cannot
 * verify what it cannot name.
 */
export function checksumProblem(algorithm: string, value: string): string | undefined {
  const key = algorithm.trim().toUpperCase().replace(/[-_]/g, '');
  if (!(key in HEX_LENGTHS)) return `unknown algorithm "${algorithm}"`;
  if (!HEX.test(value)) return `"${algorithm}" value is not hexadecimal`;
  const expected = HEX_LENGTHS[key];
  if (expected !== undefined && value.length !== expected) {
    return `"${algorithm}" value is ${value.length} hex chars, expected ${expected}`;
  }
  return undefined;
}

/** An absolute URI carries a scheme; SPDX namespaces additionally forbid a fragment. */
export function isAbsoluteUri(value: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(value);
}

const LICENSE_LITERALS = new Set(['NONE', 'NOASSERTION']);
const OPERATORS = new Set(['AND', 'OR', 'WITH']);
const LOWERCASE_OPERATORS = new Set(['and', 'or', 'with']);
/** idstring per SPDX Annex D: letters, digits, `.`, `-`; `+` marks "or later". */
const ID_TOKEN = /^[A-Za-z0-9.\-+]+$/;

/**
 * Grammar of an SPDX license expression (Annex D) — deliberately WITHOUT the
 * SPDX license list: we check that the expression can be parsed at all
 * (operators, parentheses, LicenseRef shape), never whether an identifier is a
 * real license. Rating licenses is a stated non-goal, and a vendored list
 * would go stale between releases.
 *
 * Returns a human reason, or undefined when the expression parses.
 */
export function licenseExpressionError(raw: string): string | undefined {
  const expr = raw.trim();
  if (expr === '') return 'empty expression';
  if (LICENSE_LITERALS.has(expr)) return undefined;

  const tokens = expr
    .replace(/\(/g, ' ( ')
    .replace(/\)/g, ' ) ')
    .split(/\s+/)
    .filter((t) => t !== '');

  let depth = 0;
  // The expression alternates operands and operators; `expectOperand` tracks
  // which one is due, which catches both "MIT MIT" and a trailing "AND".
  let expectOperand = true;
  let lastWasWith = false;

  for (const token of tokens) {
    if (token === '(') {
      if (!expectOperand) return 'missing operator before "("';
      if (lastWasWith) return 'WITH must be followed by an exception identifier, not "("';
      depth++;
      continue;
    }
    if (token === ')') {
      if (expectOperand) return 'empty or unfinished group before ")"';
      depth--;
      if (depth < 0) return 'unbalanced parentheses';
      continue;
    }
    if (OPERATORS.has(token)) {
      if (expectOperand) return `operator "${token}" without a left-hand license`;
      expectOperand = true;
      lastWasWith = token === 'WITH';
      continue;
    }
    if (LOWERCASE_OPERATORS.has(token)) {
      return `operators must be uppercase ("${token.toUpperCase()}", not "${token}")`;
    }
    // An operand. The two reference forms carry a `:` and are checked first,
    // since a plain idstring may not contain one.
    if (!expectOperand) return `missing operator before "${token}"`;
    if (token.startsWith('DocumentRef-')) {
      if (!/^DocumentRef-[A-Za-z0-9.-]+:LicenseRef-[A-Za-z0-9.-]+$/.test(token)) {
        return `"${token}" is not a valid DocumentRef-…:LicenseRef-… reference`;
      }
    } else if (token.startsWith('LicenseRef-')) {
      if (!/^LicenseRef-[A-Za-z0-9.-]+$/.test(token)) {
        return `"${token}" is not a valid LicenseRef-… identifier`;
      }
    } else if (!ID_TOKEN.test(token)) {
      return `"${token}" is not a valid license identifier`;
    } else if (LICENSE_LITERALS.has(token)) {
      // NONE/NOASSERTION stand alone; inside a compound they are meaningless.
      return `"${token}" cannot be combined with other licenses`;
    }
    expectOperand = false;
    lastWasWith = false;
  }

  if (expectOperand) return 'expression ends with an operator';
  if (depth !== 0) return 'unbalanced parentheses';
  return undefined;
}
