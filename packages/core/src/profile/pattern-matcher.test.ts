import { describe, expect, it } from 'vitest';
import { AUTOMOTIVE_SBOM_PROFILE } from './automotive';
import { BSI_TR_03183_PROFILE } from './bsi';
import { BSI_LICENSING_PROFILE } from './bsi-licensing';
import { CISA_2026_PROFILE } from './cisa2026';
import { CRYPTO_BSI_TR02102_PROFILE } from './crypto-bsi-tr02102';
import { CRYPTO_DORA_PROFILE } from './crypto-dora';
import { CRYPTO_EU_ROADMAP_PROFILE } from './crypto-eu-roadmap';
import { CRYPTO_PCI_PROFILE } from './crypto-pci';
import { FDA_524B_PROFILE } from './fda';
import { G7_AI_SBOM_PROFILE } from './g7-ai';
import { NTIA_PROFILE } from './ntia';
import { OCM_ESSENTIALS_PROFILE } from './ocm';
import type { PatternBudget, PatternMatcher } from './pattern-matcher';
import { PATTERN_PROGRAM_MAX, compilePattern } from './pattern-matcher';

function matcher(pattern: string): PatternMatcher {
  const compiled = compilePattern(pattern);
  if (!compiled.ok) throw new Error(`${JSON.stringify(pattern)} was refused: ${compiled.reason}`);
  return compiled.matcher;
}

const reasonOf = (pattern: string) => {
  const compiled = compilePattern(pattern);
  return compiled.ok ? 'accepted' : compiled.reason;
};

/** The matcher's answer next to RegExp's, for values short enough that RegExp is safe. */
function expectSameAsRegExp(pattern: string, values: readonly string[]): void {
  const m = matcher(pattern);
  const regex = new RegExp(pattern);
  for (const value of values) {
    expect(m.test(value), `/${pattern}/ on ${JSON.stringify(value)}`).toBe(regex.test(value));
  }
}

/** Steps one test takes, measured through a budget. */
function stepsOf(m: PatternMatcher, value: string): { matched: boolean; steps: number } {
  const budget: PatternBudget = { remaining: Number.MAX_SAFE_INTEGER };
  const matched = m.test(value, budget);
  return { matched, steps: Number.MAX_SAFE_INTEGER - budget.remaining };
}

const BUILT_IN_PATTERNS = [
  AUTOMOTIVE_SBOM_PROFILE,
  BSI_TR_03183_PROFILE,
  BSI_LICENSING_PROFILE,
  CISA_2026_PROFILE,
  CRYPTO_BSI_TR02102_PROFILE,
  CRYPTO_DORA_PROFILE,
  CRYPTO_EU_ROADMAP_PROFILE,
  CRYPTO_PCI_PROFILE,
  FDA_524B_PROFILE,
  G7_AI_SBOM_PROFILE,
  NTIA_PROFILE,
  OCM_ESSENTIALS_PROFILE,
].flatMap((profile) => profile.checks.flatMap((check) => ('pattern' in check && check.pattern ? [check.pattern] : [])));

// docs/compliance-profiles.md
const DOCUMENTED_PATTERNS = ['^https://sbom\\.acme\\.example/', '^(Organization: )?ACME', '^(3[0-9]{3}|[4-9][0-9]{3})$'];

describe('compilePattern: the answer RegExp gives', () => {
  it('agrees with RegExp on the built-in profiles and the documented examples', () => {
    expect(BUILT_IN_PATTERNS.length).toBeGreaterThan(20);
    const values = [
      '',
      'Organization: ACME Corp (security@acme.example)',
      'Person: Jane Doe (jane@example.org)',
      'Tool: syft-1.4.0',
      'Organization: ACME Corp',
      'https://sbom.acme.example/spdx/app-1.0.0',
      'ACME Corporation',
      '2048',
      '3072',
      '4096',
      '256',
      'RSA-3072',
      'ML-KEM-768',
      'ml-dsa-65',
      'secp256r1',
      'brainpoolP384r1',
      'AES-256-GCM',
      'SHA-512',
      'TLSv1.3',
      'bsi:component:effectiveLicense=Apache-2.0',
      'bsi:component:effectiveLicence=NOASSERTION',
      'other=1\nbsi:component:effectiveLicense=NONE\nmore=2',
      'other=1\nbsi:component:effectiveLicense=MIT\nbsi:component:filename=app.jar',
      'bsi:component:effectiveLicense=NONEXISTENT-1.0',
      'pkg:npm/%40acme/web@2.1.0',
      '1.2.3',
      'MIT OR Apache-2.0',
    ];
    for (const pattern of [...BUILT_IN_PATTERNS, ...DOCUMENTED_PATTERNS]) expectSameAsRegExp(pattern, values);
  });

  it('agrees on the syntax a pattern without flags can use', () => {
    const values = ['', 'a', 'ab', 'abc', 'aab', 'ba', 'b', 'a b', 'a-b', 'ab\ncd', '\n', '1', 'a1', '_', 'A', 'é', 'a b', ' ', 'aaa', 'abab', 'x'];
    for (const pattern of [
      '',
      'a',
      '^a',
      'a$',
      '^$',
      '^a|b$',
      'a|',
      '|a',
      '(a|b)c',
      'a*',
      'a+b',
      'a?b',
      'a{2}',
      'a{2,}',
      'a{1,2}b',
      'a{0}b',
      'a{0,0}',
      'a*?b',
      'a+?',
      'a??b',
      'a{1,2}?b',
      '.',
      '^.$',
      '^.+$',
      '[ab]',
      '[^ab]',
      '[a-c]+',
      '[]',
      '[^]',
      '^[^]$',
      '[-a]',
      '[a-]',
      '[\\d-z]',
      '[a\\-b]',
      '[\\b]',
      '[\\]]',
      '\\d',
      '\\D',
      '\\w+',
      '\\W',
      '\\s',
      '\\S+',
      '\\bab',
      'a\\b',
      '\\Ba',
      '\\b',
      '\\B',
      '^\\b',
      '\\n',
      '\\x61',
      '\\u0061',
      '\\u00e9',
      '\\0',
      '\\cJ',
      '\\.',
      '\\-',
      'a{',
      'a{1',
      'a{,2}',
      '}',
      ']',
      '(?:a|b)+',
      '(?<name>a)b',
      '(a)(b)?',
      '(a*)*',
      '(a+)+$',
      '(a|a)+$',
      '(a|ab)+$',
      '(a?){3}b',
      '((a|b)*c)?',
      '(^a)|(b$)',
      '(^|\\n)c',
      'a(?=b)',
      'a(?!b)',
      '(?<=a)b',
      '(?<!a)b',
      '^(?!.*b).*$',
      '^(?=.*a)(?=.*b)',
      '(?<=^a)b',
      'a(?=b$)',
      '(?=a)*b',
      '(?=a)+a',
      '(?!a)+b',
      'a(?=b(?=c))',
      'a(?=b(?!c))',
      '(?<=(?<!b)a)b',
      '(?<=a(?=b))b',
      '(?=\\b)a',
      '(?<=\\n)c',
      '(?<![^])a',
      '(?![^])',
      '\\p',
      'a\\u{1,2}',
    ]) {
      expectSameAsRegExp(pattern, values);
    }
  });

  it('agrees with a plain backtracking matcher, and with RegExp, on random patterns and values', () => {
    // Three voices. The matcher is compared with a second, deliberately naive
    // implementation that never sees the pattern text: the generator builds a
    // tree, the reference walks that tree with backtracking, and the matcher
    // gets the tree written out as a pattern. RegExp is the third voice, and
    // not the judge: engines have bugs of their own on patterns like these
    // (V8 answers false for /\D.[^]+?[^]^|/ on "c-c", though the empty
    // alternative matches anywhere; JavaScriptCore answers true).
    type Ref =
      | { k: 'char'; has: (c: number) => boolean }
      | { k: 'assert'; holds: (s: string, i: number) => boolean }
      | { k: 'seq'; items: Ref[] }
      | { k: 'alt'; items: Ref[] }
      | { k: 'rep'; item: Ref; min: number; max: number }
      | { k: 'look'; ahead: boolean; negated: boolean; body: Ref };
    type Built = { src: string; ref: Ref };

    const run = (t: Ref, s: string, i: number, then: (j: number) => boolean): boolean => {
      switch (t.k) {
        case 'char':
          return i < s.length && t.has(s.charCodeAt(i)) && then(i + 1);
        case 'assert':
          return t.holds(s, i) && then(i);
        case 'seq': {
          const from = (n: number, j: number): boolean =>
            n === t.items.length ? then(j) : run(t.items[n]!, s, j, (x) => from(n + 1, x));
          return from(0, i);
        }
        case 'alt':
          return t.items.some((item) => run(item, s, i, then));
        case 'rep': {
          // A round that takes nothing counts while rounds are still required
          // (an assertion may hold here and not later), and is pointless after.
          const round = (count: number, j: number): boolean =>
            (count < t.max && run(t.item, s, j, (x) => (x !== j || count < t.min) && round(count + 1, x))) ||
            (count >= t.min && then(j));
          return round(0, i);
        }
        case 'look': {
          let found = false;
          if (t.ahead) found = run(t.body, s, i, () => true);
          else for (let j = i; j >= 0 && !found; j--) found = run(t.body, s, j, (x) => x === i);
          return found !== t.negated && then(i);
        }
      }
    };
    const reference = (t: Ref, s: string): boolean => {
      for (let i = 0; i <= s.length; i++) if (run(t, s, i, () => true)) return true;
      return false;
    };

    // A fixed seed: the same patterns on every run.
    let seed = 0x5b0a11;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)]!;

    const isWordChar = (c: number) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
    const boundary = (s: string, i: number) =>
      (i > 0 && isWordChar(s.charCodeAt(i - 1))) !== (i < s.length && isWordChar(s.charCodeAt(i)));
    const literal = (src: string, char: string): Built => ({ src, ref: { k: 'char', has: (c) => c === char.charCodeAt(0) } });
    const LETTERS = [literal('a', 'a'), literal('a', 'a'), literal('b', 'b'), literal('c', 'c'), literal('1', '1'), literal('-', '-'), literal(' ', ' '), literal('\\n', '\n'), literal('_', '_')];
    // What a class holds is asked of RegExp one character at a time, where engines agree.
    const CLASSES = ['.', '[ab]', '[^a]', '[a-c]', '[^\\n]', '\\d', '\\w', '\\s', '\\D', '\\W', '\\S', '[\\w-]', '[^\\d ]', '[a\\-1]', '[]', '[^]'].map(
      (src): Built => {
        const one = new RegExp(`^${src}$`);
        return { src, ref: { k: 'char', has: (c) => one.test(String.fromCharCode(c)) } };
      },
    );
    const ASSERTIONS: Built[] = [
      { src: '^', ref: { k: 'assert', holds: (_s, i) => i === 0 } },
      { src: '$', ref: { k: 'assert', holds: (s, i) => i === s.length } },
      { src: '\\b', ref: { k: 'assert', holds: boundary } },
      { src: '\\B', ref: { k: 'assert', holds: (s, i) => !boundary(s, i) } },
    ];
    const QUANTIFIERS: [src: string, min: number, max: number][] = [
      ['*', 0, Infinity],
      ['+', 1, Infinity],
      ['?', 0, 1],
      ['{2}', 2, 2],
      ['{1,2}', 1, 2],
      ['{0,}', 0, Infinity],
      ['{2,}', 2, Infinity],
      ['*?', 0, Infinity],
      ['+?', 1, Infinity],
      ['??', 0, 1],
      ['{0,2}?', 0, 2],
    ];
    let names = 0;
    // Repetitions nest at most twice, so the two backtracking voices stay fast on these short values.
    const alt = (depth: number, repeats: number): Built => {
      const branches = Array.from({ length: 1 + Math.floor(random() * 2.4) }, () => seq(depth, repeats));
      return { src: branches.map((b) => b.src).join('|'), ref: { k: 'alt', items: branches.map((b) => b.ref) } };
    };
    const seq = (depth: number, repeats: number): Built => {
      const terms = Array.from({ length: Math.floor(random() * 4.5) }, () => term(depth, repeats));
      return { src: terms.map((t) => t.src).join(''), ref: { k: 'seq', items: terms.map((t) => t.ref) } };
    };
    const repeated = (atom: Built, [src, min, max]: [string, number, number]): Built => ({
      src: atom.src + src,
      ref: { k: 'rep', item: atom.ref, min, max },
    });
    const term = (depth: number, repeats: number): Built => {
      const roll = random();
      if (roll < 0.08) return pick(ASSERTIONS);
      if (roll < 0.16 && depth < 2) {
        const open = pick(['(?=', '(?!', '(?<=', '(?<!']);
        const body = alt(depth + 1, repeats);
        const look: Built = {
          src: `${open}${body.src})`,
          ref: { k: 'look', ahead: open.length === 3, negated: open.endsWith('!'), body: body.ref },
        };
        // Annex B lets a lookahead be repeated, a lookbehind not.
        return open.length === 3 && random() < 0.2 ? repeated(look, pick(QUANTIFIERS.slice(0, 3))) : look;
      }
      const quantifier = repeats < 2 && random() < 0.4 ? pick(QUANTIFIERS) : undefined;
      let atom: Built;
      if (roll < 0.34 && depth < 3) {
        const body = alt(depth + 1, repeats + (quantifier ? 1 : 0));
        atom = { src: `${pick(['(', '(?:', `(?<n${names++}>`])}${body.src})`, ref: body.ref };
      } else if (roll < 0.6) atom = pick(CLASSES);
      else atom = pick(LETTERS);
      return quantifier ? repeated(atom, quantifier) : atom;
    };
    const VALUE_LETTERS = ['a', 'a', 'b', 'c', '1', '-', ' ', '\n', '_'];
    const value = () => Array.from({ length: Math.floor(random() * 10) }, () => pick(VALUE_LETTERS)).join('');

    let compared = 0;
    const regExpDiffers: string[] = [];
    for (let round = 0; round < 6000; round++) {
      const built = alt(0, 0);
      const regex = new RegExp(built.src);
      const compiled = compilePattern(built.src);
      // The generator writes nothing the matcher refuses.
      if (!compiled.ok) throw new Error(`/${built.src}/ was refused: ${compiled.reason}`);
      expect(compiled.matcher.size).toBeLessThanOrEqual(PATTERN_PROGRAM_MAX);
      for (let i = 0; i < 6; i++) {
        const v = value();
        const expected = reference(built.ref, v);
        if (compiled.matcher.test(v) !== expected) {
          throw new Error(`/${built.src}/ on ${JSON.stringify(v)}: the reference says ${expected}`);
        }
        if (regex.test(v) !== expected) regExpDiffers.push(`/${built.src}/ on ${JSON.stringify(v)}`);
        compared++;
      }
    }
    expect(compared).toBe(36000);
    // RegExp sides with the other two but for a handful of engine oddities.
    expect(regExpDiffers.length, regExpDiffers.slice(0, 5).join('\n')).toBeLessThan(compared / 1000);
  }, 60000);

  it('reads escapes, classes and braces as RegExp does, on random pieces of syntax', () => {
    // The tree test above writes well-formed patterns only. This one glues
    // pieces of syntax together at random, to hold the parser against the
    // corners RegExp accepts without flags (Annex B): literal braces and
    // brackets, hyphens next to class escapes, octal, hex and control
    // escapes. Whatever RegExp rejects is skipped; whatever it accepts, the
    // matcher either refuses for a stated reason or answers the same.
    let seed = 0x0ddba11;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)]!;
    const PIECES = [
      'a', 'b', '-', '1', ' ', 'x', ',', '.', '|', '(', '(?:', ')', '[', '[^', ']', '{', '}', '*', '+', '?',
      '{2}', '{1,}', '{1,2}', '{,2}', '{1', '\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\b', '\\B', '\\n', '\\t',
      '\\x61', '\\x6', '\\u0062', '\\u00', '\\cJ', '\\0', '\\07', '\\.', '\\-', '\\/', '\\]', '\\[', '\\{', '\\\\', '\\p', 'a-b', '\\d-x',
    ];
    const VALUES = ['', 'a', 'b', 'ab', 'a-b', '1', ' ', 'x', ',', '.', '\n', '\t', '\0', '\x07', '\b', '/', ']', '[', '{', '}', '\\', 'p', '{2}', 'a{1', 'aa', 'a1-x', 'u00', 'x6'];
    const refusals = new Set<string>();
    let compared = 0;
    for (let round = 0; round < 20000; round++) {
      const pattern = Array.from({ length: 1 + Math.floor(random() * 7) }, () => pick(PIECES)).join('');
      let regex: RegExp;
      try {
        regex = new RegExp(pattern);
      } catch {
        continue;
      }
      const compiled = compilePattern(pattern);
      if (!compiled.ok) {
        refusals.add(compiled.reason);
        continue;
      }
      for (const value of VALUES) {
        if (compiled.matcher.test(value) !== regex.test(value)) {
          throw new Error(`/${pattern}/ on ${JSON.stringify(value)}: RegExp says ${regex.test(value)}`);
        }
        compared++;
      }
    }
    expect(compared).toBeGreaterThan(100000);
    // None of the pieces is a back reference, so nothing is refused.
    expect([...refusals]).toEqual([]);
  });

  it('agrees with RegExp on every code unit, for classes that reach beyond ASCII', () => {
    for (const pattern of [
      '^[α-ω]$',
      '^[^α-ω]$',
      '^[a-zα-ωА-я\\u3040-\\u309f]$',
      '^\\s$',
      '^\\S$',
      '^.$',
      '^\\W$',
      '^[\\w\\u2028]$',
      '^[^\\D\\u3000]$',
      '^[\\s\\u00e9-\\u00ff]$',
      '^[^\\s\\u2000-\\u2fff]$',
      '^[\\u0080-\\uffff]$',
      '^[\\uffff]$',
      '^[^\\uffff\\u0080]$',
      '^[]$',
      '^[^]$',
    ]) {
      const m = matcher(pattern);
      const regex = new RegExp(pattern);
      for (let c = 0; c <= 0xffff; c++) {
        const value = String.fromCharCode(c);
        if (m.test(value) !== regex.test(value)) throw new Error(`/${pattern}/ on U+${c.toString(16)}`);
      }
    }
  });

  it('carries nothing over from one value to the next', () => {
    const m = matcher('^(?=.*b)a+(?<!c)$|\\bz');
    const regex = new RegExp('^(?=.*b)a+(?<!c)$|\\bz');
    const values = ['aab', 'aaa', 'ab', 'z', 'a'.repeat(300) + 'b', '', 'xz', 'x z', 'aaab', 'b'];
    for (let round = 0; round < 3; round++) {
      for (const value of values) expect(m.test(value), JSON.stringify(value)).toBe(regex.test(value));
    }
  });
});

describe('compilePattern: no pattern runs long', () => {
  it('answers the patterns RegExp backtracks on, in steps bounded by pattern size times value length', () => {
    const letters = 'abcdefgh';
    const cases: [pattern: string, value: string, expected: boolean][] = [
      // Nested repetitions: the family the first guard refused.
      ['^(([a-z0-9 :.-])+)+X$', `${'a'.repeat(4000)}!`, false],
      ['(a+)+$', `${'a'.repeat(4000)}!`, false],
      ['(a*)*b', 'a'.repeat(4000), false],
      // Repeated groups whose alternatives start alike, or that hold a bounded repetition.
      ['^(a|a)+$', `${'a'.repeat(4000)}!`, false],
      ['^(a|aa)+$', 'a'.repeat(4000), true],
      ['(a+){8}$', `${'a'.repeat(4000)}!`, false],
      ['(a{1,30}){1,30}$', `${'a'.repeat(900)}!`, false],
      // Alternatives in a row, no repetition at all: two ways per group.
      [`^${'(?:\\w|\\d)'.repeat(40)}$`, `${'1'.repeat(40)}-rc1`, false],
      [`^${'(?:a|aa)'.repeat(40)}$`, `${'a'.repeat(80)}!`, false],
      // Six optional characters on each of eight letters.
      [`^${[...letters].map((c) => `${c}?`.repeat(6)).join('')}$`, `${[...letters].map((c) => c.repeat(3)).join('')}-`, false],
      // Repetitions in a row that take over each other's characters.
      ['a*a*a*b', 'a'.repeat(4000), false],
      ['^a*a*b*b*c*c*d*d*$', `${'a'.repeat(1000)}${'b'.repeat(1000)}${'c'.repeat(1000)}${'d'.repeat(1000)}-`, false],
      ['^a*a*a{1000}', 'a'.repeat(999), false],
      ['^a*a*(?=a*b)a', 'a'.repeat(4000), false],
      ['a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?aaaaaaaaaaaaaaaaaaaa', 'a'.repeat(20), true],
      ['.*.*.*.*x', 'a'.repeat(4000), false],
    ];
    for (const [pattern, value, expected] of cases) {
      const m = matcher(pattern);
      const { matched, steps } = stepsOf(m, value);
      expect(matched, pattern).toBe(expected);
      expect(steps, pattern).toBeLessThanOrEqual(2 * m.size * (value.length + 1));
    }
  });

  it('stops at the first position an anchored pattern cannot pass', () => {
    const m = matcher('^pkg:npm/');
    expect(stepsOf(m, `x${'pkg:npm/'.repeat(1000)}`).steps).toBeLessThan(10);
    expect(m.test('pkg:npm/left-pad@1.3.0')).toBe(true);
  });

  it('charges a budget and says when it ran out', () => {
    const m = matcher('.*.*x');
    const value = 'a'.repeat(1000);
    const needed = stepsOf(m, value).steps;
    const budget: PatternBudget = { remaining: needed + 50 };
    expect(m.test(value, budget)).toBe(false);
    expect(budget).toEqual({ remaining: 50 });
    // Too little for the next value: the answer is "not evaluated", never a match.
    const hit = `${'a'.repeat(999)}x`;
    expect(m.test(hit)).toBe(true);
    expect(m.test(hit, budget)).toBe(false);
    expect(budget).toEqual({ remaining: 0, exhausted: true });
    expect(m.test('x', budget)).toBe(false);
    // The matcher itself is unharmed.
    expect(m.test(hit)).toBe(true);
  });
});

describe('compilePattern: what it refuses', () => {
  it('refuses back references, which no automaton can match', () => {
    for (const pattern of ['(a)\\1', '(?<n>a)\\k<n>', '([\'"]).*\\1', '\\1']) {
      expect(reasonOf(pattern), pattern).toBe('back references are not supported');
    }
    // Inside a class a backslash and a digit are a character, never a reference.
    expect(reasonOf('(a)[\\1]')).toBe('accepted');
  });

  it('refuses what is not a regular expression, or one it does not model', () => {
    expect(reasonOf('(')).toBe('not a valid regular expression');
    expect(reasonOf('a{2,1}')).toBe('not a valid regular expression');
    expect(reasonOf('(?<=a)*')).toBe('not a valid regular expression');
    expect(reasonOf('a'.repeat(1001))).toBe('longer than 1000 characters');
    expect(reasonOf(`${'('.repeat(65)}a${')'.repeat(65)}`)).toBe('groups nested deeper than 64');
  });

  it('refuses a pattern whose counted repetitions write out too large', () => {
    for (const pattern of ['a{5000}', '(a{70}){70}', '.{0,4096}', '(a+){99999999999999999999}', '((a{20}){20}){20}']) {
      expect(reasonOf(pattern), pattern).toBe('too large once its counted repetitions are written out');
    }
    for (const pattern of ['^[a-f0-9]{64}$', '^[A-Za-z0-9+/]{1000,}={0,2}$', '.{0,1000}', '(\\d{1,3}\\.){3}\\d{1,3}']) {
      expect(matcher(pattern).size, pattern).toBeLessThanOrEqual(PATTERN_PROGRAM_MAX);
    }
  });

  it('accepts the patterns earlier guards refused for their shape', () => {
    expectSameAsRegExp('^(\\d{1,3}\\.){3}\\d{1,3}$', ['192.168.0.1', '192.168.0', '1.2.3.4.5', 'a.b.c.d']);
    expectSameAsRegExp('^[a-z0-9]+(-[a-z0-9]+)*$', ['left-pad', 'left--pad', 'a', '-a', 'a-']);
    expectSameAsRegExp('^(Person|Organization): .+ \\(.+@.+\\)$', [
      'Organization: ACME Corp (security@acme.example)',
      'Organization: ACME Corp',
      'Tool: x (a@b)',
    ]);
    expectSameAsRegExp('^\\S+@\\S+\\.\\S+$', ['a@b.c', 'a@b', 'a b@c.d']);
    expectSameAsRegExp('^\\d+(\\.\\d+){2}$', ['1.2.3', '1.2', '1.2.3.4']);
  });

  it('compiles a long or deep pattern at once', () => {
    const started = Date.now();
    compilePattern(`${'('.repeat(60)}a${')'.repeat(60)}`);
    compilePattern('a?'.repeat(400));
    compilePattern('(?:a|b)?'.repeat(100));
    compilePattern('[a-z]{4000}{4000}');
    expect(Date.now() - started).toBeLessThan(500);
  });
});
