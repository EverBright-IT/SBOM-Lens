import { describe, expect, it } from 'vitest';
import { isUnsafeRegexPattern } from './regex-safety';

describe('isUnsafeRegexPattern', () => {
  it('flags nested unbounded quantifiers (the catastrophic family)', () => {
    for (const p of [
      '^(([a-z0-9 :.-])+)+X$', // the reported profile pattern
      '(a+)+',
      '(a*)*',
      '(a+)*',
      '([a-z]+)+$',
      '((ab)+)+',
      '(a{1,}){2,}',
      '(.*)*',
    ]) {
      expect(isUnsafeRegexPattern(p), p).toBe(true);
    }
  });

  it('accepts ordinary safe patterns', () => {
    for (const p of [
      '^[A-Za-z0-9.-]+$',
      '.*foo.*',
      '^(abc|def)+$', // group quantified, nothing unbounded inside
      '\\d{1,3}\\.\\d{1,3}',
      '(ab)+cd',
      '([a-z]+)x', // inner quantifier but the group is not quantified
      '(a{2,4}){2,4}', // only bounded quantifiers
      '^v\\d+\\.\\d+\\.\\d+$',
      '',
    ]) {
      expect(isUnsafeRegexPattern(p), p).toBe(false);
    }
  });

  it('is not fooled by escaped parentheses or quantifiers in a character class', () => {
    expect(isUnsafeRegexPattern('\\(a+\\)+')).toBe(false); // literal parens, not a group
    expect(isUnsafeRegexPattern('([+*]+)+')).toBe(true); // + and * are literals in the class, but the class itself is quantified inside a quantified group
    expect(isUnsafeRegexPattern('[(]+')).toBe(false); // literal ( in a class
  });

  it('runs in linear time on a long adversarial-looking input', () => {
    const t0 = Date.now();
    isUnsafeRegexPattern('('.repeat(5000) + 'a' + ')'.repeat(5000));
    expect(Date.now() - t0).toBeLessThan(500);
  });
});
