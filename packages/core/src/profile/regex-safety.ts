/**
 * A linear-time guard against catastrophic-backtracking regular expressions.
 *
 * Compliance-profile `pattern`s are user input (imported files, deep links).
 * They are compiled with `new RegExp` and run with `.test()` on document field
 * values on the UI main thread. A pattern with nested unbounded quantifiers —
 * `(a+)+`, `(([a-z])+)+`, `(a*)*` — backtracks exponentially and freezes the
 * tab. JavaScript's RegExp has no step budget, so the only defence is to refuse
 * such a pattern before it runs.
 *
 * This detector flags "star height ≥ 2": an unbounded quantifier whose atom is
 * a group that itself contains an unbounded quantifier. It is a conservative,
 * single-pass check — it may reject an unusual-but-safe pattern, and it does
 * not claim to catch every pathological one, but it stops the whole known
 * exponential family and never loops itself.
 */

/** Whether an unbounded quantifier (`*`, `+`, or `{n,}` with no upper bound) starts at `i`. */
function unboundedQuantifierAt(src: string, i: number): boolean {
  const c = src[i];
  if (c === '*' || c === '+') return true;
  if (c === '{') {
    // `{n,}` is unbounded; `{n}` and `{n,m}` are bounded.
    const m = /^\{\d*,\s*\}/.exec(src.slice(i));
    return m !== null;
  }
  return false;
}

export function isUnsafeRegexPattern(src: string): boolean {
  // Each open group gets a frame; `hasUnbounded` records whether anything
  // inside it carries an unbounded quantifier.
  const stack: { hasUnbounded: boolean }[] = [];
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      i++; // skip the escaped character; it is a literal, never a quantifier
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      continue;
    }
    if (c === '(') {
      stack.push({ hasUnbounded: false });
      continue;
    }
    if (c === ')') {
      const frame = stack.pop();
      const quantified = unboundedQuantifierAt(src, i + 1);
      // Nested unbounded quantifiers: this group is quantified and already
      // holds an unbounded quantifier. That is the catastrophic shape.
      if (quantified && frame?.hasUnbounded) return true;
      // A quantified group is itself an unbounded element of its parent.
      if (quantified && stack.length > 0) stack[stack.length - 1]!.hasUnbounded = true;
      continue;
    }
    if (unboundedQuantifierAt(src, i) && stack.length > 0) {
      stack[stack.length - 1]!.hasUnbounded = true;
    }
  }
  return false;
}
