/**
 * Compliance-profile patterns, matched without backtracking.
 *
 * A profile `pattern` is user input (an imported file, a link, a workspace's
 * `.sbomlens/profile.json`) and is matched against document values on the UI
 * main thread. JavaScript's RegExp backtracks: a short pattern can take hours
 * on a short value, RegExp has no step budget, and judging a pattern by its
 * shape has not held (nested repetitions, alternatives that start alike,
 * repetitions in a row: each rule left another shape through).
 *
 * So a pattern never reaches RegExp. It is parsed (the syntax a RegExp
 * without flags accepts), compiled to a small automaton, and matched by
 * following every state the automaton can be in side by side. Each character
 * of a value is looked at once per state, whatever the pattern: the work is
 * bounded by pattern size times value length, and there is nothing to
 * backtrack into.
 *
 * The answer is the one the language defines for
 * `new RegExp(pattern).test(value)` (engines stray from it in rare corners;
 * the tests name one). For a yes/no match greedy and lazy repetitions and
 * the order of alternatives make no difference, and a lookahead or
 * lookbehind only asks whether its body matches at a position, which one
 * extra pass over the value answers for every position. Not supported, and
 * refused when a profile is imported: back references (they need
 * backtracking by nature) and syntax the parser does not model.
 */

const MAX_SOURCE = 1000;
const MAX_DEPTH = 64;
/** Automaton states of one pattern, lookarounds included, counted repetitions written out. */
export const PATTERN_PROGRAM_MAX = 4096;

/**
 * Matching work a caller is willing to spend, shared across values. One step
 * is one automaton state looked at for one position of a value.
 */
export interface PatternBudget {
  remaining: number;
  /** Set once a match was cut short because the steps ran out. */
  exhausted?: boolean;
}

export type PatternCompilation = { ok: true; matcher: PatternMatcher } | { ok: false; reason: string };

/** Parse and compile a profile pattern, or say why it cannot be used. */
export function compilePattern(src: string): PatternCompilation {
  if (src.length > MAX_SOURCE) return { ok: false, reason: `longer than ${MAX_SOURCE} characters` };
  try {
    // Syntax is whatever RegExp accepts: constructing one parses the pattern and runs nothing.
    new RegExp(src);
  } catch {
    return { ok: false, reason: 'not a valid regular expression' };
  }
  let pattern: Alt;
  try {
    pattern = new Parser(src).parse();
  } catch (error) {
    return { ok: false, reason: error instanceof Unsupported ? error.message : 'not understood' };
  }
  if (programSize(pattern) > PATTERN_PROGRAM_MAX) return { ok: false, reason: TOO_LARGE };
  try {
    return { ok: true, matcher: new Compiler().compile(pattern) };
  } catch (error) {
    return { ok: false, reason: error instanceof Unsupported ? error.message : 'not understood' };
  }
}

const TOO_LARGE = 'too large once its counted repetitions are written out';

// --- Syntax -----------------------------------------------------------------

type Builtin = 'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'dot';
type ClassItem = { lo: number; hi: number } | { builtin: Builtin };
type AssertKind = 'start' | 'end' | 'word' | 'notWord';

type Node =
  | { t: 'set'; items: ClassItem[]; negated: boolean }
  | { t: 'assert'; kind: AssertKind }
  | { t: 'look'; ahead: boolean; negated: boolean; body: Alt }
  | { t: 'group'; body: Alt }
  | { t: 'repeat'; atom: Node; min: number; max: number };
type Seq = Node[];
type Alt = Seq[];

class Unsupported extends Error {}

const point = (code: number): ClassItem => ({ lo: code, hi: code });
const single = (code: number): Node => ({ t: 'set', items: [point(code)], negated: false });

/** Recursive descent over the pattern syntax without flags (Annex B included). */
class Parser {
  #i = 0;
  #depth = 0;
  constructor(private readonly src: string) {}

  parse(): Alt {
    const alt = this.#alt();
    if (this.#i < this.src.length) throw new Unsupported('unbalanced parenthesis');
    return alt;
  }

  #alt(): Alt {
    const branches: Seq[] = [this.#seq()];
    while (this.src[this.#i] === '|') {
      this.#i++;
      branches.push(this.#seq());
    }
    return branches;
  }

  #seq(): Seq {
    const nodes: Seq = [];
    while (this.#i < this.src.length && this.src[this.#i] !== '|' && this.src[this.#i] !== ')') {
      nodes.push(this.#quantified(this.#atom()));
    }
    return nodes;
  }

  #quantified(atom: Node): Node {
    const c = this.src[this.#i];
    let min: number;
    let max: number;
    if (c === '*') [min, max] = [0, Infinity];
    else if (c === '+') [min, max] = [1, Infinity];
    else if (c === '?') [min, max] = [0, 1];
    else if (c === '{') {
      const bounds = /\{(\d+)(,(\d*))?\}/y;
      bounds.lastIndex = this.#i;
      const m = bounds.exec(this.src);
      if (!m) return atom; // a literal brace
      min = Number(m[1]);
      max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
      this.#i += m[0].length - 1;
    } else return atom;
    this.#i++;
    if (this.src[this.#i] === '?') this.#i++; // lazy: the same set of matches
    return { t: 'repeat', atom, min, max };
  }

  #atom(): Node {
    const c = this.src[this.#i]!;
    switch (c) {
      case '^':
        this.#i++;
        return { t: 'assert', kind: 'start' };
      case '$':
        this.#i++;
        return { t: 'assert', kind: 'end' };
      case '.':
        this.#i++;
        return { t: 'set', items: [{ builtin: 'dot' }], negated: false };
      case '(':
        return this.#group();
      case '[':
        return this.#class();
      case '\\':
        return this.#escape();
      case '*':
      case '+':
      case '?':
        throw new Unsupported('nothing to repeat');
      default:
        this.#i++;
        return single(c.charCodeAt(0));
    }
  }

  #group(): Node {
    if (++this.#depth > MAX_DEPTH) throw new Unsupported(`groups nested deeper than ${MAX_DEPTH}`);
    this.#i++;
    let look: { ahead: boolean; negated: boolean } | undefined;
    const at = (text: string) => this.src.startsWith(text, this.#i);
    if (at('?:')) this.#i += 2;
    else if (at('?=') || at('?!')) {
      look = { ahead: true, negated: at('?!') };
      this.#i += 2;
    } else if (at('?<=') || at('?<!')) {
      look = { ahead: false, negated: at('?<!') };
      this.#i += 3;
    } else if (at('?<')) {
      const end = this.src.indexOf('>', this.#i);
      if (end < 0) throw new Unsupported('unterminated group name');
      this.#i = end + 1;
    } else if (this.src[this.#i] === '?') throw new Unsupported('unknown group syntax');
    const body = this.#alt();
    if (this.src[this.#i] !== ')') throw new Unsupported('unbalanced parenthesis');
    this.#i++;
    this.#depth--;
    return look ? { t: 'look', ...look, body } : { t: 'group', body };
  }

  #class(): Node {
    this.#i++;
    const negated = this.src[this.#i] === '^';
    if (negated) this.#i++;
    const items: ClassItem[] = [];
    while (this.#i < this.src.length && this.src[this.#i] !== ']') {
      const from = this.#classAtom();
      if (this.src[this.#i] !== '-' || this.src[this.#i + 1] === undefined || this.src[this.#i + 1] === ']') {
        items.push(from);
        continue;
      }
      this.#i++;
      const to = this.#classAtom();
      if ('lo' in from && 'lo' in to) {
        if (from.lo > to.lo) throw new Unsupported('character range out of order');
        items.push({ lo: from.lo, hi: to.lo });
      } else {
        // Annex B: next to a class escape such as \d the hyphen is literal.
        items.push(from, point(45), to);
      }
    }
    if (this.src[this.#i] !== ']') throw new Unsupported('unterminated character class');
    this.#i++;
    return { t: 'set', items, negated };
  }

  #classAtom(): ClassItem {
    const c = this.src[this.#i]!;
    this.#i++;
    if (c !== '\\') return point(c.charCodeAt(0));
    const e = this.src[this.#i];
    if (e === undefined) throw new Unsupported('trailing backslash');
    if ('dDwWsS'.includes(e)) {
      this.#i++;
      return { builtin: e as Builtin };
    }
    if (e === 'b') {
      this.#i++;
      return point(8); // backspace inside a class
    }
    return point(this.#escapedChar());
  }

  #escape(): Node {
    this.#i++;
    const e = this.src[this.#i];
    if (e === undefined) throw new Unsupported('trailing backslash');
    if ('dDwWsS'.includes(e)) {
      this.#i++;
      return { t: 'set', items: [{ builtin: e as Builtin }], negated: false };
    }
    if (e === 'b' || e === 'B') {
      this.#i++;
      return { t: 'assert', kind: e === 'b' ? 'word' : 'notWord' };
    }
    // A back reference repeats what a group matched: no automaton can do that.
    // Without that many groups RegExp reads `\1` as an octal escape instead;
    // refused all the same rather than counting groups to tell the two apart.
    if ((e >= '1' && e <= '9') || (e === 'k' && this.src[this.#i + 1] === '<' && this.src.includes('>', this.#i))) {
      throw new Unsupported('back references are not supported');
    }
    return single(this.#escapedChar());
  }

  /** The code unit a character escape stands for; `#i` is just past the backslash. */
  #escapedChar(): number {
    const e = this.src[this.#i]!;
    this.#i++;
    const hex = (length: number, literal: number) => {
      const digits = this.src.slice(this.#i, this.#i + length);
      if (!new RegExp(`^[0-9a-fA-F]{${length}}$`).test(digits)) return literal;
      this.#i += length;
      return parseInt(digits, 16);
    };
    switch (e) {
      case 'n':
        return 10;
      case 'r':
        return 13;
      case 't':
        return 9;
      case 'v':
        return 11;
      case 'f':
        return 12;
      case 'x':
        return hex(2, 120);
      case 'u':
        return hex(4, 117);
      case 'c': {
        const letter = this.src[this.#i];
        if (!letter || !/[A-Za-z]/.test(letter)) throw new Unsupported('control escape');
        this.#i++;
        return letter.charCodeAt(0) % 32;
      }
      default: {
        if (!/[0-7]/.test(e)) return e.charCodeAt(0);
        // Annex B octal escape, at most three digits and 0o377.
        let value = Number(e);
        for (let n = 0; n < 2 && /[0-7]/.test(this.src[this.#i] ?? '') && value * 8 + Number(this.src[this.#i]) <= 0o377; n++) {
          value = value * 8 + Number(this.src[this.#i]);
          this.#i++;
        }
        return value;
      }
    }
  }
}

// --- Character sets ---------------------------------------------------------

const isDigit = (c: number) => c >= 48 && c <= 57;
const isWord = (c: number) => isDigit(c) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
const SPACES = [9, 10, 11, 12, 13, 32, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff];
const isSpace = (c: number) => SPACES.includes(c) || (c >= 0x2000 && c <= 0x200a);
const isLineTerminator = (c: number) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;

const BUILTIN: Record<Builtin, (c: number) => boolean> = {
  d: isDigit,
  D: (c) => !isDigit(c),
  w: isWord,
  W: (c) => !isWord(c),
  s: isSpace,
  S: (c) => !isSpace(c),
  dot: (c) => !isLineTerminator(c),
};

/**
 * One character test of a pattern: a table for ASCII, sorted ranges for
 * everything else. Either way a test costs the same few operations however
 * long the class is written, which is what lets work be counted in steps.
 */
interface CharSet {
  ascii: Uint8Array;
  /** Beyond ASCII: [from, to] pairs in ascending order, none touching. */
  ranges: Uint16Array;
}

/** Where the built-in classes change beyond ASCII (\s and the line terminators `.` leaves out). */
const BUILTIN_EDGES = [0xa0, 0xa1, 0x1680, 0x1681, 0x2000, 0x200b, 0x2028, 0x2029, 0x202a, 0x202f, 0x2030, 0x205f, 0x2060, 0x3000, 0x3001, 0xfeff, 0xff00];

function charSet(node: { items: ClassItem[]; negated: boolean }): CharSet {
  const { items, negated } = node;
  const has = (c: number) =>
    items.some((item) => ('lo' in item ? c >= item.lo && c <= item.hi : BUILTIN[item.builtin](c))) !== negated;
  const ascii = new Uint8Array(128);
  for (let c = 0; c < 128; c++) ascii[c] = has(c) ? 1 : 0;
  // Membership only changes at an edge of an item or of a built-in class:
  // one character per stretch between edges answers for the whole stretch.
  const edges = new Set<number>([128, ...BUILTIN_EDGES]);
  for (const item of items) {
    if (!('lo' in item)) continue;
    if (item.lo >= 128) edges.add(item.lo);
    if (item.hi + 1 >= 128 && item.hi + 1 <= 0xffff) edges.add(item.hi + 1);
  }
  const starts = [...edges].sort((a, b) => a - b);
  const ranges: number[] = [];
  starts.forEach((from, index) => {
    if (!has(from)) return;
    const to = (starts[index + 1] ?? 0x10000) - 1;
    if (ranges.length > 0 && ranges[ranges.length - 1] === from - 1) ranges[ranges.length - 1] = to;
    else ranges.push(from, to);
  });
  return { ascii, ranges: Uint16Array.from(ranges) };
}

function inSet(set: CharSet, c: number): boolean {
  if (c < 128) return set.ascii[c] === 1;
  const ranges = set.ranges;
  // The first range that ends at or after c holds it, or none does.
  let low = 0;
  let high = ranges.length >> 1;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (c > ranges[2 * mid + 1]!) low = mid + 1;
    else high = mid;
  }
  return low < ranges.length >> 1 && c >= ranges[2 * low]!;
}

// --- Automaton --------------------------------------------------------------

// One instruction per state. CHAR takes a character and moves on; the others
// take none and are followed at once (the closure of a position).
const CHAR = 0; // x: character set
const SPLIT = 1; // continue at x and at y
const JMP = 2; // continue at x
const AT_START = 3;
const AT_END = 4;
const WORD = 5;
const NOT_WORD = 6;
const LOOK = 7; // x: lookaround, y: 1 when negated
const MATCH = 8;

interface Program {
  op: Uint8Array;
  x: Int32Array;
  y: Int32Array;
  // Scratch, reused from value to value: the states alive at this position
  // and at the next, a visit stamp per state, and the stack of the closure.
  current: Int32Array;
  next: Int32Array;
  seen: Int32Array;
  stack: Int32Array;
  stamp: number;
  /** A closure of the current stamp reached MATCH. */
  hit: boolean;
}

interface Look {
  program: Program;
  ahead: boolean;
  /** Per position of the current value: whether the body matches there. */
  bits: Uint8Array;
  /** The test() call the bits were filled for. */
  call: number;
}

const cap = (n: number) => (n > PATTERN_PROGRAM_MAX ? PATTERN_PROGRAM_MAX + 1 : n);

/** An upper bound of the states compilation writes, lookaround bodies included. */
function programSize(pattern: Alt): number {
  let looks = 0;
  const altSize = (alt: Alt): number => cap(alt.reduce((sum, seq) => cap(sum + 2 + seqSize(seq)), 0));
  const seqSize = (seq: Seq): number => cap(seq.reduce((sum, node) => cap(sum + nodeSize(node)), 0));
  const nodeSize = (node: Node): number => {
    switch (node.t) {
      case 'set':
      case 'assert':
        return 1;
      case 'look':
        looks = cap(looks + altSize(node.body) + 1);
        return 1;
      case 'group':
        return altSize(node.body);
      case 'repeat': {
        const atom = nodeSize(node.atom);
        // min copies, then a loop or one optional copy per further round.
        const copies = node.max === Infinity ? node.min + 1 : node.max;
        return cap(cap(atom + 2) * cap(copies));
      }
    }
  };
  return cap(altSize(pattern) + 1 + looks);
}

class Builder {
  op: number[] = [];
  x: number[] = [];
  y: number[] = [];

  get length(): number {
    return this.op.length;
  }

  emit(op: number, x = 0, y = 0): number {
    // programSize() has already refused anything this large; a second line of defence.
    if (this.op.length >= PATTERN_PROGRAM_MAX) throw new Unsupported(TOO_LARGE);
    this.op.push(op);
    this.x.push(x);
    this.y.push(y);
    return this.op.length - 1;
  }

  finish(): Program {
    const size = this.op.length;
    return {
      op: Uint8Array.from(this.op),
      x: Int32Array.from(this.x),
      y: Int32Array.from(this.y),
      current: new Int32Array(size),
      next: new Int32Array(size),
      seen: new Int32Array(size),
      // Every state visited pushes at most two successors.
      stack: new Int32Array(2 * size + 2),
      stamp: 0,
      hit: false,
    };
  }
}

/** Thompson's construction: one state per character test, joined by SPLIT and JMP. */
class Compiler {
  readonly #sets: CharSet[] = [];
  readonly #setIds = new Map<string, number>();
  readonly #looks: Look[] = [];
  readonly #lookIds = new Map<Node, number>();
  #size = 0;

  compile(pattern: Alt): PatternMatcher {
    const main = this.#program(pattern, false);
    const anchored = pattern.every((branch) => branch[0]?.t === 'assert' && branch[0].kind === 'start');
    return new PatternMatcher(main, this.#looks, this.#sets, anchored, this.#size);
  }

  /** `reversed` writes every sequence back to front: the automaton then reads a value right to left. */
  #program(alt: Alt, reversed: boolean): Program {
    const b = new Builder();
    this.#alt(b, alt, reversed);
    b.emit(MATCH);
    this.#size += b.length;
    return b.finish();
  }

  #alt(b: Builder, alt: Alt, reversed: boolean): void {
    const ends: number[] = [];
    alt.forEach((branch, index) => {
      if (index === alt.length - 1) {
        this.#seq(b, branch, reversed);
        return;
      }
      const split = b.emit(SPLIT);
      b.x[split] = b.length;
      this.#seq(b, branch, reversed);
      ends.push(b.emit(JMP));
      b.y[split] = b.length;
    });
    for (const jump of ends) b.x[jump] = b.length;
  }

  #seq(b: Builder, seq: Seq, reversed: boolean): void {
    if (reversed) for (let i = seq.length - 1; i >= 0; i--) this.#node(b, seq[i]!, reversed);
    else for (const node of seq) this.#node(b, node, reversed);
  }

  #node(b: Builder, node: Node, reversed: boolean): void {
    switch (node.t) {
      case 'set':
        b.emit(CHAR, this.#set(node));
        return;
      case 'assert':
        b.emit({ start: AT_START, end: AT_END, word: WORD, notWord: NOT_WORD }[node.kind]);
        return;
      case 'look':
        b.emit(LOOK, this.#look(node), node.negated ? 1 : 0);
        return;
      case 'group':
        this.#alt(b, node.body, reversed);
        return;
      case 'repeat': {
        for (let i = 0; i < node.min; i++) this.#node(b, node.atom, reversed);
        if (node.max === Infinity) {
          const loop = b.emit(SPLIT);
          b.x[loop] = b.length;
          this.#node(b, node.atom, reversed);
          b.emit(JMP, loop);
          b.y[loop] = b.length;
          return;
        }
        // Each further round is optional, and skipping one skips the rest.
        const skips: number[] = [];
        for (let i = node.min; i < node.max; i++) {
          const split = b.emit(SPLIT);
          b.x[split] = b.length;
          skips.push(split);
          this.#node(b, node.atom, reversed);
        }
        for (const split of skips) b.y[split] = b.length;
      }
    }
  }

  #set(node: { items: ClassItem[]; negated: boolean }): number {
    const key = JSON.stringify([node.negated, node.items]);
    let id = this.#setIds.get(key);
    if (id === undefined) {
      id = this.#sets.push(charSet(node)) - 1;
      this.#setIds.set(key, id);
    }
    return id;
  }

  /**
   * A lookaround is its own automaton. A lookahead asks whether the body
   * matches starting at a position, which the reversed body answers when it
   * is run from the end of the value towards its start; a lookbehind asks
   * whether the body matches ending at a position, the plain body run from
   * the start. Compiled once per node, however often a repetition copies it.
   */
  #look(node: Extract<Node, { t: 'look' }>): number {
    let id = this.#lookIds.get(node);
    if (id === undefined) {
      // The body first: it may hold lookarounds of its own, which take their numbers before this one.
      const program = this.#program(node.body, node.ahead);
      id = this.#looks.push({ program, ahead: node.ahead, bits: new Uint8Array(0), call: 0 }) - 1;
      this.#lookIds.set(node, id);
    }
    return id;
  }
}

/**
 * A compiled pattern. `test` answers what `RegExp.prototype.test` answers for
 * the same pattern without flags, in time bounded by `size` times the length
 * of the value.
 */
export class PatternMatcher {
  readonly #main: Program;
  readonly #looks: Look[];
  readonly #sets: CharSet[];
  /** Every alternative starts with `^`: a match can only begin at the start of the value. */
  readonly #anchored: boolean;
  /** Automaton states, lookarounds included: the bound on the work per character of a value. */
  readonly size: number;

  // The value being matched, and the steps left for it.
  #input = '';
  #length = 0;
  #call = 0;
  #left = Infinity;

  /** @internal Use compilePattern. */
  constructor(main: Program, looks: Look[], sets: CharSet[], anchored: boolean, size: number) {
    this.#main = main;
    this.#looks = looks;
    this.#sets = sets;
    this.#anchored = anchored;
    this.size = size;
  }

  /**
   * Whether the pattern matches somewhere in the value. With a budget the
   * steps taken are charged to it; once it is used up the answer is false
   * and `exhausted` is set, so the caller can tell "no match" from "not
   * evaluated".
   */
  test(value: string, budget?: PatternBudget): boolean {
    if (budget && budget.remaining <= 0) {
      budget.exhausted = true;
      return false;
    }
    this.#input = value;
    this.#length = value.length;
    this.#call++;
    this.#left = budget ? budget.remaining : Infinity;
    const matched = this.#search();
    const left = this.#left;
    this.#input = '';
    if (!budget) return matched;
    if (left < 0) {
      budget.remaining = 0;
      budget.exhausted = true;
      return false;
    }
    budget.remaining = left;
    return matched;
  }

  /** The pattern itself, left to right, trying every start position at once. */
  #search(): boolean {
    const p = this.#main;
    const n = this.#length;
    const input = this.#input;
    const sets = this.#sets;
    const anchored = this.#anchored;
    const setOf = p.x;
    let current = p.current;
    let next = p.next;
    this.#fresh(p);
    let count = this.#closure(p, current, 0, 0, 0);
    for (let pos = 0; ; pos++) {
      if (p.hit) return true;
      if (pos === n || this.#left < 0) return false;
      // Nothing alive and no later start possible: the value cannot match any more.
      if (count === 0 && anchored) return false;
      const c = input.charCodeAt(pos);
      this.#fresh(p);
      let alive = 0;
      for (let i = 0; i < count; i++) {
        const pc = current[i]!;
        const set = sets[setOf[pc]!]!;
        if (inSet(set, c)) alive = this.#closure(p, next, alive, pc + 1, pos + 1);
      }
      this.#left -= count;
      if (!anchored) alive = this.#closure(p, next, alive, 0, pos + 1);
      const swap = current;
      current = next;
      next = swap;
      count = alive;
    }
  }

  /**
   * A lookaround's body, tried from every position at once, noting for each
   * position whether it matches there: ending there for a lookbehind (read
   * left to right), starting there for a lookahead (read right to left).
   */
  #fill(look: Look): void {
    const p = look.program;
    const n = this.#length;
    const input = this.#input;
    const sets = this.#sets;
    if (look.bits.length < n + 1) look.bits = new Uint8Array(Math.max(n + 1, look.bits.length * 2));
    const bits = look.bits;
    const setOf = p.x;
    const step = look.ahead ? -1 : 1;
    const last = look.ahead ? 0 : n;
    let current = p.current;
    let next = p.next;
    let pos = look.ahead ? n : 0;
    this.#fresh(p);
    let count = this.#closure(p, current, 0, 0, pos);
    for (; ; pos += step) {
      bits[pos] = p.hit ? 1 : 0;
      if (pos === last || this.#left < 0) return;
      const c = input.charCodeAt(look.ahead ? pos - 1 : pos);
      this.#fresh(p);
      let alive = 0;
      for (let i = 0; i < count; i++) {
        const pc = current[i]!;
        const set = sets[setOf[pc]!]!;
        if (inSet(set, c)) alive = this.#closure(p, next, alive, pc + 1, pos + step);
      }
      this.#left -= count;
      alive = this.#closure(p, next, alive, 0, pos + step);
      const swap = current;
      current = next;
      next = swap;
      count = alive;
    }
  }

  /** A new position: every state may be visited once more. */
  #fresh(p: Program): void {
    if (p.stamp === 0x7fffffff) {
      p.seen.fill(0);
      p.stamp = 0;
    }
    p.stamp++;
    p.hit = false;
  }

  /**
   * Follow everything reachable from `start` without taking a character, at
   * position `pos` of the value: the states waiting for a character are
   * appended to `list`, reaching MATCH sets `hit`. A state is visited once
   * per position, which is what keeps the whole match linear.
   */
  #closure(p: Program, list: Int32Array, count: number, start: number, pos: number): number {
    const { op, x, y, seen, stack, stamp } = p;
    let top = 0;
    let visited = 0;
    stack[top++] = start;
    while (top > 0) {
      const pc = stack[--top]!;
      if (seen[pc] === stamp) continue;
      seen[pc] = stamp;
      visited++;
      switch (op[pc]) {
        case CHAR:
          list[count++] = pc;
          break;
        case MATCH:
          p.hit = true;
          break;
        case JMP:
          stack[top++] = x[pc]!;
          break;
        case SPLIT:
          stack[top++] = y[pc]!;
          stack[top++] = x[pc]!;
          break;
        case AT_START:
          if (pos === 0) stack[top++] = pc + 1;
          break;
        case AT_END:
          if (pos === this.#length) stack[top++] = pc + 1;
          break;
        case WORD:
          if (this.#boundary(pos)) stack[top++] = pc + 1;
          break;
        case NOT_WORD:
          if (!this.#boundary(pos)) stack[top++] = pc + 1;
          break;
        case LOOK:
          if (this.#looksAt(x[pc]!, pos) !== (y[pc] === 1)) stack[top++] = pc + 1;
          break;
      }
    }
    // Charged after the walk: a lookaround's own pass charges itself meanwhile.
    this.#left -= visited;
    return count;
  }

  #boundary(pos: number): boolean {
    const before = pos > 0 && isWord(this.#input.charCodeAt(pos - 1));
    const after = pos < this.#length && isWord(this.#input.charCodeAt(pos));
    return before !== after;
  }

  /** Whether the lookaround's body matches at `pos`; its pass over the value runs on first use. */
  #looksAt(id: number, pos: number): boolean {
    const look = this.#looks[id]!;
    if (look.call !== this.#call) {
      look.call = this.#call;
      this.#fill(look);
    }
    return look.bits[pos] === 1;
  }
}
