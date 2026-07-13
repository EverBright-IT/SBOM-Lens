/**
 * Deterministic per-document accent colors: the same document name always
 * maps to the same palette slot (stable across sessions and load order), so
 * badges, map nodes, and inventory chips agree. Collisions are fine — the
 * color is a recognition aid, not an identifier.
 *
 * Class strings are full literals on purpose: Tailwind only generates what
 * it can see in the source.
 */

export interface DocAccent {
  /** Bordered chip (tree boundary badge, inventory document cell). */
  chip: string;
  /** SVG accent stripe / marker fill. */
  fill: string;
  /** Small solid dot. */
  dot: string;
}

const PALETTE: readonly DocAccent[] = [
  {
    chip: 'border-sky-300/80 bg-sky-50 text-sky-700 dark:border-sky-800 dark:bg-sky-950/40 dark:text-sky-300',
    fill: 'fill-sky-500 dark:fill-sky-400',
    dot: 'bg-sky-500',
  },
  {
    chip: 'border-violet-300/80 bg-violet-50 text-violet-700 dark:border-violet-800 dark:bg-violet-950/40 dark:text-violet-300',
    fill: 'fill-violet-500 dark:fill-violet-400',
    dot: 'bg-violet-500',
  },
  {
    chip: 'border-emerald-300/80 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300',
    fill: 'fill-emerald-500 dark:fill-emerald-400',
    dot: 'bg-emerald-500',
  },
  {
    chip: 'border-amber-300/80 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300',
    fill: 'fill-amber-500 dark:fill-amber-400',
    dot: 'bg-amber-500',
  },
  {
    chip: 'border-rose-300/80 bg-rose-50 text-rose-700 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-300',
    fill: 'fill-rose-500 dark:fill-rose-400',
    dot: 'bg-rose-500',
  },
  {
    chip: 'border-cyan-300/80 bg-cyan-50 text-cyan-700 dark:border-cyan-800 dark:bg-cyan-950/40 dark:text-cyan-300',
    fill: 'fill-cyan-500 dark:fill-cyan-400',
    dot: 'bg-cyan-500',
  },
  {
    chip: 'border-lime-300/80 bg-lime-50 text-lime-700 dark:border-lime-800 dark:bg-lime-950/40 dark:text-lime-300',
    fill: 'fill-lime-500 dark:fill-lime-400',
    dot: 'bg-lime-500',
  },
  {
    chip: 'border-fuchsia-300/80 bg-fuchsia-50 text-fuchsia-700 dark:border-fuchsia-800 dark:bg-fuchsia-950/40 dark:text-fuchsia-300',
    fill: 'fill-fuchsia-500 dark:fill-fuchsia-400',
    dot: 'bg-fuchsia-500',
  },
  {
    chip: 'border-orange-300/80 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/40 dark:text-orange-300',
    fill: 'fill-orange-500 dark:fill-orange-400',
    dot: 'bg-orange-500',
  },
  {
    chip: 'border-teal-300/80 bg-teal-50 text-teal-700 dark:border-teal-800 dark:bg-teal-950/40 dark:text-teal-300',
    fill: 'fill-teal-500 dark:fill-teal-400',
    dot: 'bg-teal-500',
  },
];

/** FNV-1a — tiny, stable, good spread on short names. */
function hash(name: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function docAccent(name: string): DocAccent {
  return PALETTE[hash(name) % PALETTE.length]!;
}
