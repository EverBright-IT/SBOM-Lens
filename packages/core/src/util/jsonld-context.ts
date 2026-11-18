/**
 * The text of a JSON-LD `@context`, for format sniffing: every string it
 * holds, joined by spaces. A context may be a string, an array, or an object
 * (an inline context, or one that pulls in another through `@import`), and
 * the three nest. Sniffing only asks whether a known vocabulary IRI occurs,
 * so the walk is shallow and bounded: a crafted context cannot make it slow.
 */
const MAX_DEPTH = 8;
const MAX_STRINGS = 512;

export function contextText(context: unknown): string {
  const strings: string[] = [];
  const walk = (value: unknown, depth: number): void => {
    if (depth > MAX_DEPTH) return;
    if (typeof value === 'string') {
      strings.push(value);
      return;
    }
    const items = Array.isArray(value) ? value : value !== null && typeof value === 'object' ? Object.values(value) : [];
    for (const item of items) {
      if (strings.length >= MAX_STRINGS) return;
      walk(item, depth + 1);
    }
  };
  walk(context, 0);
  return strings.join(' ');
}
