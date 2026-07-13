/**
 * Tolerant accessors for untrusted JSON. Real-world SBOMs are dirty; parsing
 * collects diagnostics instead of rejecting, so these never throw.
 */

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

export function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

export function asRecordArray(v: unknown): Record<string, unknown>[] {
  return asArray(v).filter(isRecord);
}

export function asStringArray(v: unknown): string[] {
  return asArray(v).filter((x): x is string => typeof x === 'string');
}
