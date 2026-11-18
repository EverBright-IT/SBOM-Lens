import { asArray, isRecord } from '../../util/narrow';

/**
 * Entries of a BOM-level list: an array in the JSON form, or the XML
 * mapper's generic form for lists it has no reader for, `{ <item>: one }` or
 * `{ <item>: [many] }`.
 */
export function cdxListLength(value: unknown, item: string): number {
  if (Array.isArray(value)) return value.length;
  if (!isRecord(value)) return 0;
  const inner = value[item];
  return Array.isArray(inner) ? inner.length : inner === undefined ? 0 : 1;
}

/**
 * A CycloneDX VEX document rather than an SBOM: it states vulnerabilities but
 * lists no components, services or dependencies. `metadata.component` (the
 * product the statements are about) may be present, as long as it carries no
 * inventory of its own: a hierarchical BOM nests its components under the
 * subject, and that is an SBOM. Loaded as an SBOM, a VEX document would show
 * as an empty one.
 */
export function isStandaloneCdxVex(root: Record<string, unknown>): boolean {
  const metadata = isRecord(root.metadata) ? root.metadata : {};
  const subject = isRecord(metadata.component) ? metadata.component : {};
  return (
    cdxListLength(root.vulnerabilities, 'vulnerability') > 0 &&
    asArray(root.components).length === 0 &&
    asArray(subject.components).length === 0 &&
    cdxListLength(root.services, 'service') === 0 &&
    asArray(root.dependencies).length === 0
  );
}
