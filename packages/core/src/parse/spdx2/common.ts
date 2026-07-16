import type {
  ElementRef,
  ExternalDocumentRef,
  ExternalRef,
  Relationship,
  SbomElement,
} from '../../model/document';
import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';

/** Parses `SPDXRef-x`, `DocumentRef-X:SPDXRef-y`, bare `DocumentRef-X`, NOASSERTION/NONE. */
export function parseElementRef(raw: string): ElementRef {
  if (raw === 'NOASSERTION' || raw === 'NONE') return { kind: 'special', value: raw };
  if (raw.startsWith('DocumentRef-')) {
    const colon = raw.indexOf(':');
    if (colon === -1) return { kind: 'external', docRef: raw, spdxId: null };
    const spdxId = raw.slice(colon + 1);
    return { kind: 'external', docRef: raw.slice(0, colon), spdxId: spdxId || null };
  }
  return { kind: 'local', spdxId: raw };
}

export function refToString(ref: ElementRef): string {
  switch (ref.kind) {
    case 'local':
      return ref.spdxId;
    case 'external':
      return ref.spdxId === null ? ref.docRef : `${ref.docRef}:${ref.spdxId}`;
    case 'special':
      return ref.value;
  }
}

export function normalizeRelType(type: string): string {
  return type.trim().toUpperCase().replaceAll('-', '_');
}

export function extractPurl(externalRefs: ExternalRef[] | undefined): string | undefined {
  return externalRefs?.find((r) => r.type === 'purl')?.locator;
}

/** `pkg:type/ns/name@version?qualifiers#subpath` → version, if present. */
export function versionFromPurl(purl: string): string | undefined {
  const withoutSuffix = purl.split('#', 1)[0]!.split('?', 1)[0]!;
  const at = withoutSuffix.lastIndexOf('@');
  if (at === -1 || at < withoutSuffix.lastIndexOf('/')) return undefined;
  const version = withoutSuffix.slice(at + 1);
  return version ? decodeURIComponent(version) : undefined;
}

/** Identity part of a purl — `pkg:type/ns/name`, without version/qualifiers/subpath. */
export function purlWithoutVersion(purl: string): string {
  const withoutSuffix = purl.split('#', 1)[0]!.split('?', 1)[0]!;
  const at = withoutSuffix.lastIndexOf('@');
  if (at === -1 || at < withoutSuffix.lastIndexOf('/')) return withoutSuffix;
  return withoutSuffix.slice(0, at);
}

/** Keeps the first element per SPDXID; trivy output repeats identical blocks. */
export function dedupeBySpdxId(elements: SbomElement[], diagnostics: Diagnostic[]): SbomElement[] {
  const seen = new Set<string>();
  const result: SbomElement[] = [];
  let dropped = 0;
  let example = '';
  for (const el of elements) {
    if (seen.has(el.spdxId)) {
      dropped++;
      if (!example) example = el.spdxId;
      continue;
    }
    seen.add(el.spdxId);
    result.push(el);
  }
  if (dropped > 0) {
    diagnostics.push(
      diag(
        'info',
        'DUP_SPDXID',
        `${dropped} element(s) with duplicate SPDXIDs removed (e.g. ${example}).`,
      ),
    );
  }
  return result;
}

/**
 * Normalizes `documentDescribes` and DESCRIBES relationships into one source
 * of truth: synthetic DESCRIBES relationships for uncovered entries, plus the
 * convenience `describes` list of local root SPDXIDs.
 */
export function normalizeDescribes(
  docSpdxId: string,
  documentDescribes: string[],
  relationships: Relationship[],
): { relationships: Relationship[]; describes: string[] } {
  const described = new Set<string>();
  for (const rel of relationships) {
    if (
      rel.type === 'DESCRIBES' &&
      rel.from.kind === 'local' &&
      rel.from.spdxId === docSpdxId &&
      rel.to.kind === 'local'
    ) {
      described.add(rel.to.spdxId);
    }
    if (
      rel.type === 'DESCRIBED_BY' &&
      rel.to.kind === 'local' &&
      rel.to.spdxId === docSpdxId &&
      rel.from.kind === 'local'
    ) {
      described.add(rel.from.spdxId);
    }
  }
  const synthetic: Relationship[] = [];
  for (const target of documentDescribes) {
    const ref = parseElementRef(target);
    if (ref.kind !== 'local') continue;
    if (!described.has(ref.spdxId)) {
      described.add(ref.spdxId);
      synthetic.push({ from: { kind: 'local', spdxId: docSpdxId }, type: 'DESCRIBES', to: ref });
    }
  }
  return { relationships: [...relationships, ...synthetic], describes: [...described] };
}

/** Warns once about relationship DocumentRefs that have no ExternalDocumentRef entry. */
export function checkRelationshipDocRefs(
  relationships: Relationship[],
  externalDocumentRefs: ExternalDocumentRef[],
  diagnostics: Diagnostic[],
): void {
  const known = new Set(externalDocumentRefs.map((r) => r.docRef));
  const unknown = new Set<string>();
  for (const rel of relationships) {
    for (const ref of [rel.from, rel.to]) {
      if (ref.kind === 'external' && !known.has(ref.docRef)) unknown.add(ref.docRef);
    }
  }
  if (unknown.size > 0) {
    diagnostics.push(
      diag(
        'warning',
        'REL_UNKNOWN_DOCREF',
        `Relationships reference ${unknown.size} DocumentRef(s) with no ExternalDocumentRef entry: ${[...unknown].slice(0, 3).join(', ')}${unknown.size > 3 ? ', ...' : ''}.`,
      ),
    );
  }
}
