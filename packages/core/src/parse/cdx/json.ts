import type {
  Checksum,
  ExternalDocumentRef,
  ExternalRef,
  Relationship,
  SbomDocument,
  SbomElement,
  SpecInfo,
} from '../../model/document';
import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import { makeDocumentId, makeElementId } from '../../model/ids';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import type { ParseResult, SourceInput } from '../parser';
import { validateCdxStructure } from './validate';

/**
 * CycloneDX 1.x JSON → document model. Additive next to the SPDX parsers,
 * same contract: read-only viewing, tolerant parsing (anomalies degrade to
 * diagnostics, never to a refusal), nothing invented, the full component
 * node rides in `raw` for the source view.
 *
 * Cross-document story: a CDX document's namespace is its BOM-Link identity
 * `urn:cdx:<serialNumber-uuid>/<version>`, and every external reference of
 * type "bom" whose URL is a BOM-Link becomes an ExternalDocumentRef with
 * that URN as the URI — the existing namespace resolution then links loaded
 * CDX documents into one cascade exactly like SPDX namespaces, including
 * actionable placeholders for unresolved links. BOM-Links carry no document
 * hash, so the checksum resolution stage honestly does not apply.
 *
 * The ML-BOM reading in the AIBOM flavor predates this parser and stays
 * separate until it can rebase onto this shared core.
 */

/**
 * Assembly nesting is capped so a malformed or hostile BOM cannot overflow
 * the stack. Breadth deliberately is not capped - the SPDX parsers accept
 * arbitrarily many elements too, and the worker keeps parsing off-thread.
 */
const MAX_NESTING = 64;

const PURPOSE_BY_TYPE: Record<string, string> = {
  application: 'APPLICATION',
  framework: 'FRAMEWORK',
  library: 'LIBRARY',
  container: 'CONTAINER',
  device: 'DEVICE',
  firmware: 'FIRMWARE',
  platform: 'PLATFORM',
  'operating-system': 'OPERATING-SYSTEM',
  'machine-learning-model': 'MODEL',
  data: 'DATA',
};

export function parseCdxJson(
  input: SourceInput,
  root: Record<string, unknown>,
  serialization: 'json' | 'yaml',
): ParseResult {
  const diagnostics: Diagnostic[] = [];
  const specVersion = asString(root.specVersion) ?? 'unknown';
  const serial = asString(root.serialNumber);
  const bomVersion =
    typeof root.version === 'number' && Number.isInteger(root.version)
      ? root.version
      : typeof root.version === 'string' && /^\d+$/.test(root.version)
        ? Number(root.version)
        : 1;
  // The BOM-Link identity doubles as the namespace so link targets resolve
  // through the same matcher SPDX namespaces use.
  // Lowercased on both sides (here and in bomLinkRef): URN scheme/NID are
  // case-insensitive and UUIDs are canonically lowercase, but real BOMs mix
  // cases - a byte-exact comparison would silently never resolve.
  const namespace = serial ? `urn:cdx:${serial.replace(/^urn:uuid:/i, '').toLowerCase()}/${bomVersion}` : null;
  const documentId = makeDocumentId(namespace, input.sha1);
  const spec: SpecInfo = { model: 'cyclonedx', version: `CycloneDX-${specVersion}`, serialization };

  const metadata = isRecord(root.metadata) ? root.metadata : {};
  const elements: SbomElement[] = [];
  const relationships: Relationship[] = [];
  const usedIds = new Set<string>();
  const idByBomRef = new Map<string, string>();

  // BOM-Links: urn:cdx:<uuid>/<version>[#bom-ref] → external document refs,
  // deduped by target URN; the fragment addresses an element over there.
  const externalDocumentRefs: ExternalDocumentRef[] = [];
  const docRefByUrn = new Map<string, string>();
  const bomLinkRef = (url: string): { docRef: string; fragment: string | null } => {
    const hash = url.indexOf('#');
    const urn = (hash === -1 ? url : url.slice(0, hash)).toLowerCase();
    const fragment = hash === -1 ? null : decodeURIComponent(url.slice(hash + 1));
    let docRef = docRefByUrn.get(urn);
    if (!docRef) {
      docRef = `DocumentRef-cdx${docRefByUrn.size + 1}`;
      docRefByUrn.set(urn, docRef);
      externalDocumentRefs.push({ docRef, uri: urn });
    }
    return { docRef, fragment: fragment !== null && fragment !== '' ? fragment : null };
  };

  /** type "bom" references become cascade links; the owner depends on them. */
  const collectBomLinks = (refs: unknown, ownerSpdxId: string | undefined): void => {
    for (const r of asRecordArray(refs)) {
      const url = asString(r.url);
      if (asString(r.type) !== 'bom' || !url?.toLowerCase().startsWith('urn:cdx:')) continue;
      const { docRef, fragment } = bomLinkRef(url);
      if (ownerSpdxId) {
        relationships.push({
          from: { kind: 'local', spdxId: ownerSpdxId },
          type: 'DEPENDS_ON',
          to: { kind: 'external', docRef, spdxId: fragment },
        });
      }
    }
  };

  let nestingCapped = false;
  const addComponent = (node: Record<string, unknown>, parentSpdxId?: string, depth = 0): void => {
    if (depth > MAX_NESTING) {
      nestingCapped = true;
      return; // a malformed or hostile BOM must not overflow the worker stack
    }
    const name = asString(node.name);
    if (!name) {
      diagnostics.push(
        diag('warning', 'CDX_COMPONENT_MALFORMED', 'A component without a name was skipped.'),
      );
      return;
    }
    const bomRef = asString(node['bom-ref']);
    // bom-refs become spdxIds VERBATIM (the SPDX-3 IRI precedent: spdxId is
    // an internal string, arbitrary values are fine). BOM-Link fragments
    // address elements by bom-ref, so any transformation here would break
    // cross-document element resolution. Invented SPDXRef-<name> ids exist
    // only for components without a bom-ref; duplicate bom-refs are
    // spec-invalid and get a suffix.
    const spdxId = bomRef ? uniqueRaw(bomRef, usedIds) : uniqueId(`SPDXRef-${name}`, usedIds);
    if (bomRef) idByBomRef.set(bomRef, spdxId);
    const type = asString(node.type)?.toLowerCase() ?? '';
    const isFile = type === 'file';
    elements.push({
      id: makeElementId(documentId, spdxId),
      documentId,
      spdxId,
      kind: isFile ? 'file' : 'package',
      name,
      version: asString(node.version),
      purl: asString(node.purl),
      supplier: supplierName(node.supplier) ?? asString(node.publisher),
      copyright: asString(node.copyright),
      licenseDeclared: licenseParts(node.licenses, 'declared'),
      licenseConcluded: licenseParts(node.licenses, 'concluded'),
      ...(isFile ? {} : { purpose: PURPOSE_BY_TYPE[type] ?? (type ? type.toUpperCase() : undefined) }),
      description: asString(node.description),
      checksums: readHashes(node.hashes),
      externalRefs: readExternalRefs(node),
      raw: { kind: 'json', value: node },
    });
    if (parentSpdxId) {
      relationships.push({
        from: { kind: 'local', spdxId: parentSpdxId },
        type: 'CONTAINS',
        to: { kind: 'local', spdxId },
      });
    }
    collectBomLinks(node.externalReferences, spdxId);
    // Nested assemblies: a component may carry its own components.
    for (const child of asRecordArray(node.components)) addComponent(child, spdxId, depth + 1);
  };

  // The BOM's subject (metadata.component) is the described root when present.
  const describes: string[] = [];
  const subject = isRecord(metadata.component) ? metadata.component : null;
  if (subject) {
    addComponent(subject);
    const rootId = elements[0]?.spdxId;
    if (rootId) {
      describes.push(rootId);
      relationships.push({
        from: { kind: 'local', spdxId: 'SPDXRef-DOCUMENT' },
        type: 'DESCRIBES',
        to: { kind: 'local', spdxId: rootId },
      });
    }
  }
  const rootSpdxId = describes[0];
  // The components list is the subject's inventory; rendering it as CONTAINS
  // under the described root mirrors how syft-style SPDX nests packages. An
  // interpretation for the tree, not a spec claim - dependencies[] carries
  // the actual graph.
  for (const component of asRecordArray(root.components)) addComponent(component, rootSpdxId);
  collectBomLinks(root.externalReferences, rootSpdxId);

  // dependencies[]: { ref, dependsOn[] } in bom-ref space; a dependsOn entry
  // that is itself a BOM-Link points into another document.
  let unmappedDeps = 0;
  for (const dep of asRecordArray(root.dependencies)) {
    const fromRef = asString(dep.ref);
    const from = fromRef ? idByBomRef.get(fromRef) : undefined;
    if (!from) {
      unmappedDeps++;
      continue;
    }
    for (const target of Array.isArray(dep.dependsOn) ? dep.dependsOn : []) {
      if (typeof target !== 'string') continue;
      if (target.toLowerCase().startsWith('urn:cdx:')) {
        const { docRef, fragment } = bomLinkRef(target);
        relationships.push({
          from: { kind: 'local', spdxId: from },
          type: 'DEPENDS_ON',
          to: { kind: 'external', docRef, spdxId: fragment },
        });
        continue;
      }
      const to = idByBomRef.get(target);
      if (!to) {
        unmappedDeps++;
        continue;
      }
      relationships.push({
        from: { kind: 'local', spdxId: from },
        type: 'DEPENDS_ON',
        to: { kind: 'local', spdxId: to },
      });
    }
  }
  if (unmappedDeps > 0) {
    diagnostics.push(
      diag(
        'info',
        'CDX_DEPENDENCIES_UNMAPPED',
        `${unmappedDeps} dependency reference(s) point outside this BOM's components.`,
      ),
    );
  }
  if (nestingCapped) {
    diagnostics.push(
      diag(
        'warning',
        'CDX_NESTING_CAPPED',
        `Component nesting exceeded ${MAX_NESTING} levels; deeper assemblies were not read.`,
      ),
    );
  }

  // Spec lint last: parser notes explain what could not be read, spec findings
  // what the BOM itself gets wrong. It loads either way.
  diagnostics.push(...validateCdxStructure(root));

  const document: SbomDocument = {
    id: documentId,
    spec,
    spdxId: 'SPDXRef-DOCUMENT',
    name: asString(subject?.name) ?? input.fileName,
    namespace,
    created: asString(metadata.timestamp),
    creators: readCreators(metadata),
    describes,
    externalDocumentRefs,
    elements,
    relationships,
    diagnostics,
  };
  return { document, diagnostics };
}

// -- field readers -------------------------------------------------------------

function readHashes(value: unknown): Checksum[] | undefined {
  const out: Checksum[] = [];
  for (const h of asRecordArray(value)) {
    const alg = asString(h.alg);
    const content = asString(h.content);
    if (alg && content) {
      out.push({ algorithm: alg.toUpperCase().replace(/-/g, ''), value: content.toLowerCase() });
    }
  }
  return out.length > 0 ? out : undefined;
}

/**
 * External references plus the component's CPE: the cpe field is first-class
 * in CycloneDX and lands as a SECURITY reference, which is exactly where the
 * VEX overlay's CPE matching looks.
 */
function readExternalRefs(node: Record<string, unknown>): ExternalRef[] | undefined {
  const out: ExternalRef[] = [];
  const cpe = asString(node.cpe);
  if (cpe) {
    const lower = cpe.toLowerCase();
    out.push({
      category: 'SECURITY',
      // Only claim a concrete form when the string actually has it; matching
      // reads the locator either way.
      type: lower.startsWith('cpe:2.3:') ? 'cpe23Type' : lower.startsWith('cpe:/') ? 'cpe22Type' : 'cpe',
      locator: cpe,
    });
  }
  for (const r of asRecordArray(node.externalReferences)) {
    const url = asString(r.url);
    if (url) out.push({ type: asString(r.type) ?? 'other', locator: url });
  }
  return out.length > 0 ? out : undefined;
}

function supplierName(value: unknown): string | undefined {
  return isRecord(value) ? asString(value.name) : undefined;
}

/**
 * Licenses: expressions and id/name entries, joined. CycloneDX 1.6 marks an
 * entry's `acknowledgment` as declared or concluded; unmarked entries count
 * as declared (the overwhelmingly common case in generator output).
 * CycloneDX leaves the aggregate semantics of a multi-entry license list
 * undefined; joining with AND shows every named license rather than
 * guessing a weaker OR - display, not legal interpretation.
 */
function licenseParts(value: unknown, which: 'declared' | 'concluded'): string | undefined {
  const parts: string[] = [];
  for (const entry of asRecordArray(value)) {
    const ack = asString(entry.acknowledgment) ?? 'declared';
    if (ack !== which) continue;
    const expression = asString(entry.expression);
    if (expression) parts.push(expression);
    const license = isRecord(entry.license) ? entry.license : null;
    const idOrName = license ? (asString(license.id) ?? asString(license.name)) : undefined;
    if (idOrName) parts.push(idOrName);
  }
  return parts.length > 0 ? parts.join(' AND ') : undefined;
}

function readCreators(metadata: Record<string, unknown>): string[] {
  const out: string[] = [];
  const tools = isRecord(metadata.tools)
    ? asRecordArray(metadata.tools.components)
    : asRecordArray(metadata.tools);
  for (const t of tools) {
    const name = asString(t.name);
    if (name) out.push(`Tool: ${name}${asString(t.version) ? `-${asString(t.version)}` : ''}`);
  }
  for (const a of asRecordArray(metadata.authors)) {
    const name = asString(a.name);
    if (name) out.push(`Person: ${name}`);
  }
  return out;
}

/** Verbatim id, suffixed only on (spec-invalid) duplicates. */
function uniqueRaw(candidate: string, used: Set<string>): string {
  let id = candidate;
  if (used.has(id)) {
    let suffix = 2;
    while (used.has(`${id}-${suffix}`)) suffix++;
    id = `${id}-${suffix}`;
  }
  used.add(id);
  return id;
}

function uniqueId(candidate: string, used: Set<string>): string {
  let id = candidate.replace(/[^A-Za-z0-9.-]/g, '-');
  if (used.has(id)) {
    let suffix = 2;
    while (used.has(`${id}-${suffix}`)) suffix++;
    id = `${id}-${suffix}`;
  }
  used.add(id);
  return id;
}
