import type {
  Checksum,
  ElementRef,
  ExternalDocumentRef,
  ExternalRef,
  Relationship,
  SbomElement,
} from '../../model/document';
import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import { makeDocumentId, makeElementId } from '../../model/ids';
import { asRecordArray, asString, asStringArray, isRecord } from '../../util/narrow';
import type { ParseResult, SourceInput } from '../parser';
import { dedupeBySpdxId } from '../spdx2/common';
import { validateSpdx3Structure } from './validate';

/**
 * SPDX 3.0.x JSON-LD → document model. Additive next to the 2.x parsers:
 * SPDX 2.x support is unchanged, this maps the 3.x element graph onto the
 * same element-shaped model, so every view, profile, and analysis works on
 * both. Same tolerance rules as the 2.x parsers: missing pieces degrade to
 * diagnostics, never to a refusal.
 *
 * Scope (stated in README/docs): packages, files, relationships
 * (including multi-target `to` lists), creation info and agents, hashes,
 * purl/CPE external identifiers, licenses expressed through
 * hasDeclaredLicense / hasConcludedLicense relationships, and
 * cross-document imports (ExternalMap): import entries become external
 * document references (grouped by the defining document's IRI), and
 * relationship ends pointing at imported IRIs become external element
 * refs, so the existing cascade resolution links 3.x documents exactly
 * like 2.x ones. The non-software profiles (AI, dataset, build, security)
 * are not mapped yet; their elements are counted, not dropped silently.
 */
export function parseSpdx3Json(input: SourceInput, root: Record<string, unknown>): ParseResult {
  const diagnostics: Diagnostic[] = [];
  const graph = asRecordArray(root['@graph']);
  if (graph.length === 0) {
    return {
      document: null,
      diagnostics: [diag('error', 'SPDX3_NO_GRAPH', 'SPDX 3.x document has no @graph element list.')],
    };
  }

  // --- index the graph -------------------------------------------------------
  const byId = new Map<string, Record<string, unknown>>();
  for (const node of graph) {
    const id = asString(node.spdxId) ?? asString(node['@id']);
    if (id) byId.set(id, node);
  }
  const nodeType = (node: Record<string, unknown>): string => asString(node.type) ?? asString(node['@type']) ?? '';

  const agentName = (ref: unknown): string | undefined => {
    const node = typeof ref === 'string' ? byId.get(ref) : isRecord(ref) ? ref : undefined;
    if (!node) return undefined;
    const name = asString(node.name);
    if (!name) return undefined;
    const type = nodeType(node);
    const prefix = type.includes('Organization')
      ? 'Organization'
      : type.includes('Person')
        ? 'Person'
        : type.includes('Agent') || type.includes('Tool')
          ? 'Tool'
          : 'Organization';
    return `${prefix}: ${name}`;
  };

  /**
   * hasDeclaredLicense/hasConcludedLicense targets resolve to the expression
   * form the rest of the model speaks (the same string an SPDX 2 document
   * would carry), never to a licence TEXT: a text is not an expression, and
   * the lint, the profiles, and the Licenses tab would all report it as
   * unparseable.
   *
   *   LicenseExpression element          -> its simplelicensing_licenseExpression
   *   ListedLicense (by IRI or element)  -> the id, the tail of spdx.org/licenses/<id>
   *   NoAssertionLicense / NoneLicense   -> NOASSERTION / NONE (3.0.1 individuals)
   *   CustomLicense element              -> LicenseRef-<idstring>, as 2.x spells it
   *   structured sets (AND/OR/WITH elements) -> not mapped
   */
  const licenseText = (ref: unknown): string | undefined => {
    if (typeof ref !== 'string') return undefined;
    if (ref.endsWith('/NoAssertionLicense')) return 'NOASSERTION';
    if (ref.endsWith('/NoneLicense')) return 'NONE';
    const node = byId.get(ref);
    if (node) {
      const type = nodeType(node);
      if (type.endsWith('NoAssertionLicense')) return 'NOASSERTION';
      if (type.endsWith('NoneLicense')) return 'NONE';
      const expression = asString(node.simplelicensing_licenseExpression);
      if (expression !== undefined) return expression;
      if (type.endsWith('ListedLicense')) return iriTail(ref);
      if (type.endsWith('CustomLicense')) return customLicenseRef(ref, node);
      return undefined;
    }
    if (ref.includes('/licenses/') || ref.startsWith('spdx.org/licenses/')) return iriTail(ref); // ListedLicense IRI
    return noAssertion(ref);
  };

  // --- document identity ------------------------------------------------------
  const docNode = graph.find((n) => nodeType(n) === 'SpdxDocument');
  const sbomNode = graph.find((n) => nodeType(n) === 'software_Sbom');
  const namespace = asString(docNode?.spdxId) ?? asString(sbomNode?.spdxId) ?? null;
  if (!docNode) {
    diagnostics.push(
      diag('info', 'SPDX3_NO_DOCUMENT_ELEMENT', 'No SpdxDocument element in the graph; document identity is derived from the content.'),
    );
  }
  const documentId = makeDocumentId(namespace, input.sha1);
  const docSpdxId = namespace ?? 'SPDXRef-DOCUMENT';

  const creationRef = docNode?.creationInfo ?? sbomNode?.creationInfo;
  const creationNode =
    (typeof creationRef === 'string' ? byId.get(creationRef) : isRecord(creationRef) ? creationRef : undefined) ??
    graph.find((n) => nodeType(n) === 'CreationInfo');
  const creators: string[] = [];
  for (const ref of [...asStringArray(creationNode?.createdBy), ...asStringArray(creationNode?.createdUsing)]) {
    const name = agentName(ref);
    if (name) creators.push(name);
  }

  // --- imports (ExternalMap) --------------------------------------------------
  // Import entries name elements DEFINED in other documents by IRI. We group
  // them by the defining document: the IRI part before the fragment doubles
  // as that document's namespace (its SpdxDocument @id), which is exactly
  // what the namespace resolution matches once both files are loaded.
  // verifiedUsing hashes ride along (SHA1 feeds the checksum resolver;
  // anything else still renders as the expected hash).
  const externalDocumentRefs: ExternalDocumentRef[] = [];
  const refByDocKey = new Map<string, ExternalDocumentRef>();
  /** imported element IRI -> docRef of its defining document's reference. */
  const importedElements = new Map<string, string>();
  for (const entry of [...asRecordArray(docNode?.import), ...asRecordArray(sbomNode?.import)]) {
    const externalSpdxId = asString(entry.externalSpdxId);
    if (!externalSpdxId) continue;
    const hash = externalSpdxId.indexOf('#');
    const docIri = hash > 0 ? externalSpdxId.slice(0, hash) : undefined;
    const locationHint = asString(entry.locationHint);
    const docKey = docIri ?? locationHint ?? externalSpdxId;
    const hashes = readHashes(entry.verifiedUsing);
    const checksum = hashes?.find((h) => h.algorithm === 'SHA1') ?? hashes?.[0];
    let ref = refByDocKey.get(docKey);
    if (!ref) {
      ref = {
        docRef: docKey,
        uri: docIri ?? locationHint ?? externalSpdxId,
        ...(checksum ? { checksum } : {}),
      };
      refByDocKey.set(docKey, ref);
      externalDocumentRefs.push(ref);
    } else if (!ref.checksum && checksum) {
      // Several imports may point into the same defining document; any one
      // of them carrying a hash is enough to feed the checksum resolver.
      ref.checksum = checksum;
    }
    importedElements.set(externalSpdxId, ref.docRef);
  }

  /** Relationship ends resolve against imports first, local otherwise. */
  const elementRef = (iri: string): ElementRef => {
    const docRef = importedElements.get(iri);
    return docRef !== undefined
      ? { kind: 'external', docRef, spdxId: iri }
      : { kind: 'local', spdxId: iri };
  };

  // --- elements ---------------------------------------------------------------
  const elements: SbomElement[] = [];
  const skippedTypes = new Map<string, number>();
  let anonCounter = 0;

  for (const node of graph) {
    const type = nodeType(node);
    if (type === 'software_Package' || type === 'software_File') {
      const kind = type === 'software_Package' ? 'package' : 'file';
      const name = asString(node.name) ?? `(unnamed ${kind})`;
      const spdxId = asString(node.spdxId) ?? `SPDXRef-sbomlens-anonymous-${++anonCounter}`;
      const externalRefs = readExternalIdentifiers(node.externalIdentifier);
      // SPDX 3.0.1 carries the purl as its own property on software_Package
      // (software_packageUrl); generators that use the externalIdentifier
      // form instead are read through readExternalIdentifiers.
      const purl = asString(node.software_packageUrl) ?? externalRefs?.find((r) => r.type === 'purl')?.locator;
      elements.push({
        id: makeElementId(documentId, spdxId),
        documentId,
        spdxId,
        kind,
        name,
        version: asString(node.software_packageVersion),
        purl,
        supplier: agentName(node.suppliedBy),
        originator: asStringArray(node.originatedBy).map(agentName).find(Boolean),
        downloadLocation: noAssertion(asString(node.software_downloadLocation)),
        copyright: noAssertion(asString(node.software_copyrightText)),
        purpose: asString(node.software_primaryPurpose)?.toUpperCase(),
        description: asString(node.description) ?? asString(node.summary),
        comment: asString(node.comment),
        checksums: readHashes(node.verifiedUsing),
        externalRefs,
        fileName: asString(node.software_packageFileName),
        // Core/Artifact: supportLevel is a list of SupportType; the first
        // entry is what a coverage meter can act on. validUntilTime means
        // "reassess after", not "end of support" - profiles that read it say so.
        supportLevel: asString(node.supportLevel) ?? asStringArray(node.supportLevel)[0],
        validUntil: asString(node.validUntilTime),
        raw: { kind: 'json', value: node },
      });
      continue;
    }
    // Metadata and licensing nodes are consumed, not elements of the tree.
    if (
      type === 'SpdxDocument' ||
      type === 'software_Sbom' ||
      type === 'CreationInfo' ||
      type === 'Relationship' ||
      type === 'ExternalIdentifier' ||
      type === 'Hash' ||
      type.includes('Agent') ||
      type === 'Person' ||
      type === 'Organization' ||
      type === 'Tool' ||
      type.startsWith('simplelicensing_') ||
      type.startsWith('expandedlicensing_') ||
      type === ''
    ) {
      continue;
    }
    skippedTypes.set(type, (skippedTypes.get(type) ?? 0) + 1);
  }

  if (skippedTypes.size > 0) {
    const list = [...skippedTypes.entries()].map(([t, n]) => `${t} (${n})`).join(', ');
    diagnostics.push(
      diag('info', 'SPDX3_ELEMENTS_SKIPPED', `Element types not displayed in this version: ${list}.`),
    );
  }

  // --- relationships ----------------------------------------------------------
  const relationships: Relationship[] = [];
  const describes = new Set<string>();
  const licenseByElement = new Map<string, { declared?: string; concluded?: string }>();
  let malformedRels = 0;

  for (const node of graph) {
    if (nodeType(node) !== 'Relationship') continue;
    const from = asString(node.from);
    const relType = asString(node.relationshipType);
    const targets = asStringArray(node.to);
    if (!from || !relType || targets.length === 0) {
      malformedRels++;
      continue;
    }
    // License relationships fold into the element's license fields instead of
    // becoming tree edges (license expressions are not tree elements here).
    if (relType === 'hasDeclaredLicense' || relType === 'hasConcludedLicense') {
      const entry = licenseByElement.get(from) ?? {};
      const text = licenseText(targets[0]);
      if (relType === 'hasDeclaredLicense') entry.declared = text;
      else entry.concluded = text;
      licenseByElement.set(from, entry);
      continue;
    }
    for (const to of targets) {
      if (relType === 'describes' && !importedElements.has(to)) describes.add(to);
      relationships.push({
        from: elementRef(from),
        type: camelToScreamingSnake(relType),
        to: elementRef(to),
        comment: asString(node.comment),
      });
    }
  }
  if (malformedRels > 0) {
    diagnostics.push(
      diag('warning', 'REL_MALFORMED', `${malformedRels} relationship(s) without from/relationshipType/to skipped.`),
    );
  }

  for (const [spdxId, licenses] of licenseByElement) {
    const element = elements.find((e) => e.spdxId === spdxId);
    if (!element) continue;
    if (licenses.declared) element.licenseDeclared = licenses.declared;
    if (licenses.concluded) element.licenseConcluded = licenses.concluded;
  }

  for (const rootRef of [...asStringArray(docNode?.rootElement), ...asStringArray(sbomNode?.rootElement)]) {
    // rootElement may point at the Sbom collection itself; only elements count.
    if (elements.some((e) => e.spdxId === rootRef)) describes.add(rootRef);
  }

  // Spec lint last: parser notes explain what could not be read, spec findings
  // what the document itself gets wrong. The document loads either way.
  diagnostics.push(...validateSpdx3Structure(graph, byId));

  const specVersion = asString(creationNode?.specVersion) ?? versionFromContext(root) ?? '3.x';
  const document = {
    id: documentId,
    spec: { model: 'spdx-3' as const, version: `SPDX-${specVersion}`, serialization: 'json' as const },
    spdxId: docSpdxId,
    name: asString(docNode?.name) ?? asString(sbomNode?.name) ?? input.fileName,
    namespace,
    created: asString(creationNode?.created),
    creators,
    comment: asString(docNode?.comment),
    dataLicense: licenseText(asString(docNode?.dataLicense)) ?? asString(docNode?.dataLicense),
    describes: [...describes],
    externalDocumentRefs,
    elements: dedupeBySpdxId(elements, diagnostics),
    relationships,
    diagnostics,
    // software_Sbom.sbomType (design, source, build, analyzed, deployed,
    // runtime) - a list in the model; the first entry names the kind.
    ...(sbomType(sbomNode) ? { sbomType: sbomType(sbomNode) } : {}),
  };
  return { document, diagnostics };
}

function sbomType(sbomNode: Record<string, unknown> | undefined): string | undefined {
  if (!sbomNode) return undefined;
  return asString(sbomNode.software_sbomType) ?? asStringArray(sbomNode.software_sbomType)[0];
}

/** SPDX 3 hash algorithm ids are lowercase ('sha256'); our display uppercases. */
function readHashes(value: unknown): Checksum[] | undefined {
  const hashes: Checksum[] = [];
  for (const entry of asRecordArray(value)) {
    const algorithm = asString(entry.algorithm);
    const hashValue = asString(entry.hashValue);
    if (algorithm && hashValue) {
      hashes.push({ algorithm: algorithm.toUpperCase().replace(/-/g, ''), value: hashValue.toLowerCase() });
    }
  }
  return hashes.length > 0 ? hashes : undefined;
}

function readExternalIdentifiers(value: unknown): ExternalRef[] | undefined {
  const refs: ExternalRef[] = [];
  for (const entry of asRecordArray(value)) {
    const type = asString(entry.externalIdentifierType);
    const identifier = asString(entry.identifier);
    if (!type || !identifier) continue;
    if (type === 'packageUrl') refs.push({ category: 'PACKAGE-MANAGER', type: 'purl', locator: identifier });
    else if (type.startsWith('cpe')) refs.push({ category: 'SECURITY', type, locator: identifier });
    else refs.push({ category: 'OTHER', type, locator: identifier });
  }
  return refs.length > 0 ? refs : undefined;
}

/** 'dependsOn' → 'DEPENDS_ON', 'contains' → 'CONTAINS' (matches the 2.x vocab). */
function camelToScreamingSnake(type: string): string {
  return type.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
}

/** SPDX 3 spells absence as Core individuals; align with the 2.x sentinels. */
function noAssertion(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (value.endsWith('NoAssertion')) return 'NOASSERTION';
  if (value.endsWith('/None') || value === 'None') return 'NONE';
  return value;
}

/** The last path or fragment segment of an IRI. */
function iriTail(iri: string): string {
  return iri.slice(Math.max(iri.lastIndexOf('/'), iri.lastIndexOf('#')) + 1);
}

/**
 * A CustomLicense has no expression form of its own; SPDX 2 spells the same
 * thing LicenseRef-<idstring> (Annex D), and that is what the profiles and the
 * Licenses tab count as a reference rather than as text. Generators that
 * follow the 3.0.1 examples already end the IRI in LicenseRef-…; for the
 * rest, the IRI tail (or the name) becomes the idstring.
 */
function customLicenseRef(iri: string, node: Record<string, unknown>): string {
  const tail = iriTail(iri);
  if (/^LicenseRef-[A-Za-z0-9.-]+$/.test(tail)) return tail;
  const stem = (tail || asString(node.name) || 'custom').replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
  return `LicenseRef-${stem || 'custom'}`;
}

function versionFromContext(root: Record<string, unknown>): string | undefined {
  const context = root['@context'];
  const text = Array.isArray(context) ? context.join(' ') : String(context ?? '');
  const match = /spdx\.org\/rdf\/(3\.[0-9.]*[0-9])/.exec(text);
  return match?.[1];
}
