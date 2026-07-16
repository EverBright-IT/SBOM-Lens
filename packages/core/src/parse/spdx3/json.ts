import type {
  Checksum,
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

/**
 * SPDX 3.0.x JSON-LD → document model. Additive next to the 2.x parsers:
 * SPDX 2.x support is unchanged, this maps the 3.x element graph onto the
 * same element-shaped model, so every view, profile, and analysis works on
 * both. Same tolerance rules as the 2.x parsers: missing pieces degrade to
 * diagnostics, never to a refusal.
 *
 * Scope (v1, stated in README/docs): packages, files, relationships
 * (including multi-target `to` lists), creation info and agents, hashes,
 * purl/CPE external identifiers, and licenses expressed through
 * hasDeclaredLicense / hasConcludedLicense relationships. Cross-document
 * imports (ExternalMap) and the non-software profiles (AI, dataset, build,
 * security) are not mapped yet; their elements are counted, not dropped
 * silently.
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

  /** hasDeclaredLicense/hasConcludedLicense targets resolve to expressions. */
  const licenseText = (ref: unknown): string | undefined => {
    if (typeof ref !== 'string') return undefined;
    if (ref.includes('/licenses/') || ref.startsWith('spdx.org/licenses/')) {
      return ref.slice(ref.lastIndexOf('/') + 1); // ListedLicense IRI
    }
    const node = byId.get(ref);
    if (!node) return noAssertion(ref);
    return (
      asString(node.simplelicensing_licenseExpression) ??
      asString(node.simplelicensing_licenseText) ??
      asString(node.name)
    );
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
      const purl = externalRefs?.find((r) => r.type === 'purl')?.locator;
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
      if (relType === 'describes') describes.add(to);
      relationships.push({
        from: { kind: 'local', spdxId: from },
        type: camelToScreamingSnake(relType),
        to: { kind: 'local', spdxId: to },
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
    externalDocumentRefs: [],
    elements: dedupeBySpdxId(elements, diagnostics),
    relationships,
    diagnostics,
  };
  return { document, diagnostics };
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

function versionFromContext(root: Record<string, unknown>): string | undefined {
  const context = root['@context'];
  const text = Array.isArray(context) ? context.join(' ') : String(context ?? '');
  const match = /spdx\.org\/rdf\/(3\.[0-9.]*[0-9])/.exec(text);
  return match?.[1];
}
