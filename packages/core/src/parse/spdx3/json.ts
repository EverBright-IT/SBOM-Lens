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
import { contextText } from '../../util/jsonld-context';
import { asArray, asRecordArray, asString, asStringArray, isRecord } from '../../util/narrow';
import type { ParseResult, SourceInput } from '../parser';
import { dedupeBySpdxId } from '../spdx2/common';
import { vocabularyTerm } from './individuals';
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
 * like 2.x ones. AI and dataset packages (ai_AIPackage, dataset_DatasetPackage,
 * both Package subclasses) map as packages with purpose MODEL / DATA; their
 * profile-specific fields (ai_*, dataset_*) stay raw. The remaining profile
 * elements (build, security, ...) are counted, not dropped silently.
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

  /**
   * An agent in the SPDX 2 spelling ("Organization: name"). With `contact`,
   * the agent's email, urlScheme or http(s) `other` external identifier
   * rides along as "(contact)": TR-03183-2 appendix 8.2 maps the SBOM
   * creator's and the component creator's contact onto exactly those
   * identifiers. Suppliers keep the bare name, so the Inventory and CSV
   * columns do not move.
   */
  const agentName = (ref: unknown, opts?: { contact?: boolean }): string | undefined => {
    const node = typeof ref === 'string' ? byId.get(ref) : isRecord(ref) ? ref : undefined;
    if (!node) return undefined;
    const name = asString(node.name);
    if (!name) return undefined;
    const type = nodeType(node);
    // SoftwareAgent and Tool are software. A plain Agent says nothing about
    // its nature and takes the same fallback as any other agent type.
    const prefix = type.includes('Organization')
      ? 'Organization'
      : type.includes('Person')
        ? 'Person'
        : type.includes('SoftwareAgent') || type.includes('Tool')
          ? 'Tool'
          : 'Organization';
    const contact = opts?.contact ? agentContact(node) : undefined;
    return `${prefix}: ${name}${contact ? ` (${contact})` : ''}`;
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
   *   NoAssertionLicense / NoneLicense   -> NOASSERTION / NONE (3.0.1 individuals,
   *     by IRI or by the short term the context defines for them)
   *   CustomLicense element              -> LicenseRef-<idstring>, as 2.x spells it
   *   ConjunctiveLicenseSet / DisjunctiveLicenseSet -> members joined by AND / OR,
   *     compound members in parentheses
   *   OrLaterOperator                    -> <licence>+
   *   WithAdditionOperator               -> <licence> WITH <exception or AdditionRef->
   *
   * Members and operands may be IRIs or inline elements. A structure with a
   * part that cannot be read yields nothing rather than half an expression.
   */
  const licenseMemo = new Map<string, string | undefined>();
  const licenseInProgress = new Set<string>();
  const licenseText = (ref: unknown, depth = 0): string | undefined => {
    const iri = typeof ref === 'string' ? ref : isRecord(ref) ? (asString(ref.spdxId) ?? asString(ref['@id'])) : undefined;
    const term = iri !== undefined ? vocabularyTerm(iri) : undefined;
    if (term === 'NoAssertionLicense' || iri?.endsWith('/NoAssertionLicense')) return 'NOASSERTION';
    if (term === 'NoneLicense' || iri?.endsWith('/NoneLicense')) return 'NONE';
    const node = isRecord(ref) ? ref : iri !== undefined ? byId.get(iri) : undefined;
    if (node) {
      const type = nodeType(node);
      if (type.endsWith('NoAssertionLicense')) return 'NOASSERTION';
      if (type.endsWith('NoneLicense')) return 'NONE';
      const expression = asString(node.simplelicensing_licenseExpression);
      if (expression !== undefined) return upperCaseOperators(expression);
      if (type.endsWith('ListedLicense')) return iri !== undefined ? iriTail(iri) : undefined;
      if (type.endsWith('CustomLicense')) return customLicenseRef(iri ?? '', node);
      if (depth >= MAX_LICENSE_DEPTH) return undefined;
      // Structures can be shared, and a hostile one can contain itself: each
      // referenced structure is folded once, a cycle reads as unreadable, and
      // the text is capped far above any real expression.
      if (iri !== undefined) {
        if (licenseMemo.has(iri)) return licenseMemo.get(iri);
        if (licenseInProgress.has(iri)) return undefined;
        licenseInProgress.add(iri);
      }
      const folded = foldLicenseStructure(node, type, depth);
      const result = folded !== undefined && folded.length <= MAX_LICENSE_TEXT ? folded : undefined;
      if (iri !== undefined) {
        licenseInProgress.delete(iri);
        licenseMemo.set(iri, result);
      }
      return result;
    }
    if (iri === undefined) return undefined;
    if (iri.includes('/licenses/') || iri.startsWith('spdx.org/licenses/')) return iriTail(iri); // ListedLicense IRI
    return noAssertion(iri);
  };

  /**
   * A licence that can stand inside a set or under an operator: resolved, and
   * neither an absence (NONE, NOASSERTION) nor a reference that resolves to
   * nothing and merely comes back as its own text.
   */
  const licenseOperand = (ref: unknown, depth: number): string | undefined => {
    const text = licenseText(ref, depth);
    return text === undefined || text === 'NONE' || text === 'NOASSERTION' || text === ref ? undefined : text;
  };

  /** AND/OR sets, or-later and with-addition operators; undefined when a part cannot be read. */
  const foldLicenseStructure = (node: Record<string, unknown>, type: string, depth: number): string | undefined => {
    const conjunctive = type.endsWith('ConjunctiveLicenseSet');
    if (conjunctive || type.endsWith('DisjunctiveLicenseSet')) {
      const parts: string[] = [];
      let length = 0;
      for (const member of asArray(node.expandedlicensing_member)) {
        const part = licenseOperand(member, depth + 1);
        if (part === undefined) return undefined;
        const piece = /\s(AND|OR)\s/.test(part) ? `(${part})` : part;
        length += piece.length + 5;
        if (length > MAX_LICENSE_TEXT) return undefined;
        parts.push(piece);
      }
      return parts.length > 0 ? parts.join(conjunctive ? ' AND ' : ' OR ') : undefined;
    }
    if (type.endsWith('OrLaterOperator')) {
      const subject = licenseOperand(node.expandedlicensing_subjectLicense, depth + 1);
      return subject !== undefined && /^[A-Za-z0-9.:-]+$/.test(subject) ? `${subject}+` : undefined;
    }
    if (type.endsWith('WithAdditionOperator')) {
      const subject = licenseOperand(node.expandedlicensing_subjectExtendableLicense, depth + 1);
      const addition = additionText(node.expandedlicensing_subjectAddition);
      return subject !== undefined && addition !== undefined && /^[A-Za-z0-9.:-]+\+?$/.test(subject)
        ? `${subject} WITH ${addition}`
        : undefined;
    }
    return undefined;
  };

  /** The operand after WITH: a listed exception by its id, a custom addition as AdditionRef-<idstring>. */
  const additionText = (ref: unknown): string | undefined => {
    const iri = typeof ref === 'string' ? ref : isRecord(ref) ? (asString(ref.spdxId) ?? asString(ref['@id'])) : undefined;
    const node = isRecord(ref) ? ref : iri !== undefined ? byId.get(iri) : undefined;
    const type = node ? nodeType(node) : '';
    if (type.endsWith('CustomLicenseAddition')) {
      const tail = iri !== undefined ? iriTail(iri) : '';
      if (/^AdditionRef-[A-Za-z0-9.-]+$/.test(tail)) return tail;
      return `AdditionRef-${idstring(tail || asString(node?.name) || 'custom') || 'custom'}`;
    }
    if (iri !== undefined && (type.endsWith('ListedLicenseException') || iri.includes('/licenses/'))) return iriTail(iri);
    return undefined;
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
    const name = agentName(ref, { contact: true });
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
    const special = specialElement(iri);
    if (special) return { kind: 'special', value: special };
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
    const impliedPurpose = Object.hasOwn(PURPOSE_BY_PACKAGE_TYPE, type) ? PURPOSE_BY_PACKAGE_TYPE[type] : undefined;
    if (type === 'software_Package' || type === 'software_File' || impliedPurpose !== undefined) {
      const kind = type === 'software_File' ? 'file' : 'package';
      const name = asString(node.name) ?? `(unnamed ${kind})`;
      const spdxId = asString(node.spdxId) ?? `SPDXRef-sbomlens-anonymous-${++anonCounter}`;
      const identifiers = readExternalIdentifiers(node.externalIdentifier);
      const links = readExternalRefs(node.externalRef);
      const externalRefs = identifiers || links ? [...(identifiers ?? []), ...(links ?? [])] : undefined;
      // SPDX 3.0.1 carries the purl as its own property on software_Package
      // (software_packageUrl); generators that use the externalIdentifier
      // form instead are read through readExternalIdentifiers.
      const purl = asString(node.software_packageUrl) ?? identifiers?.find((r) => r.type === 'purl')?.locator;
      elements.push({
        id: makeElementId(documentId, spdxId),
        documentId,
        spdxId,
        kind,
        name,
        version: asString(node.software_packageVersion),
        purl,
        supplier: agentName(node.suppliedBy),
        originator: asStringArray(node.originatedBy)
          .map((ref) => agentName(ref, { contact: true }))
          .find(Boolean),
        downloadLocation: noAssertion(asString(node.software_downloadLocation)),
        copyright: noAssertion(asString(node.software_copyrightText)),
        // The AI and dataset profiles say what the package is even when
        // primaryPurpose is absent; a stated purpose still wins.
        purpose: asString(node.software_primaryPurpose)?.toUpperCase() ?? impliedPurpose,
        description: asString(node.description) ?? asString(node.summary),
        comment: asString(node.comment),
        checksums: readHashes(node.verifiedUsing),
        externalRefs,
        // 3.0.1 has no packageFileName: the filename is the name of the File
        // reached through hasDistributionArtifact, filled in below. The
        // property is still read when a generator writes it.
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
      type === 'LifecycleScopedRelationship' ||
      type === 'ExternalIdentifier' ||
      type === 'ExternalRef' ||
      type === 'ExternalMap' ||
      type === 'NamespaceMap' ||
      type === 'DictionaryEntry' ||
      type === 'PositiveIntegerRange' ||
      type === 'PackageVerificationCode' ||
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
  const distributionArtifacts = new Map<string, string>();
  let malformedRels = 0;
  let unmappedLicenses = 0;

  for (const node of graph) {
    const relClass = nodeType(node);
    if (relClass !== 'Relationship' && relClass !== 'LifecycleScopedRelationship') continue;
    const from = asString(node.from);
    const relTypeText = asString(node.relationshipType);
    const relType = relTypeText !== undefined ? iriTail(relTypeText) : undefined;
    // `to` is a list in 3.x; the single-value shorthand occurs in the wild.
    const targets = typeof node.to === 'string' ? [node.to] : asStringArray(node.to);
    if (!from || !relType || targets.length === 0) {
      malformedRels++;
      continue;
    }
    const scopeText = asString(node.scope);
    const scope = scopeText !== undefined ? iriTail(scopeText) : undefined;
    // License relationships fold into the element's license fields instead of
    // becoming tree edges (license expressions are not tree elements here).
    if (relType === 'hasDeclaredLicense' || relType === 'hasConcludedLicense') {
      const entry = licenseByElement.get(from) ?? {};
      const text = licenseText(targets[0]);
      if (text === undefined) unmappedLicenses++;
      if (relType === 'hasDeclaredLicense') entry.declared = text;
      else entry.concluded = text;
      licenseByElement.set(from, entry);
      continue;
    }
    if (relType === 'hasDistributionArtifact') distributionArtifacts.set(from, targets[0]!);
    for (const to of targets) {
      if (relType === 'describes' && !importedElements.has(to) && !specialElement(to)) describes.add(to);
      relationships.push({
        from: elementRef(from),
        type: camelToScreamingSnake(relType),
        to: elementRef(to),
        comment: asString(node.comment),
        ...(scope !== undefined ? { scope } : {}),
      });
    }
  }
  if (malformedRels > 0) {
    diagnostics.push(
      diag('warning', 'REL_MALFORMED', `${malformedRels} relationship(s) without from/relationshipType/to skipped.`),
    );
  }
  if (unmappedLicenses > 0) {
    diagnostics.push(
      diag(
        'info',
        'SPDX3_LICENSE_NOT_MAPPED',
        `${unmappedLicenses} licence statement(s) point at a licence structure this version cannot read as an expression; those licence fields stay empty.`,
      ),
    );
  }

  // First element per spdxId, as the lookups below always took; duplicates
  // are reported by dedupeBySpdxId.
  const elementBySpdxId = new Map<string, SbomElement>();
  for (const element of elements) {
    if (!elementBySpdxId.has(element.spdxId)) elementBySpdxId.set(element.spdxId, element);
  }

  for (const [spdxId, licenses] of licenseByElement) {
    const element = elementBySpdxId.get(spdxId);
    if (!element) continue;
    if (licenses.declared) element.licenseDeclared = licenses.declared;
    if (licenses.concluded) element.licenseConcluded = licenses.concluded;
  }

  // TR-03183-2 appendix 8.2: a package's filename is the name of the File it
  // reaches through hasDistributionArtifact. The edge stays in the tree.
  for (const [spdxId, target] of distributionArtifacts) {
    const element = elementBySpdxId.get(spdxId);
    const file = elementBySpdxId.get(target);
    if (element && file?.kind === 'file' && element.fileName === undefined) element.fileName = file.name;
  }

  for (const rootRef of [...asStringArray(docNode?.rootElement), ...asStringArray(sbomNode?.rootElement)]) {
    // rootElement may point at the Sbom collection itself; only elements count.
    if (elementBySpdxId.has(rootRef)) describes.add(rootRef);
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

/** Nesting cap for structured licence sets: deep enough for any real document. */
const MAX_LICENSE_DEPTH = 16;
/** Length cap for a folded licence expression, far above any real one. */
const MAX_LICENSE_TEXT = 8192;

/** Package subclasses of the AI and dataset profiles, and the purpose they imply. Read with Object.hasOwn: the key comes from the document. */
const PURPOSE_BY_PACKAGE_TYPE: Record<string, string> = {
  ai_AIPackage: 'MODEL',
  dataset_DatasetPackage: 'DATA',
};

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

/**
 * General externalRef links (vcs, securityAdvisory, ...): one entry per
 * locator, category OTHER, the type as its vocabulary term. They are links,
 * not identifiers, so the unique-identifier checks do not count them.
 */
function readExternalRefs(value: unknown): ExternalRef[] | undefined {
  const refs: ExternalRef[] = [];
  for (const entry of asRecordArray(value)) {
    const typeText = asString(entry.externalRefType);
    const type = typeText !== undefined ? iriTail(typeText) : 'other';
    const locators = typeof entry.locator === 'string' ? [entry.locator] : asStringArray(entry.locator);
    for (const locator of locators) {
      if (locator.length > 0) refs.push({ category: 'OTHER', type, locator });
    }
  }
  return refs.length > 0 ? refs : undefined;
}

/**
 * The Core individuals that stand for "no element" and "no assertion" as a
 * relationship end, by IRI or by the context's short term. An element of the
 * document's own whose IRI merely ends in one of these names stays an element.
 */
function specialElement(ref: string): 'NONE' | 'NOASSERTION' | undefined {
  const term = vocabularyTerm(ref);
  if (term === 'NoneElement') return 'NONE';
  if (term === 'NoAssertionElement') return 'NOASSERTION';
  return undefined;
}

/** The contact an agent states: an email, else a urlScheme, else an http(s) identifier of type other. */
function agentContact(node: Record<string, unknown>): string | undefined {
  const identifiers = asRecordArray(node.externalIdentifier).flatMap((entry) => {
    const type = asString(entry.externalIdentifierType);
    const identifier = asString(entry.identifier);
    return type && identifier ? [{ type, identifier }] : [];
  });
  return (
    identifiers.find((i) => i.type === 'email')?.identifier ??
    identifiers.find((i) => i.type === 'urlScheme')?.identifier ??
    identifiers.find((i) => i.type === 'other' && /^https?:\/\//.test(i.identifier))?.identifier
  );
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

/**
 * SPDX 3.0.1 allows `and`/`or`/`with` in lower case; the rest of the model
 * speaks the 2.3 form (upper case only), so the mapping normalises them.
 * Operands are untouched: identifiers are case-insensitive by definition.
 */
function upperCaseOperators(expression: string): string {
  return expression.replace(/(^|[\s()])(and|or|with)(?=[\s()]|$)/g, (_m, before: string, op: string) => `${before}${op.toUpperCase()}`);
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
  return `LicenseRef-${idstring(tail || asString(node.name) || 'custom') || 'custom'}`;
}

/**
 * An idstring as SPDX spells it: every run of other characters becomes one
 * hyphen, and no hyphen stays at either end. The ends are trimmed by index,
 * not by a regular expression: `-+$` backtracks quadratically over a long
 * hyphen run, and the IRI comes from the document.
 */
function idstring(text: string): string {
  const collapsed = text.replace(/[^A-Za-z0-9.-]+/g, '-');
  let start = 0;
  let end = collapsed.length;
  while (start < end && collapsed.charCodeAt(start) === 45) start++;
  while (end > start && collapsed.charCodeAt(end - 1) === 45) end--;
  return collapsed.slice(start, end);
}

function versionFromContext(root: Record<string, unknown>): string | undefined {
  const match = /spdx\.org\/rdf\/(3\.[0-9.]*[0-9])/.exec(contextText(root['@context']));
  return match?.[1];
}
