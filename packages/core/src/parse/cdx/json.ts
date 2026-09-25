import type {
  Checksum,
  ExternalDocumentRef,
  ExternalRef,
  Relationship,
  SbomDocument,
  SbomElement,
  SpecInfo,
} from '../../model/document';
import type { CryptoElementExt, CryptoRelatedAsset } from '../../model/crypto';
import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import { makeDocumentId, makeElementId } from '../../model/ids';
import { asRecordArray, asString, asStringArray, isRecord } from '../../util/narrow';
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
  // Kept as its own purpose so an inventory facet can isolate the CBOM part.
  'cryptographic-asset': 'CRYPTOGRAPHIC-ASSET',
};

export function parseCdxJson(
  input: SourceInput,
  root: Record<string, unknown>,
  serialization: 'json' | 'yaml' | 'xml',
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
    const fragment = hash === -1 ? null : decodeFragment(url.slice(hash + 1));
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
  let assetsWithoutProperties = 0;
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
      // The entity that created the component: 1.6 manufacturer, else the
      // authors list (1.6), else the single author string (1.5 and earlier).
      // This is the "producer" the CISA 2026 and G7 elements ask for.
      originator: supplierName(node.manufacturer) ?? entityNames(node.authors) ?? asString(node.author),
      copyright: asString(node.copyright),
      licenseDeclared: licenseParts(node.licenses, 'declared'),
      licenseConcluded: licenseParts(node.licenses, 'concluded'),
      ...(isFile ? {} : { purpose: PURPOSE_BY_TYPE[type] ?? (type ? type.toUpperCase() : undefined) }),
      description: asString(node.description),
      checksums: readHashes(node.hashes),
      externalRefs: readExternalRefs(node),
      properties: readProperties(node.properties),
      ...(isRecord(node.cryptoProperties) ? { crypto: readCryptoProperties(node.cryptoProperties) } : {}),
      raw: { kind: 'json', value: node },
    });
    if (type === 'cryptographic-asset' && !isRecord(node.cryptoProperties)) assetsWithoutProperties++;
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
    // provides[] (1.5+): what this component makes available, e.g. a library
    // providing the algorithms a CBOM lists. Rendered as PROVIDES, an open
    // type the tree does not follow (it is not containment).
    for (const target of Array.isArray(dep.provides) ? dep.provides : []) {
      if (typeof target !== 'string') continue;
      if (target.toLowerCase().startsWith('urn:cdx:')) {
        const { docRef, fragment } = bomLinkRef(target);
        relationships.push({ from: { kind: 'local', spdxId: from }, type: 'PROVIDES', to: { kind: 'external', docRef, spdxId: fragment } });
        continue;
      }
      const to = idByBomRef.get(target);
      if (!to) {
        unmappedDeps++;
        continue;
      }
      relationships.push({ from: { kind: 'local', spdxId: from }, type: 'PROVIDES', to: { kind: 'local', spdxId: to } });
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
  if (assetsWithoutProperties > 0) {
    // Legal (cryptoProperties is optional on every component type), but
    // such an asset carries nothing the CBOM views or profiles can read.
    diagnostics.push(
      diag(
        'info',
        'CDX_CRYPTO_PROPERTIES_MISSING',
        `${assetsWithoutProperties} cryptographic-asset component(s) carry no cryptoProperties and are listed without algorithm, certificate, key or protocol data.`,
      ),
    );
  }

  // Spec lint last: parser notes explain what could not be read, spec findings
  // what the BOM itself gets wrong. It loads either way.
  diagnostics.push(...validateCdxStructure(root));

  const lifecycles = readLifecycles(metadata);
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
    // CycloneDX has no sbomType; the first lifecycle phase is the closest
    // statement of "what kind of BOM this is" and is reported as such.
    ...(lifecycles ? { lifecycles, sbomType: lifecycles[0] } : {}),
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

/** The names of an organizationalContact/organizationalEntity list, joined; undefined when none. */
function entityNames(value: unknown): string | undefined {
  const names = asRecordArray(value)
    .map((entry) => asString(entry.name))
    .filter((name): name is string => name !== undefined && name !== '');
  return names.length > 0 ? names.join(', ') : undefined;
}

/** `properties[]` name/value pairs, verbatim; entries without both are dropped. */
function readProperties(value: unknown): { name: string; value: string }[] | undefined {
  const out: { name: string; value: string }[] = [];
  for (const p of asRecordArray(value)) {
    const name = asString(p.name);
    const v = typeof p.value === 'string' ? p.value : undefined;
    if (name && v !== undefined) out.push({ name, value: v });
  }
  return out.length > 0 ? out : undefined;
}

/** `metadata.lifecycles[].phase` (1.5+), in order. */
function readLifecycles(metadata: Record<string, unknown>): string[] | undefined {
  const phases = asRecordArray(metadata.lifecycles)
    .map((l) => asString(l.phase) ?? asString(l.name))
    .filter((p): p is string => p !== undefined);
  return phases.length > 0 ? phases : undefined;
}

/**
 * Licenses: expressions and id/name entries, joined. CycloneDX 1.6 marks an
 * entry as declared or concluded via `acknowledgement`, which sits next to
 * `expression` in the expression form and inside the `license` object in
 * the id/name form (bom-1.6.schema.json). Unmarked entries count as
 * declared (the overwhelmingly common case in generator output).
 * CycloneDX leaves the aggregate semantics of a multi-entry license list
 * undefined; joining with AND shows every named license rather than
 * guessing a weaker OR - display, not legal interpretation.
 */
function licenseParts(value: unknown, which: 'declared' | 'concluded'): string | undefined {
  const parts: string[] = [];
  for (const entry of asRecordArray(value)) {
    const license = isRecord(entry.license) ? entry.license : null;
    const ack =
      asString(entry.acknowledgement) ?? (license ? asString(license.acknowledgement) : undefined) ?? 'declared';
    if (ack !== which) continue;
    const expression = asString(entry.expression);
    if (expression) parts.push(expression);
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

/** A BOM-Link fragment, percent-decoded when it decodes; a malformed escape stays verbatim rather than refusing the document. */
function decodeFragment(fragment: string): string {
  try {
    return decodeURIComponent(fragment);
  } catch {
    return fragment;
  }
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

/**
 * `cryptoProperties` (CBOM, 1.6 and 1.7) into the crypto extension. Tolerant
 * of both generations: 1.6 `curve` and the per-field refs, 1.7
 * `ellipticCurve`, `algorithmFamily` and `relatedCryptographicAssets`. The
 * XML mapper produces the same object shape, so one reader serves both.
 */
function readCryptoProperties(cp: Record<string, unknown>): CryptoElementExt {
  const related: CryptoRelatedAsset[] = [];
  const collectRelated = (node: Record<string, unknown>) => {
    for (const entry of asRecordArray(node.relatedCryptographicAssets)) {
      const ref = asString(entry.ref);
      if (ref) related.push({ type: asString(entry.type) ?? 'related', ref });
    }
  };
  const ext: CryptoElementExt = {
    ...(asString(cp.assetType) !== undefined ? { assetType: asString(cp.assetType)! } : {}),
    ...(asString(cp.oid) !== undefined ? { oid: asString(cp.oid)! } : {}),
  };
  const ap = isRecord(cp.algorithmProperties) ? cp.algorithmProperties : undefined;
  if (ap) {
    ext.algorithm = compact({
      primitive: asString(ap.primitive),
      family: asString(ap.algorithmFamily),
      parameterSet: asString(ap.parameterSetIdentifier),
      ellipticCurve: asString(ap.ellipticCurve),
      curve: asString(ap.curve),
      executionEnvironment: asString(ap.executionEnvironment),
      implementationPlatform: asString(ap.implementationPlatform),
      certificationLevel: nonEmpty(strings(ap.certificationLevel)),
      mode: asString(ap.mode),
      padding: asString(ap.padding),
      cryptoFunctions: nonEmpty(strings(ap.cryptoFunctions)),
      classicalSecurityLevel: asInteger(ap.classicalSecurityLevel),
      nistQuantumSecurityLevel: asInteger(ap.nistQuantumSecurityLevel),
    });
  }
  const cert = isRecord(cp.certificateProperties) ? cp.certificateProperties : undefined;
  if (cert) {
    const fingerprint = isRecord(cert.fingerprint) ? cert.fingerprint : undefined;
    ext.certificate = compact({
      serialNumber: asString(cert.serialNumber),
      subjectName: asString(cert.subjectName),
      issuerName: asString(cert.issuerName),
      notValidBefore: asString(cert.notValidBefore),
      notValidAfter: asString(cert.notValidAfter),
      certificateFormat: asString(cert.certificateFormat),
      fileExtension: asString(cert.certificateFileExtension) ?? asString(cert.certificateExtension),
      // Pre-defined states carry `state`, custom ones `name` (1.7).
      states: nonEmpty(
        asRecordArray(cert.certificateState)
          .map((s) => asString(s.state) ?? asString(s.name))
          .filter((s): s is string => s !== undefined && s !== '')
          .concat(strings(cert.certificateState)),
      ),
      creationDate: asString(cert.creationDate),
      activationDate: asString(cert.activationDate),
      deactivationDate: asString(cert.deactivationDate),
      revocationDate: asString(cert.revocationDate),
      destructionDate: asString(cert.destructionDate),
      fingerprint: fingerprint ? nonEmptyObject(compact({ algorithm: asString(fingerprint.alg), value: asString(fingerprint.content) })) : undefined,
    });
    for (const [field, type] of [
      ['signatureAlgorithmRef', 'signatureAlgorithm'],
      ['subjectPublicKeyRef', 'subjectPublicKey'],
    ] as const) {
      const ref = asString(cert[field]);
      if (ref) related.push({ type, ref });
    }
    collectRelated(cert);
  }
  const mat = isRecord(cp.relatedCryptoMaterialProperties) ? cp.relatedCryptoMaterialProperties : undefined;
  if (mat) {
    const securedBy = isRecord(mat.securedBy) ? mat.securedBy : undefined;
    ext.material = compact({
      type: asString(mat.type),
      id: asString(mat.id),
      state: asString(mat.state),
      creationDate: asString(mat.creationDate),
      activationDate: asString(mat.activationDate),
      updateDate: asString(mat.updateDate),
      expirationDate: asString(mat.expirationDate),
      size: asInteger(mat.size),
      format: asString(mat.format),
      securedBy: securedBy
        ? nonEmptyObject(compact({ mechanism: asString(securedBy.mechanism), algorithmRef: asString(securedBy.algorithmRef) }))
        : undefined,
    });
    const ref = asString(mat.algorithmRef);
    if (ref) related.push({ type: 'algorithm', ref });
    collectRelated(mat);
  }
  const proto = isRecord(cp.protocolProperties) ? cp.protocolProperties : undefined;
  if (proto) {
    ext.protocol = compact({
      type: asString(proto.type),
      version: asString(proto.version),
      cipherSuites: nonEmpty(
        asRecordArray(proto.cipherSuites)
          .map((suite) =>
            nonEmptyObject(
              compact({
                name: asString(suite.name),
                algorithms: nonEmpty(strings(suite.algorithms)),
                identifiers: nonEmpty(strings(suite.identifiers)),
              }),
            ),
          )
          .filter((suite): suite is NonNullable<typeof suite> => suite !== undefined),
      ),
    });
    for (const ref of strings(proto.cryptoRefArray)) related.push({ type: 'protocolCrypto', ref });
    collectRelated(proto);
  }
  if (related.length > 0) ext.related = related;
  return ext;
}

function asInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

function nonEmpty<T>(list: T[]): T[] | undefined {
  return list.length > 0 ? list : undefined;
}

/** Non-empty strings of a list (an empty XML element reads as ""). */
function strings(value: unknown): string[] {
  return asStringArray(value).filter((s) => s !== '');
}

/** An object that states nothing is not worth carrying. */
function nonEmptyObject<T extends object>(value: T): T | undefined {
  return Object.keys(value).length > 0 ? value : undefined;
}

type Compact<T> = { [K in keyof T]?: Exclude<T[K], undefined> };

/** Drops undefined members so the model carries only what the BOM said. */
function compact<T extends Record<string, unknown>>(value: T): Compact<T> {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Compact<T>;
}
