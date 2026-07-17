import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import type { ExternalDocumentRef, Relationship, SbomDocument, SbomElement } from '../model/document';
import { makeDocumentId, makeElementId } from '../model/ids';
import { parseDocument } from '../parse/parser';
import { buildPurl } from '../util/purl';
import { sha1Hex } from '../util/sha1';
import type { ComposeArtifact, ComposeConfig } from './config';
import { purlPartsFor } from './config';

/**
 * Link-only composition: builds ONE fresh product-level SPDX document whose
 * artifacts point at their child SBOMs via ExternalDocumentRef + SHA-1 —
 * the same mechanics the viewer resolves. The children are read, hashed,
 * and parsed for their namespace, but NEVER modified, merged, or rewritten:
 * their provenance (tool, timestamps, signatures-by-hash) stays exactly as
 * the scanner produced it. That is the architectural difference to
 * flatten/merge tools, and it is what makes the output verifiable — the
 * checksum either matches the file you ship or it does not.
 */

export interface ComposeChild {
  /** The artifact (by config name) this child SBOM belongs to. */
  artifact: string;
  fileName: string;
  bytes: Uint8Array;
}

export interface ComposeResult {
  document: SbomDocument;
  /** Non-fatal notes (fatal problems throw ComposeError instead). */
  diagnostics: Diagnostic[];
}

export class ComposeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ComposeError';
  }
}

export interface ComposeOptions {
  /** Deterministic creation timestamp (SPDX format); defaults to now. */
  created?: string;
  /** Version stamped into the tool creator string. */
  toolVersion?: string;
}

export async function composeDocument(
  config: ComposeConfig,
  children: ComposeChild[],
  options?: ComposeOptions,
): Promise<ComposeResult> {
  const diagnostics: Diagnostic[] = [];
  const created = options?.created ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(created)) {
    throw new ComposeError(`"created" must be an SPDX timestamp (YYYY-MM-DDTHH:MM:SSZ), got "${created}"`);
  }

  const documentId = makeDocumentId(config.product.namespace, '');
  const usedSpdxIds = new Set<string>(['SPDXRef-DOCUMENT']);
  const usedDocRefs = new Set<string>();
  const elements: SbomElement[] = [];
  const relationships: Relationship[] = [];
  const externalDocumentRefs: ExternalDocumentRef[] = [];

  const childByArtifact = new Map<string, ComposeChild>();
  for (const child of children) {
    if (childByArtifact.has(child.artifact)) {
      throw new ComposeError(`more than one child SBOM supplied for artifact "${child.artifact}"`);
    }
    childByArtifact.set(child.artifact, child);
  }

  // Root package: the product itself.
  const rootId = uniqueId(usedSpdxIds, `SPDXRef-Package-${sanitize(config.product.name)}`);
  elements.push(
    packageElement(documentId, rootId, {
      name: config.product.name,
      version: config.product.version,
      supplier: config.product.supplier,
      license: config.product.license,
      copyright: config.product.copyright,
      comment: config.product.comment,
      purpose: config.product.purpose ?? 'APPLICATION',
      purl: config.product.purl
        ? buildPurl(purlPartsFor(config.product.purl, config.product.name, config.product.version))
        : undefined,
    }),
  );
  relationships.push({
    from: { kind: 'local', spdxId: 'SPDXRef-DOCUMENT' },
    type: 'DESCRIBES',
    to: { kind: 'local', spdxId: rootId },
  });

  for (const artifact of config.artifacts) {
    const spdxId = uniqueId(usedSpdxIds, `SPDXRef-Package-${sanitize(artifact.name)}`);
    elements.push(
      packageElement(documentId, spdxId, {
        name: artifact.name,
        version: artifact.version,
        supplier: artifact.supplier,
        license: artifact.license,
        copyright: artifact.copyright,
        downloadLocation: artifact.downloadLocation,
        comment: artifact.comment,
        purpose: artifact.purpose,
        checksums: artifact.checksums,
        purl: artifact.purl ? buildPurl(purlPartsFor(artifact.purl, artifact.name, artifact.version)) : undefined,
      }),
    );
    relationships.push({
      from: { kind: 'local', spdxId: rootId },
      type: artifact.relationship ?? config.relationshipType ?? 'CONTAINS',
      to: { kind: 'local', spdxId: spdxId },
    });

    if (artifact.sbom) {
      const child = childByArtifact.get(artifact.name);
      if (!child) {
        throw new ComposeError(`artifact "${artifact.name}" declares an SBOM but no child bytes were supplied`);
      }
      childByArtifact.delete(artifact.name);
      const ref = await childRef(artifact, child, usedDocRefs);
      externalDocumentRefs.push(ref.ref);
      diagnostics.push(...ref.diagnostics);
      relationships.push({
        from: { kind: 'local', spdxId: spdxId },
        type: 'DESCRIBED_BY',
        to: { kind: 'external', docRef: ref.ref.docRef, spdxId: 'SPDXRef-DOCUMENT' },
      });
    }
  }
  if (childByArtifact.size > 0) {
    throw new ComposeError(
      `child SBOMs supplied for unknown artifacts: ${[...childByArtifact.keys()].join(', ')}`,
    );
  }

  const document: SbomDocument = {
    id: documentId,
    spec: { model: 'spdx-2', version: 'SPDX-2.3', serialization: 'json' },
    spdxId: 'SPDXRef-DOCUMENT',
    name: `${config.product.name}-${config.product.version}`,
    namespace: config.product.namespace,
    created,
    creators: [`Tool: sbomloom-${options?.toolVersion ?? '0'}`, ...(config.creators ?? [])],
    describes: [rootId],
    externalDocumentRefs,
    elements,
    relationships,
    diagnostics: [],
  };
  return { document, diagnostics };
}

/** Hash and parse one child: the ref carries its real namespace + SHA-1. */
async function childRef(
  artifact: ComposeArtifact,
  child: ComposeChild,
  usedDocRefs: Set<string>,
): Promise<{ ref: ExternalDocumentRef; diagnostics: Diagnostic[] }> {
  const copy = new Uint8Array(child.bytes);
  const sha1 = await sha1Hex(copy.buffer as ArrayBuffer);
  const text = new TextDecoder().decode(copy);
  const parsed = parseDocument({ fileName: child.fileName, text, sha1, byteSize: copy.byteLength });
  if (!parsed.document) {
    const reason = parsed.diagnostics[0]?.message ?? 'unrecognized format';
    throw new ComposeError(`child SBOM "${child.fileName}" for artifact "${artifact.name}" did not parse: ${reason}`);
  }
  if (!parsed.document.namespace) {
    throw new ComposeError(
      `child SBOM "${child.fileName}" has no documentNamespace: an ExternalDocumentRef needs one as its URI`,
    );
  }
  const docRef = uniqueId(usedDocRefs, `DocumentRef-${sanitize(artifact.name)}`);
  const diagnostics: Diagnostic[] = [];
  if (parsed.document.spec.model !== 'spdx-2') {
    diagnostics.push(
      diag(
        'warning',
        'COMPOSE_CHILD_NOT_SPDX2',
        `Child "${child.fileName}" is ${parsed.document.spec.version}; SPDX 2.3 tooling may not follow this reference.`,
      ),
    );
  }
  return {
    ref: {
      docRef,
      uri: parsed.document.namespace,
      checksum: { algorithm: 'SHA1', value: sha1 },
    },
    diagnostics,
  };
}

function packageElement(
  documentId: SbomDocument['id'],
  spdxId: string,
  fields: {
    name: string;
    version?: string;
    supplier?: string;
    license?: string;
    copyright?: string;
    downloadLocation?: string;
    comment?: string;
    purpose?: string;
    purl?: string;
    checksums?: { algorithm: string; value: string }[];
  },
): SbomElement {
  return {
    id: makeElementId(documentId, spdxId),
    documentId,
    spdxId,
    kind: 'package',
    name: fields.name,
    version: fields.version,
    purl: fields.purl,
    supplier: fields.supplier,
    downloadLocation: fields.downloadLocation,
    licenseDeclared: fields.license,
    copyright: fields.copyright,
    purpose: fields.purpose,
    comment: fields.comment,
    ...(fields.checksums && fields.checksums.length > 0 ? { checksums: fields.checksums } : {}),
    raw: { kind: 'json', value: { name: fields.name, SPDXID: spdxId } },
  };
}

function sanitize(candidate: string): string {
  return candidate.replace(/[^A-Za-z0-9.-]/g, '-');
}

function uniqueId(used: Set<string>, base: string): string {
  let id = base;
  let suffix = 2;
  while (used.has(id)) id = `${base}-${suffix++}`;
  used.add(id);
  return id;
}
