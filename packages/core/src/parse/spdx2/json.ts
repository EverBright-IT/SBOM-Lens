import type {
  Checksum,
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
import {
  checkRelationshipDocRefs,
  dedupeBySpdxId,
  extractPurl,
  normalizeDescribes,
  normalizeRelType,
  parseElementRef,
  versionFromPurl,
} from './common';
import { validateSpdx2Structure } from './validate';

/**
 * SPDX 2.x JSON/YAML → document model (YAML parses to the same object shape).
 * Tolerant normalization: missing arrays are treated as empty, wrong-typed
 * fields are skipped with a diagnostic, and the original package/file objects
 * are kept as raw fields for the detail view.
 */
export function parseSpdx2Json(
  input: SourceInput,
  root: Record<string, unknown>,
  serialization: 'json' | 'yaml' = 'json',
): ParseResult {
  const diagnostics: Diagnostic[] = [];

  const namespace = asString(root.documentNamespace) ?? null;
  if (!namespace) {
    diagnostics.push(diag('warning', 'DOC_NO_NAMESPACE', 'Document has no documentNamespace; using a content-hash id instead.'));
  }
  const documentId = makeDocumentId(namespace, input.sha1);
  const docSpdxId = asString(root.SPDXID) ?? 'SPDXRef-DOCUMENT';

  const externalDocumentRefs: ExternalDocumentRef[] = [];
  for (const ref of asRecordArray(root.externalDocumentRefs)) {
    const docRef = asString(ref.externalDocumentId);
    const uri = asString(ref.spdxDocument);
    if (!docRef || !uri) {
      diagnostics.push(diag('warning', 'EXTREF_MALFORMED', 'externalDocumentRefs entry without externalDocumentId/spdxDocument skipped.'));
      continue;
    }
    externalDocumentRefs.push({ docRef, uri, checksum: readChecksum(ref.checksum) });
  }

  const elements: SbomElement[] = [];
  let anonCounter = 0;
  const makeSpdxId = (record: Record<string, unknown>, kind: string, name: string): string => {
    const spdxId = asString(record.SPDXID);
    if (spdxId) return spdxId;
    const assigned = `SPDXRef-sbomlens-anonymous-${++anonCounter}`;
    diagnostics.push(diag('warning', 'JSON_MISSING_SPDXID', `${kind} "${name}" has no SPDXID; assigned ${assigned}.`));
    return assigned;
  };

  for (const pkg of asRecordArray(root.packages)) {
    const name = asString(pkg.name) ?? '(unnamed package)';
    const spdxId = makeSpdxId(pkg, 'package', name);
    const externalRefs = readExternalRefs(pkg.externalRefs);
    const purl = extractPurl(externalRefs);
    elements.push({
      id: makeElementId(documentId, spdxId),
      documentId,
      spdxId,
      kind: 'package',
      name,
      version: asString(pkg.versionInfo) ?? (purl ? versionFromPurl(purl) : undefined),
      purl,
      supplier: asString(pkg.supplier),
      originator: asString(pkg.originator),
      downloadLocation: asString(pkg.downloadLocation),
      licenseConcluded: asString(pkg.licenseConcluded),
      licenseDeclared: asString(pkg.licenseDeclared),
      copyright: asString(pkg.copyrightText),
      purpose: asString(pkg.primaryPackagePurpose),
      description: asString(pkg.description) ?? asString(pkg.summary),
      comment: asString(pkg.comment),
      checksums: readChecksums(pkg.checksums),
      externalRefs,
      raw: { kind: 'json', value: pkg },
    });
  }

  for (const file of asRecordArray(root.files)) {
    const name = asString(file.fileName) ?? '(unnamed file)';
    const spdxId = makeSpdxId(file, 'file', name);
    elements.push({
      id: makeElementId(documentId, spdxId),
      documentId,
      spdxId,
      kind: 'file',
      name,
      licenseConcluded: asString(file.licenseConcluded),
      copyright: asString(file.copyrightText),
      comment: asString(file.comment),
      checksums: readChecksums(file.checksums),
      raw: { kind: 'json', value: file },
    });
  }

  const snippetCount = asRecordArray(root.snippets).length;
  if (snippetCount > 0) {
    diagnostics.push(diag('info', 'JSON_SNIPPETS_SKIPPED', `Skipped ${snippetCount} snippet(s): not displayed in this version.`));
  }

  const relationships: Relationship[] = [];
  let malformedRels = 0;
  for (const rel of asRecordArray(root.relationships)) {
    const from = asString(rel.spdxElementId);
    const type = asString(rel.relationshipType);
    const to = asString(rel.relatedSpdxElement);
    if (!from || !type || !to) {
      malformedRels++;
      continue;
    }
    relationships.push({
      from: parseElementRef(from),
      type: normalizeRelType(type),
      to: parseElementRef(to),
      comment: asString(rel.comment),
    });
  }
  if (malformedRels > 0) {
    diagnostics.push(diag('warning', 'REL_MALFORMED', `${malformedRels} relationship(s) without spdxElementId/relationshipType/relatedSpdxElement skipped.`));
  }

  const creationInfo = isRecord(root.creationInfo) ? root.creationInfo : {};
  const deduped = dedupeBySpdxId(elements, diagnostics);
  const { relationships: allRelationships, describes } = normalizeDescribes(
    docSpdxId,
    asStringArray(root.documentDescribes),
    relationships,
  );
  checkRelationshipDocRefs(allRelationships, externalDocumentRefs, diagnostics);

  // Spec lint last: parser notes explain what could not be read, spec findings
  // what the document itself gets wrong. The document loads either way.
  diagnostics.push(...validateSpdx2Structure(root));

  const document = {
    id: documentId,
    spec: {
      model: 'spdx-2' as const,
      version: asString(root.spdxVersion) ?? 'SPDX-2.x',
      serialization,
    },
    spdxId: docSpdxId,
    name: asString(root.name) ?? input.fileName,
    namespace,
    created: asString(creationInfo.created),
    creators: asStringArray(creationInfo.creators),
    comment: asString(root.comment) ?? asString(creationInfo.comment),
    dataLicense: asString(root.dataLicense),
    describes,
    externalDocumentRefs,
    elements: deduped,
    relationships: allRelationships,
    diagnostics,
  };
  return { document, diagnostics };
}

function readChecksum(value: unknown): Checksum | undefined {
  if (!isRecord(value)) return undefined;
  const algorithm = asString(value.algorithm);
  const checksumValue = asString(value.checksumValue);
  if (!algorithm || !checksumValue) return undefined;
  return { algorithm: algorithm.toUpperCase(), value: checksumValue.toLowerCase() };
}

function readChecksums(value: unknown): Checksum[] | undefined {
  const checksums = asRecordArray(value)
    .map(readChecksum)
    .filter((c): c is Checksum => c !== undefined);
  return checksums.length > 0 ? checksums : undefined;
}

function readExternalRefs(value: unknown): ExternalRef[] | undefined {
  const refs: ExternalRef[] = [];
  for (const ref of asRecordArray(value)) {
    const type = asString(ref.referenceType);
    const locator = asString(ref.referenceLocator);
    if (!type || !locator) continue;
    refs.push({ category: asString(ref.referenceCategory), type, locator });
  }
  return refs.length > 0 ? refs : undefined;
}
