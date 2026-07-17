import type { Checksum, ElementRef, SbomDocument, SbomElement } from '../model/document';

/**
 * SPDX 2.3 JSON emission — the repo's first writer. It serializes the TYPED
 * model, deliberately: the composer builds fresh documents, so there is no
 * hidden source to stay faithful to, and a fixed field order keeps the
 * output byte-deterministic (diffable, goldenable). This is NOT a lossless
 * re-emitter for arbitrary parsed inputs; fields the model does not carry
 * (annotations, snippets, extracted licensing infos) do not round-trip.
 *
 * The writer emits what the document holds and leaves validity to its
 * callers: the composer guarantees the SPDX mandatory fields, and the
 * emit tests prove the output re-parses through our own spdx2 parser.
 */

export class EmitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EmitError';
  }
}

/** Marks the second seam consumer (SPDX 3.0.1 JSON-LD) as designed-for. */
export interface SbomWriter {
  readonly format: 'spdx-2.3-json';
  emit(document: SbomDocument): string;
}

export const spdx23JsonWriter: SbomWriter = {
  format: 'spdx-2.3-json',
  emit: emitSpdx23Json,
};

export function emitSpdx23Json(document: SbomDocument): string {
  if (!document.namespace) {
    throw new EmitError('SPDX 2.3 requires a documentNamespace; refusing to emit without one.');
  }
  if (!document.created || document.creators.length === 0) {
    throw new EmitError('SPDX 2.3 requires creationInfo (created + at least one creator).');
  }

  const packages = document.elements.filter((e) => e.kind === 'package').map(emitPackage);
  const files = document.elements.filter((e) => e.kind === 'file').map(emitFile);

  const out: Record<string, unknown> = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: document.dataLicense ?? 'CC0-1.0',
    SPDXID: document.spdxId || 'SPDXRef-DOCUMENT',
    name: document.name,
    documentNamespace: document.namespace,
    creationInfo: {
      created: document.created,
      creators: document.creators,
    },
    ...(document.comment ? { comment: document.comment } : {}),
    ...(document.externalDocumentRefs.length > 0
      ? {
          externalDocumentRefs: document.externalDocumentRefs.map((ref) => ({
            externalDocumentId: ref.docRef,
            spdxDocument: ref.uri,
            ...(ref.checksum ? { checksum: emitChecksum(ref.checksum) } : {}),
          })),
        }
      : {}),
    ...(document.describes.length > 0 ? { documentDescribes: document.describes } : {}),
    ...(packages.length > 0 ? { packages } : {}),
    ...(files.length > 0 ? { files } : {}),
    ...(document.relationships.length > 0
      ? {
          relationships: document.relationships.map((rel) => ({
            spdxElementId: refToString(rel.from),
            relationshipType: rel.type,
            relatedSpdxElement: refToString(rel.to),
            ...(rel.comment ? { comment: rel.comment } : {}),
          })),
        }
      : {}),
  };
  return JSON.stringify(out, null, 2) + '\n';
}

function emitPackage(element: SbomElement): Record<string, unknown> {
  const externalRefs = [
    ...(element.purl
      ? [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: element.purl }]
      : []),
    ...(element.externalRefs ?? [])
      .filter((ref) => !(ref.type === 'purl' && ref.locator === element.purl))
      .map((ref) => ({
        referenceCategory: ref.category ?? 'OTHER',
        referenceType: ref.type,
        referenceLocator: ref.locator,
      })),
  ];
  return {
    name: element.name,
    SPDXID: element.spdxId,
    ...(element.version ? { versionInfo: element.version } : {}),
    ...(element.supplier ? { supplier: element.supplier } : {}),
    ...(element.originator ? { originator: element.originator } : {}),
    // Mandatory in 2.3; the composer never analyzes files, and a viewer
    // model has no way to claim otherwise honestly.
    downloadLocation: element.downloadLocation ?? 'NOASSERTION',
    filesAnalyzed: false,
    ...(element.licenseConcluded ? { licenseConcluded: element.licenseConcluded } : {}),
    ...(element.licenseDeclared ? { licenseDeclared: element.licenseDeclared } : {}),
    ...(element.copyright ? { copyrightText: element.copyright } : {}),
    ...(element.description ? { description: element.description } : {}),
    ...(element.comment ? { comment: element.comment } : {}),
    ...(element.purpose ? { primaryPackagePurpose: element.purpose } : {}),
    ...(element.checksums && element.checksums.length > 0
      ? { checksums: element.checksums.map(emitChecksum) }
      : {}),
    ...(externalRefs.length > 0 ? { externalRefs } : {}),
  };
}

function emitFile(element: SbomElement): Record<string, unknown> {
  return {
    fileName: element.name,
    SPDXID: element.spdxId,
    ...(element.checksums && element.checksums.length > 0
      ? { checksums: element.checksums.map(emitChecksum) }
      : {}),
    ...(element.licenseConcluded ? { licenseConcluded: element.licenseConcluded } : {}),
    ...(element.copyright ? { copyrightText: element.copyright } : {}),
    ...(element.comment ? { comment: element.comment } : {}),
  };
}

function emitChecksum(checksum: Checksum): { algorithm: string; checksumValue: string } {
  return { algorithm: checksum.algorithm, checksumValue: checksum.value };
}

function refToString(ref: ElementRef): string {
  if (ref.kind === 'special') return ref.value;
  if (ref.kind === 'external') return ref.spdxId ? `${ref.docRef}:${ref.spdxId}` : ref.docRef;
  return ref.spdxId;
}
