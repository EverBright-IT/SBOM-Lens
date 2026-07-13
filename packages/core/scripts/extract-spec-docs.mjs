/**
 * Regenerates packages/core/src/spec/spdx23-field-docs.ts from the official SPDX 2.3
 * JSON schema. Build-time only — the viewer ships a few KB of distilled field
 * documentation (descriptions, enums) instead of parsing schemas at runtime.
 *
 *   npm run generate:spec-docs
 *
 * Source: https://github.com/spdx/spdx-spec (v2.3 tag), CC-BY-3.0.
 */
import { mkdirSync, writeFileSync } from 'node:fs';

const SCHEMA_URL = 'https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json';

const response = await fetch(SCHEMA_URL);
if (!response.ok) throw new Error(`${SCHEMA_URL}: ${response.status}`);
const schema = await response.json();

/**
 * Hand-curated links into the RENDERED spec (anchors verified against
 * https://spdx.github.io/spdx-spec/v2.3/ — the JSON schema carries no
 * chapter/anchor information).
 */
const SPEC_BASE = 'https://spdx.github.io/spdx-spec/v2.3';
const ANCHORS = {
  document: {
    spdxVersion: 'document-creation-information/#61-spdx-version-field',
    dataLicense: 'document-creation-information/#62-data-license-field',
    SPDXID: 'document-creation-information/#63-spdx-identifier-field',
    name: 'document-creation-information/#64-document-name-field',
    documentNamespace: 'document-creation-information/#65-spdx-document-namespace-field',
    externalDocumentRefs: 'document-creation-information/#66-external-document-references-field',
    creators: 'document-creation-information/#68-creator-field',
    created: 'document-creation-information/#69-created-field',
    comment: 'document-creation-information/#611-document-comment-field',
    documentDescribes: 'document-creation-information/',
  },
  package: {
    name: 'package-information/#71-package-name-field',
    SPDXID: 'package-information/#72-package-spdx-identifier-field',
    versionInfo: 'package-information/#73-package-version-field',
    supplier: 'package-information/#75-package-supplier-field',
    originator: 'package-information/#76-package-originator-field',
    downloadLocation: 'package-information/#77-package-download-location-field',
    checksums: 'package-information/#710-package-checksum-field',
    licenseConcluded: 'package-information/#713-concluded-license-field',
    licenseDeclared: 'package-information/#715-declared-license-field',
    copyrightText: 'package-information/#717-copyright-text-field',
    description: 'package-information/#719-package-detailed-description-field',
    comment: 'package-information/#720-package-comment-field',
    externalRefs: 'package-information/#721-external-reference-field',
    primaryPackagePurpose: 'package-information/#724-primary-package-purpose-field',
  },
  file: {
    fileName: 'file-information/#81-file-name-field',
    checksums: 'file-information/#84-file-checksum-field',
    licenseConcluded: 'file-information/#85-concluded-license-field',
    copyrightText: 'file-information/#88-copyright-text-field',
    comment: 'file-information/#812-file-comment-field',
  },
  relationshipType: 'relationships-between-SPDX-elements/#111-relationship-field',
};

/** property node → {description, enum?, specUrl?} or undefined. */
function doc(prop, anchor) {
  if (!prop) return undefined;
  const description = (prop.description ?? '').replace(/\s+/g, ' ').trim();
  const enumValues = prop.enum ?? prop.items?.enum;
  if (!description && !enumValues) return undefined;
  const result = { description };
  if (enumValues) result.enum = enumValues;
  if (anchor) result.specUrl = `${SPEC_BASE}/${anchor}`;
  return result;
}

function pickAll(properties, keys, anchors = {}) {
  const out = {};
  for (const key of keys) {
    const d = doc(properties?.[key], anchors[key]);
    if (d) out[key] = d;
  }
  return out;
}

const root = schema.properties ?? {};
const creationInfo = root.creationInfo?.properties ?? {};
const packageProps = root.packages?.items?.properties ?? {};
const fileProps = root.files?.items?.properties ?? {};
const relationshipProps = root.relationships?.items?.properties ?? {};

const docs = {
  document: {
    ...pickAll(
      root,
      [
        'spdxVersion',
        'dataLicense',
        'SPDXID',
        'name',
        'documentNamespace',
        'comment',
        'documentDescribes',
        'externalDocumentRefs',
      ],
      ANCHORS.document,
    ),
    ...(doc(creationInfo.created, ANCHORS.document.created)
      ? { created: doc(creationInfo.created, ANCHORS.document.created) }
      : {}),
    ...(doc(creationInfo.creators, ANCHORS.document.creators)
      ? { creators: doc(creationInfo.creators, ANCHORS.document.creators) }
      : {}),
  },
  package: pickAll(
    packageProps,
    [
      'name',
      'SPDXID',
      'versionInfo',
      'supplier',
      'originator',
      'downloadLocation',
      'licenseConcluded',
      'licenseDeclared',
      'copyrightText',
      'primaryPackagePurpose',
      'description',
      'comment',
      'checksums',
      'externalRefs',
    ],
    ANCHORS.package,
  ),
  file: pickAll(
    fileProps,
    ['fileName', 'checksums', 'licenseConcluded', 'copyrightText', 'comment'],
    ANCHORS.file,
  ),
  relationshipType: doc(relationshipProps.relationshipType, ANCHORS.relationshipType),
};

const banner = `/**
 * GENERATED by scripts/extract-spec-docs.mjs — do not edit by hand.
 *
 * Field documentation distilled from the official SPDX 2.3 JSON schema
 * (https://github.com/spdx/spdx-spec, v2.3), licensed CC-BY-3.0 by the
 * SPDX project / The Linux Foundation.
 */
export interface SpecFieldDoc {
  description: string;
  enum?: readonly string[];
  /** Deep link into the rendered spec at spdx.github.io. */
  specUrl?: string;
}

export const SPDX23_DOCS: {
  document: Record<string, SpecFieldDoc>;
  package: Record<string, SpecFieldDoc>;
  file: Record<string, SpecFieldDoc>;
  relationshipType?: SpecFieldDoc;
} = `;

const target = new URL('../src/spec/spdx23-field-docs.ts', import.meta.url);
mkdirSync(new URL('.', target), { recursive: true });
writeFileSync(target, `${banner}${JSON.stringify(docs, null, 2)};\n`);

const count = Object.keys(docs.document).length + Object.keys(docs.package).length + Object.keys(docs.file).length;
console.log(`wrote ${target.pathname} (${count} field docs, relationship enum: ${docs.relationshipType?.enum?.length ?? 0} types)`);
