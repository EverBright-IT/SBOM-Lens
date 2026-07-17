import type { SpecFieldDoc } from './spdx23-field-docs';

/**
 * Hand-curated field documentation for SPDX 3.0.1 documents, paraphrased
 * from the SPDX 3.0.1 model specification (https://spdx.github.io/spdx-spec/
 * v3.0.1/, CC-BY-3.0 by the SPDX project / The Linux Foundation — see
 * NOTICE). The keys mirror the SPDX-2.3 doc lookups the detail views use,
 * but every text speaks the 3.0.1 vocabulary and links into the 3.0.1
 * model pages: a 2.3 chapter link on a 3.x document would be confidently
 * wrong. Where our viewer folds 3.x structure into a 2.x-shaped field
 * (license relationships, creators), the text says so.
 */

const MODEL = 'https://spdx.github.io/spdx-spec/v3.0.1/model';

export interface Spdx3FieldDoc extends SpecFieldDoc {
  /** Rendered in the ⓘ tooltip: "Open this field in the SPDX 3.0.1 specification". */
  specName: 'SPDX 3.0.1';
}

const doc = (description: string, specUrl: string): Spdx3FieldDoc => ({
  description,
  specUrl,
  specName: 'SPDX 3.0.1',
});

export const SPDX3_DOCS: {
  document: Record<string, Spdx3FieldDoc>;
  package: Record<string, Spdx3FieldDoc>;
  file: Record<string, Spdx3FieldDoc>;
  relationshipType: Spdx3FieldDoc;
} = {
  document: {
    documentNamespace: doc(
      'The IRI (@id) of the SpdxDocument element. In SPDX 3.x every element has a globally unique IRI; the document IRI is the prefix under which its elements live, and imports from other documents reference those IRIs.',
      `${MODEL}/Core/Classes/SpdxDocument/`,
    ),
    spdxVersion: doc(
      'The specVersion from the document creation information: the semantic version of the SPDX specification this document conforms to.',
      `${MODEL}/Core/Classes/CreationInfo/`,
    ),
    created: doc(
      'creationInfo.created: the date and time this document (and any element sharing the creation info) was created, as an ISO 8601 timestamp.',
      `${MODEL}/Core/Properties/created/`,
    ),
    creators: doc(
      'Resolved from creationInfo.createdBy (Agents: persons, organizations) and createdUsing (Tools). The viewer renders each agent or tool by its name.',
      `${MODEL}/Core/Properties/createdBy/`,
    ),
    dataLicense: doc(
      'The license under which the SPDX metadata itself is provided (SpdxDocument.dataLicense), typically CC0-1.0.',
      `${MODEL}/Core/Classes/SpdxDocument/`,
    ),
    comment: doc(
      'Free-form commentary the document author attached to the SpdxDocument element.',
      `${MODEL}/Core/Properties/comment/`,
    ),
    externalDocumentRefs: doc(
      'Entries of the document\'s import list (ExternalMap): elements defined in other SPDX documents, referenced by their IRI, optionally with a locationHint to fetch the defining document and verifiedUsing hashes to prove it.',
      `${MODEL}/Core/Classes/ExternalMap/`,
    ),
  },
  package: {
    versionInfo: doc(
      'software_packageVersion: the version of this Package element, in whatever versioning scheme the package uses.',
      `${MODEL}/Software/Properties/packageVersion/`,
    ),
    primaryPackagePurpose: doc(
      'software_primaryPurpose: what this software artifact primarily is, from the SoftwarePurpose vocabulary (application, library, container, operatingSystem, ...).',
      `${MODEL}/Software/Vocabularies/SoftwarePurpose/`,
    ),
    supplier: doc(
      'suppliedBy: the Agent (person or organization) who supplied this artifact — who you got it from, which may differ from who originally made it.',
      `${MODEL}/Core/Properties/suppliedBy/`,
    ),
    originator: doc(
      'originatedBy: the Agent the artifact originally came from — its author or producing organization.',
      `${MODEL}/Core/Properties/originatedBy/`,
    ),
    downloadLocation: doc(
      'software_downloadLocation: the download URL for this exact package artifact.',
      `${MODEL}/Software/Properties/downloadLocation/`,
    ),
    licenseConcluded: doc(
      'In SPDX 3.x the concluded license is a hasConcludedLicense relationship from the element to a license expression; the viewer folds it into this field for display.',
      `${MODEL}/Core/Vocabularies/RelationshipType/`,
    ),
    licenseDeclared: doc(
      'In SPDX 3.x the declared license is a hasDeclaredLicense relationship from the element to a license expression; the viewer folds it into this field for display.',
      `${MODEL}/Core/Vocabularies/RelationshipType/`,
    ),
    copyrightText: doc(
      'software_copyrightText: the copyright holders and dates declared in or for the artifact.',
      `${MODEL}/Software/Properties/copyrightText/`,
    ),
    description: doc(
      'A detailed description of the element, from the document author.',
      `${MODEL}/Core/Properties/description/`,
    ),
    comment: doc(
      'Free-form commentary the document author attached to this element.',
      `${MODEL}/Core/Properties/comment/`,
    ),
    SPDXID: doc(
      'The element\'s spdxId: a globally unique IRI (not a DocumentRef-scoped id as in SPDX 2.x). Other documents can reference the element by this IRI via imports.',
      `${MODEL}/Core/Classes/Element/`,
    ),
    externalRefs: doc(
      'externalIdentifier entries (purl, CPE, gitoid, ...) that identify this element in other systems; general externalRef links ride along.',
      `${MODEL}/Core/Classes/ExternalIdentifier/`,
    ),
    checksums: doc(
      'verifiedUsing: integrity methods (Hash entries with algorithm and value) that let a consumer verify the artifact bytes.',
      `${MODEL}/Core/Classes/Hash/`,
    ),
  },
  file: {
    licenseConcluded: doc(
      'In SPDX 3.x the concluded license is a hasConcludedLicense relationship from the element to a license expression; the viewer folds it into this field for display.',
      `${MODEL}/Core/Vocabularies/RelationshipType/`,
    ),
    copyrightText: doc(
      'software_copyrightText: the copyright holders and dates declared in or for the file.',
      `${MODEL}/Software/Properties/copyrightText/`,
    ),
    comment: doc(
      'Free-form commentary the document author attached to this File element.',
      `${MODEL}/Core/Properties/comment/`,
    ),
    checksums: doc(
      'verifiedUsing: integrity methods (Hash entries with algorithm and value) that let a consumer verify the file bytes.',
      `${MODEL}/Core/Classes/Hash/`,
    ),
  },
  relationshipType: doc(
    'The RelationshipType vocabulary entry describing how the from-element relates to the to-elements (contains, dependsOn, describes, ...). The viewer shows the SCREAMING_SNAKE form familiar from SPDX 2.x.',
    `${MODEL}/Core/Vocabularies/RelationshipType/`,
  ),
};
