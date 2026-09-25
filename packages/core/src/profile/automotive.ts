import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V4 } from './model';

/**
 * OpenChain Automotive SBOM Specification v1.1 (OpenChain Automotive Work
 * Group, CC0-1.0). The specification lists the SBOM fields an automotive
 * supply chain exchanges, thirteen of them mandatory, and maps each onto
 * SPDX and CycloneDX. Its pull is contractual: OEMs pass UNECE R155/R156
 * obligations down the tier chain in their purchase terms, not in law.
 *
 * Mapping decisions:
 *   - Every mandatory field that is a package field is a coverage METER
 *     without a threshold. A contractual requirement between two parties is
 *     not something this viewer can call "met"; it can show how much of the
 *     document carries the data.
 *   - "SBOM Type" and "External Document References" are boolean facts about
 *     the document and marked informational: SPDX 2.x has no dedicated
 *     SBOM type field (SPDX 3 sbomType and the CycloneDX lifecycle phase
 *     are read), and a supplier-level SBOM legitimately references
 *     nothing. Neither should read as a failure.
 *   - "Component Name" is satisfied by construction in any parsed document
 *     and is not checked; a check that always passes would pad the report.
 *   - The n-tier case the specification is written for (a vehicle SBOM
 *     referencing supplier SBOMs) is what the cascade view resolves; the
 *     External Document References fact is its entry point.
 */
export const AUTOMOTIVE_SBOM_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V4,
  name: 'OpenChain Automotive SBOM v1.1',
  specUrl: 'https://github.com/OpenChain-Project/Automotive-SBOM',
  description:
    'Measures the mandatory fields of the OpenChain Automotive SBOM ' +
    'Specification v1.1 (CC0-1.0), which maps each field onto SPDX and ' +
    'CycloneDX. The requirement is contractual, passed down the tier chain by ' +
    'OEMs under UNECE R155/R156, so nothing here gates: package fields are ' +
    'coverage meters, document facts report pass or fail, and a complete ' +
    'report is not a statement of contractual compliance. SBOM type is read ' +
    'from SPDX 3 sbomType and the CycloneDX lifecycle phase (SPDX 2.x has no ' +
    'dedicated field) and external document references are absent by design in a ' +
    'leaf SBOM; both are informational. Component name is satisfied by ' +
    'construction and not checked. The concluded licence is the SPDX ' +
    'licenseConcluded field or a CycloneDX licence acknowledged as concluded; ' +
    'the file name is SPDX packageFileName, which CycloneDX has no dedicated field for. ' +
    'Hashes are optional in the specification and shown as a meter.',
  checks: [
    // --- SBOM level ----------------------------------------------------------
    {
      id: 'sbom-author',
      type: 'document-field',
      field: 'creators',
      pattern: '^(Person|Organization):',
      label: 'SBOM author (person or organization)',
    },
    { id: 'sbom-timestamp', type: 'document-field', field: 'created', label: 'SBOM timestamp' },
    {
      id: 'sbom-type',
      type: 'document-field',
      field: 'sbomType',
      informational: true,
      label: 'SBOM type (SPDX 3 sbomType or CycloneDX lifecycle; no dedicated SPDX 2.x field)',
    },
    { id: 'primary-component', type: 'document-field', field: 'describes', label: 'Primary component declared' },
    {
      id: 'external-document-refs',
      type: 'document-field',
      field: 'externalDocumentRefs',
      informational: true,
      label: 'External document references (supplier SBOMs linked)',
    },
    { id: 'relationships', type: 'relationships', label: 'Component relationships' },
    // --- component level -----------------------------------------------------
    { id: 'component-version', type: 'package-coverage', field: 'version', label: 'Version' },
    { id: 'component-supplier', type: 'package-coverage', field: 'supplier', label: 'Supplier' },
    { id: 'component-unique-id', type: 'package-coverage', field: 'uniqueId', label: 'Unique ID (purl, CPE or other reference)' },
    { id: 'component-file-name', type: 'package-coverage', field: 'fileName', label: 'File name (SPDX packageFileName; no dedicated CycloneDX field)' },
    { id: 'component-concluded-license', type: 'package-coverage', field: 'licenseConcluded', label: 'Concluded license' },
    { id: 'component-copyright', type: 'package-coverage', field: 'copyright', label: 'Copyright' },
    { id: 'component-hash', type: 'package-coverage', field: 'checksum', label: 'Hash (optional in the specification)' },
  ],
};
