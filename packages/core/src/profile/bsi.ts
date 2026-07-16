import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V1 } from './model';

/**
 * Field-level approximation of BSI TR-03183-2 v2.1.0, expressed as profile
 * data. Deliberately honest about its limits: the TR accepts only SPDX
 * >= 3.0.1 or CycloneDX >= 1.6, so an SPDX 2.x document can never be
 * TR-conformant; this profile measures whether the REQUIRED DATA is present
 * in the fields SPDX 2.x has. Requirements the engine cannot check ride in
 * the description so the report never overstates itself.
 */
export const BSI_TR_03183_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V1,
  name: 'BSI TR-03183-2 field coverage (approximation)',
  description:
    'Approximates BSI TR-03183-2 v2.1.0 on SPDX 2.x fields. Note: the TR itself ' +
    'accepts only SPDX 3.0.1+ or CycloneDX 1.6+, so passing these checks does not ' +
    'make an SPDX 2.x document TR-conformant; they measure whether the required ' +
    'data is present. Not checkable by this engine and reviewed manually: the SBOM ' +
    'format baseline, component filenames, the executable/archive/structured ' +
    'properties, SHA-512 as the hash algorithm, source-code and deployable-form ' +
    'URIs, and the explicit completeness indication for dependencies.',
  checks: [
    {
      id: 'creators',
      type: 'document-field',
      field: 'creators',
      pattern: '(@|https?://)',
      label: 'SBOM creator with contact (email or URL)',
    },
    { id: 'created', type: 'document-field', field: 'created', label: 'Timestamp' },
    { id: 'relationships', type: 'relationships', label: 'Dependencies enumerated' },
    { id: 'pkg-version', type: 'package-coverage', field: 'version', threshold: 100, label: 'Version on every component' },
    {
      id: 'pkg-supplier',
      type: 'package-coverage',
      field: 'supplier',
      threshold: 100,
      label: 'Component creator on every component',
    },
    {
      id: 'pkg-license',
      type: 'package-coverage',
      field: 'license',
      threshold: 100,
      label: 'Distribution licence on every component',
    },
    {
      id: 'pkg-checksum',
      type: 'package-coverage',
      field: 'checksum',
      threshold: 100,
      label: 'Hash on every component (the TR requires SHA-512)',
    },
    {
      id: 'pkg-unique-id',
      type: 'package-coverage',
      field: 'uniqueId',
      label: 'Unique identifiers (purl or CPE), where they exist',
    },
  ],
};
