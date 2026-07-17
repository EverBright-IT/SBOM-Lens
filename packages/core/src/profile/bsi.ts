import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V3 } from './model';

/**
 * Field-level approximation of BSI TR-03183-2 v2.1.0, expressed as profile
 * data (schema v3: the `requires` precondition plus v2's SHA-512 algorithm
 * gate). The TR accepts only SPDX >= 3.0.1 or CycloneDX >= 1.6 as formats,
 * and that is not description prose here: `requires` turns it into a
 * leading GATED check, so an SPDX 2.x document visibly fails the format
 * baseline instead of rendering an all-green report that overstates
 * conformance. The field checks still measure whether the required data is
 * present on either SPDX line; what the engine cannot check rides in the
 * description.
 */
export const BSI_TR_03183_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V3,
  name: 'BSI TR-03183-2 field coverage (approximation)',
  description:
    'Approximates BSI TR-03183-2 v2.1.0. The TR accepts only SPDX 3.0.1+ or ' +
    'CycloneDX 1.6+ as formats; this profile enforces the SPDX side of that ' +
    'baseline as a gated check, so an SPDX 2.x document reports the format ' +
    'mismatch instead of looking conformant. The remaining checks measure ' +
    'whether the required data is present; the component creator is ' +
    'approximated via the SPDX supplier field. Not checkable by this engine ' +
    'and reviewed manually: component filenames, the executable/archive/' +
    'structured properties, source-code and deployable-form URIs, and the ' +
    'explicit completeness indication for dependencies.',
  requires: { spec: 'spdx-3' },
  checks: [
    {
      id: 'creators',
      type: 'document-field',
      field: 'creators',
      // The contact must sit on a human/organisational creator — a plain
      // "Tool: npm@10" must not satisfy this via its version's "@".
      pattern: '(Person|Organization):.*(@|https?://)',
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
      label: 'Component creator on every component (via supplier)',
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
      algorithms: ['SHA512'],
      label: 'SHA-512 hash on every component',
    },
    {
      id: 'pkg-unique-id',
      type: 'package-coverage',
      field: 'uniqueId',
      label: 'Unique identifiers (purl or CPE), where they exist',
    },
  ],
};
