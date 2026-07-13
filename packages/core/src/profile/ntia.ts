import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V1 } from './model';

/**
 * The built-in NTIA-minimum-elements report, expressed as profile data.
 * Ids, labels, and ORDER match the pre-profile QualitySection exactly; the
 * coverage checks carry no threshold, so the default UI renders the same
 * informational meters as before. analysis/quality.ts stays alive as an
 * independent implementation — the parity test pins the two together.
 */
export const NTIA_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V1,
  name: 'NTIA minimum elements',
  checks: [
    { id: 'creators', type: 'document-field', field: 'creators', label: 'SBOM author (creators)' },
    { id: 'created', type: 'document-field', field: 'created', label: 'Timestamp (created)' },
    { id: 'namespace', type: 'document-field', field: 'namespace', label: 'Document namespace' },
    { id: 'relationships', type: 'relationships', label: 'Dependency relationships' },
    { id: 'pkg-version', type: 'package-coverage', field: 'version', label: 'Version' },
    { id: 'pkg-supplier', type: 'package-coverage', field: 'supplier', label: 'Supplier' },
    { id: 'pkg-unique-id', type: 'package-coverage', field: 'uniqueId', label: 'Unique IDs (purl/refs)' },
    { id: 'pkg-checksum', type: 'package-coverage', field: 'checksum', label: 'Checksums' },
    { id: 'pkg-license', type: 'package-coverage', field: 'license', label: 'License' },
  ],
};
