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
  name: 'NTIA minimum elements (2021)',
  specUrl: 'https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom',
  description:
    'The 2021 NTIA minimum elements, kept as the default report because ' +
    'contracts and procurement documents still name them. CISA, NSA, FBI ' +
    'and international partners published the 2026 Minimum Elements on ' +
    '29 July 2026, which updates and replaces this document: it renames ' +
    'supplier to component producer, and adds component hash, component ' +
    'license and SBOM tool elements. Select the CISA 2026 preset to ' +
    'measure against the current version.',
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
