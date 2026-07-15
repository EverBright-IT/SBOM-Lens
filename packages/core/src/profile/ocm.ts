import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V1 } from './model';

/**
 * The built-in quality framing for OCM component descriptors — what a
 * well-formed component version should carry, expressed in the shared
 * profile engine. Version coverage is gated (an artifact without a version
 * has no identity); digests and access locations are informational meters
 * (unsigned or reference-only descriptors legitimately lack them).
 */
export const OCM_ESSENTIALS_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V1,
  name: 'OCM component essentials',
  checks: [
    { id: 'name', type: 'document-field', field: 'name', label: 'Component name' },
    { id: 'provider', type: 'document-field', field: 'creators', label: 'Provider' },
    { id: 'created', type: 'document-field', field: 'created', label: 'Creation time' },
    { id: 'relationships', type: 'relationships', label: 'Artifact relationships' },
    { id: 'res-version', type: 'package-coverage', field: 'version', threshold: 100, label: 'Version' },
    { id: 'res-digest', type: 'package-coverage', field: 'checksum', label: 'Digests' },
    { id: 'res-access', type: 'package-coverage', field: 'downloadLocation', label: 'Access location' },
    { id: 'res-unique', type: 'package-coverage', field: 'uniqueId', label: 'Unique IDs (purl)' },
  ],
};
