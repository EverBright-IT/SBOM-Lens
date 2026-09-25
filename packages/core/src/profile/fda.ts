import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V4 } from './model';

/**
 * FDA "Cybersecurity in Medical Devices: Quality Management System
 * Considerations and Content of Premarket Submissions" (final guidance,
 * February 2026) for cyber devices under section 524B of the FD&C Act.
 * The guidance asks for a machine-readable SBOM built on the NTIA/Framing
 * baseline plus, per component, the level of support, the end-of-support
 * date, and known vulnerabilities; the SBOM or an addendum may carry them.
 *
 * Mapping decisions:
 *   - The baseline checks repeat the NTIA preset's ids and semantics (not
 *     imported: that preset is pinned to analysis/quality.ts by a parity
 *     test and must stay byte-stable).
 *   - Level of support and end of support are coverage METERS. The guidance
 *     is nonbinding; the legal lever is section 524B's refuse-to-accept at
 *     submission, which the FDA applies, not this viewer.
 *   - Three field conventions are read, and only these: SPDX 2.3
 *     ValidUntilDate ("end of the support period ... from the supplier",
 *     7.27); SPDX 3.0.1 supportLevel and validUntilTime (the latter means
 *     "reassess after", not end of support - close, not identical);
 *     CycloneDX properties named support-level (or support_level) for the
 *     level and end-of-support, end-of-life, eos, eol or valid-until (hyphen
 *     or underscore) for the date, each optionally prefixed fda:lifecycle:
 *     (either prefix alone counts too), because CycloneDX has no normative field yet (the
 *     patterns live in evaluate.ts). A generator using other names is
 *     reported as missing, not guessed.
 *   - Known vulnerabilities are not a profile check: that is the VEX/CSAF
 *     overlay's job, and it never scores.
 */
export const FDA_524B_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V4,
  name: 'FDA 524B cybersecurity (02/2026)',
  specUrl:
    'https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-management-system-considerations-and-content-premarket',
  description:
    'Measures the SBOM content the FDA guidance "Cybersecurity in Medical ' +
    'Devices" (final, February 2026) asks for under section 524B of the FD&C ' +
    'Act: the NTIA baseline plus, per component, the level of support and the ' +
    'end-of-support date. The guidance is nonbinding and the decision on a ' +
    'submission is the FDA\'s, so package fields here are coverage meters and ' +
    'a complete report is not a statement of acceptability. The guidance ' +
    'allows these fields in the SBOM or in an addendum; an addendum is not ' +
    'read. Field conventions read, and only these: SPDX 2.3 ValidUntilDate ' +
    '(end of the support period from the supplier), SPDX 3.0.1 supportLevel ' +
    'and validUntilTime (the latter means "reassess after", which is close to ' +
    'but not the same as end of support), and CycloneDX properties named ' +
    'support-level (or support_level) for the level and end-of-support, ' +
    'end-of-life, eos, eol or valid-until (hyphen or underscore) for the ' +
    'date, each optionally prefixed fda:lifecycle: (either prefix alone ' +
    'counts too), since CycloneDX ' +
    'has no normative field for either. Known vulnerabilities ' +
    'per component are shown by the VEX/CSAF overlay, not scored here. Note ' +
    'for quality systems: ISO 13485 clause 4.1.6 expects software used in the ' +
    'QMS to be validated; this viewer measures, it does not decide.',
  checks: [
    // --- NTIA/Framing baseline (same ids and semantics as the NTIA preset) ---
    { id: 'creators', type: 'document-field', field: 'creators', label: 'SBOM author (creators)' },
    { id: 'created', type: 'document-field', field: 'created', label: 'Timestamp (created)' },
    { id: 'relationships', type: 'relationships', label: 'Dependency relationships' },
    { id: 'pkg-version', type: 'package-coverage', field: 'version', label: 'Version' },
    { id: 'pkg-supplier', type: 'package-coverage', field: 'supplier', label: 'Supplier' },
    { id: 'pkg-unique-id', type: 'package-coverage', field: 'uniqueId', label: 'Unique IDs (purl/refs)' },
    // --- 524B additions ------------------------------------------------------
    {
      id: 'pkg-support-level',
      type: 'package-coverage',
      field: 'supportLevel',
      label: 'Level of support (SPDX 3 supportLevel or CycloneDX support-level property)',
    },
    {
      id: 'pkg-end-of-support',
      type: 'package-coverage',
      field: 'validUntil',
      label: 'End-of-support date (SPDX 2.3 ValidUntilDate, SPDX 3 validUntilTime, CycloneDX end-of-support property)',
    },
  ],
};
