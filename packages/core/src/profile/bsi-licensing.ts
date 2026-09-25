import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V4 } from './model';

/**
 * BSI TR-03183-2 v2.1.0, section 6.1: the licence fields a conformant SBOM
 * MUST carry per component. The TR requires licences to be stated as SPDX
 * identifiers or SPDX expressions (a licence text does not replace the id),
 * with the ScanCode LicenseDB as the fallback for licences the SPDX list
 * does not carry (LicenseRef-scancode-...). It names the distribution
 * licence as mandatory and the effective licence as optional, and it argues
 * the requirement from security, not only from compliance: a licence can
 * forbid changing code to fix a vulnerability (8.1.13).
 *
 * Mapping decisions:
 *   - "Distribution licence" is the declared licence field (SPDX
 *     licenseDeclared, CycloneDX licences not acknowledged as concluded);
 *     "effective licence" is the concluded field. Gated at 100 % for the
 *     mandatory one, a meter for the optional one - the same split the BSI
 *     field-coverage preset uses.
 *   - Identifier validity is checked against the SPDX License List ids
 *     (generated list, ids and deprecation flags only). LicenseRef-* counts,
 *     because the TR's ScanCode fallback is exactly that form. Deprecated
 *     ids still count: they are identifiers on the list; the Licenses view
 *     marks them so a reader can decide.
 *   - Whether a value is a licence TEXT instead of an id is the grammar
 *     lint's job (SPDX*_SCHEMA_BAD_LICENSE_EXPRESSION), not repeated here.
 *   - Format baseline as in the BSI preset: the TR accepts SPDX 3.0.1+ and
 *     CycloneDX 1.6+; an older format fails the baseline visibly.
 *   - No obligations, no compatibility, no rating. Which licence is
 *     acceptable is a decision this viewer does not make.
 */
export const BSI_LICENSING_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V4,
  name: 'BSI TR-03183-2 licence fields (6.1)',
  specUrl: 'https://www.bsi.bund.de/dok/TR-03183',
  description:
    'Measures the licence fields BSI TR-03183-2 v2.1.0 section 6.1 requires ' +
    'per component: the distribution licence (mandatory, gated at 100 %) and ' +
    'the effective licence (optional, a meter), each stated as an SPDX ' +
    'identifier or expression. Identifiers are checked against the SPDX ' +
    'License List; LicenseRef-* identifiers count, because the TR names the ' +
    'ScanCode LicenseDB (LicenseRef-scancode-*) as the fallback for licences ' +
    'the list lacks. Deprecated identifiers still count as identifiers; the ' +
    'Licenses view marks them. NOASSERTION and NONE count as absent. A ' +
    'licence text in place of an identifier is reported by the expression ' +
    'grammar lint, not here. The TR accepts only SPDX 3.0.1+ or CycloneDX ' +
    '1.6+, enforced as the leading format-baseline check. This profile says ' +
    'nothing about which licence is acceptable, what it obliges, or whether ' +
    'two licences are compatible: it measures whether the required ' +
    'identifiers are present and valid, and that is not a conformance ' +
    'statement.',
  requires: { spec: ['spdx-3', 'cdx-1.6'] },
  checks: [
    {
      id: 'distribution-licence',
      type: 'package-coverage',
      field: 'licenseDeclared',
      threshold: 100,
      licenseIds: 'known-or-ref',
      label: 'Distribution licence on every component, as SPDX identifier or expression',
    },
    {
      id: 'effective-licence',
      type: 'package-coverage',
      field: 'licenseConcluded',
      licenseIds: 'known-or-ref',
      label: 'Effective (concluded) licence, where stated',
    },
  ],
};
