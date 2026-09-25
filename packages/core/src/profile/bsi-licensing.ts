import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V4 } from './model';

/**
 * BSI TR-03183-2 v2.1.0: the licence data fields of sections 5.2.2, 5.2.4
 * and 5.2.5, stated as section 6.1 demands (SPDX identifiers or SPDX
 * expressions; a licence text does not replace the id; the ScanCode
 * LicenseDB as the fallback, LicenseRef-scancode-...), and mapped as the
 * TR's own appendix 8.2 maps them onto the formats:
 *   - "Distribution licences" (5.2.2, required per component): SPDX 3
 *     hasConcludedLicense, CycloneDX licence with acknowledgement
 *     "concluded". Model field licenseConcluded. Gated at 100 %.
 *   - "Original licences" (5.2.4, required if they exist): SPDX 3
 *     hasDeclaredLicense, CycloneDX acknowledgement "declared". Model field
 *     licenseDeclared. A meter, because "if they exist" cannot gate.
 *   - "Effective licence" (5.2.5, optional): CycloneDX property
 *     bsi:component:effectiveLicense, read as a properties pattern; in
 *     SPDX 3 a Relationship of type other with the comment
 *     hasEffectiveLicense, which this engine does not read. A meter.
 * The TR argues the requirement from security as well as compliance: a
 * licence can forbid changing code to fix a vulnerability (8.1.13).
 *
 * Consequences worth knowing:
 *   - A CycloneDX licence entry without acknowledgement is read as declared
 *     (the parser's default), so a BOM that states licences without the
 *     acknowledgement the mapping names fails the distribution gate. That
 *     is the mapping's requirement, not a parser quirk.
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
    'Measures the licence data fields BSI TR-03183-2 v2.1.0 lists per ' +
    'component, stated as section 6.1 demands (SPDX identifier or ' +
    'expression) and mapped as appendix 8.2 of the TR maps them: the ' +
    'distribution licence (5.2.2, required; SPDX 3 hasConcludedLicense, ' +
    'CycloneDX licence acknowledged as concluded) is gated at 100 %, the ' +
    'original licence (5.2.4, required where it exists; hasDeclaredLicense, ' +
    'acknowledgement declared) is a meter, and the effective licence (5.2.5, ' +
    'optional) is a meter on the presence of the CycloneDX property ' +
    'bsi:component:effectiveLicense (NOASSERTION and NONE count as absent; ' +
    'a property value is not checked against the License List); its SPDX 3 ' +
    'form, a relationship of type other with the comment hasEffectiveLicense, ' +
    'is not read. A ' +
    'CycloneDX licence entry without acknowledgement counts as declared, so ' +
    'a BOM that omits the acknowledgement the mapping names fails the ' +
    'distribution gate. Identifiers are checked against the SPDX License ' +
    'List; LicenseRef-* identifiers count, because the TR names the ' +
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
      field: 'licenseConcluded',
      threshold: 100,
      licenseIds: 'known-or-ref',
      label:
        'Distribution licence on every component, as SPDX identifier or expression (5.2.2: SPDX 3 hasConcludedLicense, CycloneDX acknowledgement concluded)',
    },
    {
      id: 'original-licence',
      type: 'package-coverage',
      field: 'licenseDeclared',
      licenseIds: 'known-or-ref',
      label: 'Original licence where it exists, as SPDX identifier or expression (5.2.4: SPDX 3 hasDeclaredLicense, CycloneDX acknowledgement declared)',
    },
    {
      id: 'effective-licence',
      type: 'package-coverage',
      field: 'properties',
      pattern: '(^|\\n)bsi:component:effectiveLicense=(?!(NOASSERTION|NONE)(\\n|$))\\S',
      label:
        'Effective licence property present (5.2.5: CycloneDX property bsi:component:effectiveLicense, presence only; the SPDX 3 form is not read)',
    },
  ],
};
