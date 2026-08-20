import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V1 } from './model';

/**
 * The 2026 Minimum Elements for a Software Bill of Materials (CISA, NSA, FBI
 * and 16 international partners including the BSI, 29 July 2026), which
 * "updates and replaces" the 2021 NTIA minimum elements this repo also ships.
 *
 * Appendix A lists 17 data fields plus six Practices and Processes. Only the
 * data fields can be read off a document at all, and not even all of those.
 * The mapping decisions worth remembering:
 *
 *   - Component Producer is the SPDX `originator`, NOT `supplier`. The 2026
 *     text replaces "Supplier Name" and says why: "Supplier Name has proven
 *     ambiguous in practice, particularly around distributors of software."
 *     SPDX draws exactly that line — supplier is "the immediate supplier of
 *     this package to the recipient", originator "the person or organization
 *     that originally created the package". Measuring producer on `supplier`
 *     would report the distributor and call it the producer.
 *   - Hash Value and Hash Algorithm are one check. Both SPDX and CycloneDX
 *     carry a checksum as an (algorithm, value) pair; there is no document in
 *     which one is present without the other, so two checks would be padding.
 *   - The gated/informational split is the engine's, not a claim of ours.
 *     Boolean checks (document fields, relationships) gate by construction;
 *     coverage checks without a threshold are meters. We deliberately set no
 *     coverage thresholds: the source document disclaims itself as
 *     non-binding ("does not create new requirements", "not intended to ...
 *     constitute advice for compliance, regulatory, or legal purposes"), so
 *     demanding 100% producer coverage would turn guidance into a verdict.
 *     A missing SBOM author still fails, and should: that is a fact about
 *     the document, not an interpretation of the guidance.
 *   - No `requires` baseline, unlike the BSI profile. The 2026 elements name
 *     SPDX and CycloneDX without a version floor, so inventing one here would
 *     be a requirement of our own making.
 *
 * Schema v1 on purpose: the profile uses only `pattern` and plain coverage,
 * so an older engine evaluates it faithfully rather than rejecting it.
 */
export const CISA_2026_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V1,
  name: 'CISA 2026 minimum elements',
  specUrl:
    'https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom',
  description:
    'Measures the data fields of the 2026 Minimum Elements for a Software ' +
    'Bill of Materials (CISA, NSA, FBI and international partners, ' +
    '29 July 2026), which updates and replaces the 2021 NTIA minimum ' +
    'elements. Field presence only: the source states that it does not ' +
    'create new requirements and is not advice for compliance purposes, so ' +
    'a complete report is not a conformance statement. The document-level ' +
    'elements report as pass or fail; the component elements are coverage ' +
    'meters with no threshold, because demanding full coverage of ' +
    'non-binding guidance would turn it into a verdict. ' +
    'There is no format baseline, because the 2026 elements name SPDX and ' +
    'CycloneDX without a version floor. Component producer is measured on ' +
    'the SPDX originator field rather than supplier, because the element ' +
    'replaced Supplier Name precisely to move away from the distributor ' +
    'reading; mainstream generators populate neither field today, so a low ' +
    'meter here is a finding about the SBOM, not about the profile. ' +
    'Component hash value and hash algorithm are one check, since both ' +
    'formats carry them as a pair. Satisfied by construction in any parsed ' +
    'document and therefore not checked: component name, SBOM data format ' +
    'name, SBOM data format version. Not checkable by this engine and ' +
    'reviewed manually: SBOM author signature (detached from the document), ' +
    'SBOM generation context (no SPDX field, and the CycloneDX lifecycles ' +
    'field is not mapped), SBOM version, and SBOM tool version separately ' +
    'from the tool name. On CycloneDX the SBOM author is read from ' +
    'metadata.authors only. The six practices and processes elements ' +
    '(accommodation of updates, coverage, distribution and delivery, ' +
    'explicitly identifying unknown information, frequency, ' +
    'machine-processable data) describe how an organisation handles SBOM ' +
    'data and cannot be read off a document; note that the coverage element ' +
    'explicitly accepts linking to separate SBOM documents, which the ' +
    'workspace resolves and reports as cascades.',
  checks: [
    // --- SBOM metadata ------------------------------------------------------
    {
      id: 'sbom-author',
      type: 'document-field',
      field: 'creators',
      // "This element captures the entity operating the tool to generate the
      // SBOM, not the tool itself." Patterns match per creator entry, so a
      // lone "Tool: syft-1.0" cannot satisfy this.
      pattern: '^(Person|Organization):',
      label: 'SBOM author (person or organization, not the tool)',
    },
    { id: 'sbom-timestamp', type: 'document-field', field: 'created', label: 'SBOM timestamp' },
    {
      id: 'sbom-tool',
      type: 'document-field',
      field: 'creators',
      pattern: '^Tool:',
      label: 'SBOM tool name',
    },
    // --- Component data -----------------------------------------------------
    {
      id: 'component-producer',
      type: 'package-coverage',
      field: 'originator',
      label: 'Component producer (the entity that created the component)',
    },
    { id: 'component-version', type: 'package-coverage', field: 'version', label: 'Component version' },
    {
      id: 'component-identifiers',
      type: 'package-coverage',
      field: 'uniqueId',
      label: 'Component identifiers (purl, CPE or other external refs)',
    },
    {
      id: 'component-hash',
      type: 'package-coverage',
      field: 'checksum',
      label: 'Component hash value and algorithm',
    },
    { id: 'component-license', type: 'package-coverage', field: 'license', label: 'Component license' },
    {
      id: 'component-dependency',
      type: 'relationships',
      label: 'Component dependency relationships',
    },
  ],
};
