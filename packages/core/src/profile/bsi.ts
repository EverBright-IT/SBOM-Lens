import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V4 } from './model';

/**
 * Field-level approximation of BSI TR-03183-2 v2.1.0 (2025-08-20), mapped as
 * the TR's appendix 8.2 maps its fields onto SPDX 3.0.1 and CycloneDX 1.6,
 * expressed as profile data (schema v4: the `requires` precondition, the
 * SHA-512 algorithm gate, the fileName and properties fields, and an
 * informational document fact). The TR accepts only SPDX >= 3.0.1 or
 * CycloneDX >= 1.6 as formats; `requires` turns that into a leading GATED
 * check, so an SPDX 2.x document visibly fails the format baseline instead
 * of rendering an all-green report that overstates conformance.
 *
 * Gated, because the TR states them without condition: the format, the SBOM
 * creator with contact, the timestamp, the dependencies, and per component
 * the version, the creator with contact and the distribution licence.
 * Meters: the filename and the SHA-512 hash, because 3.2.1 omits what a
 * component's assembly cannot provide and 3.2.2 exempts logical components
 * from both; the executable, archive and structured properties (read in the
 * CycloneDX taxonomy form only); unique identifiers (5.2.4, "where they
 * exist"); and the SBOM-URI (5.2.3, "if it exists").
 */
export const BSI_TR_03183_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V4,
  name: 'BSI TR-03183-2 field coverage (approximation)',
  specUrl: 'https://www.bsi.bund.de/dok/TR-03183',
  description:
    'Approximates BSI TR-03183-2 v2.1.0, mapped as its appendix 8.2 maps the fields onto SPDX 3.0.1+ and ' +
    'CycloneDX 1.6+. The TR accepts only those formats; this profile enforces that baseline as a gated check ' +
    'on both lines, so an SPDX 2.x or CycloneDX 1.5 document reports the format mismatch instead of looking ' +
    'conformant. Gated: SBOM creator with email or URL, timestamp, dependencies enumerated, and per component ' +
    'the version, the creator with email or URL (originatedBy or manufacturer, not the supplier) and the ' +
    'distribution licence (the concluded licence). Meters, because the TR exempts logical components and ' +
    'what an assembly cannot provide (3.2.1, 3.2.2): the filename, the SHA-512 hash, the executable, archive ' +
    'and structured properties, unique identifiers where they exist, and the SBOM-URI. Not checkable by ' +
    'this engine and reviewed manually: the completeness indication for dependencies, source-code and ' +
    'deployable-form URIs, the SPDX 3 form of the three properties (software_additionalPurpose on the ' +
    'distribution artifact), hashes stated on the distribution artifact or reference rather than on the ' +
    'component, security.txt, and that an SBOM carries no vulnerability data (8.1.14). Licence identifier ' +
    'validity (6.1) is the licence preset.',
  requires: { spec: ['spdx-3', 'cdx-1.6'] },
  checks: [
    {
      id: 'creators',
      type: 'document-field',
      field: 'creators',
      // The contact must sit on a human/organisational creator: a plain
      // "Tool: npm@10" must not satisfy this via its version's "@". The
      // parsers put the contact in parentheses after the name.
      pattern: '^(Person|Organization):.*(@|https?://)',
      label:
        'SBOM creator with email or URL (5.2.1, 8.1.8; SPDX 3 createdBy agent with an email or urlScheme ' +
        'externalIdentifier, CycloneDX metadata.manufacturer contact email or url)',
    },
    {
      id: 'created',
      type: 'document-field',
      field: 'created',
      label: 'Timestamp (5.2.1; SPDX 3 CreationInfo created, CycloneDX metadata.timestamp)',
    },
    {
      id: 'relationships',
      type: 'relationships',
      label:
        'Dependencies on other components enumerated (5.2.2; SPDX 3 contains or dependsOn relationships, ' +
        'CycloneDX dependencies[] or nested components; the completeness indication is not read)',
    },
    {
      id: 'pkg-version',
      type: 'package-coverage',
      field: 'version',
      threshold: 100,
      label: 'Component version on every component (5.2.2)',
    },
    {
      id: 'pkg-creator',
      type: 'package-coverage',
      field: 'originator',
      threshold: 100,
      pattern: '(@|https?://)',
      label:
        'Component creator with email or URL on every component (5.2.2, 8.1.8; SPDX 3 originatedBy agent ' +
        'with an email or URL externalIdentifier, CycloneDX manufacturer contact email or url)',
    },
    {
      id: 'pkg-license',
      type: 'package-coverage',
      field: 'licenseConcluded',
      threshold: 100,
      label:
        'Distribution licence on every component (5.2.2; SPDX 3 hasConcludedLicense, CycloneDX licence ' +
        'acknowledged as concluded; identifier validity per 6.1 is the licence preset)',
    },
    {
      id: 'pkg-filename',
      type: 'package-coverage',
      field: 'fileName',
      label:
        'Filename of the component (5.2.2, not required for logical components per 3.2.2; SPDX 3 ' +
        'hasDistributionArtifact file name, CycloneDX property bsi:component:filename)',
    },
    {
      id: 'pkg-checksum',
      type: 'package-coverage',
      field: 'checksum',
      algorithms: ['SHA512'],
      label:
        'SHA-512 hash of the deployable component (5.2.2, not required for logical components per 3.2.2; ' +
        'read from the component itself, not from the distribution-artifact locations of 8.2)',
    },
    {
      id: 'pkg-executable',
      type: 'package-coverage',
      field: 'properties',
      pattern: '(^|\\n)bsi:component:executable=(executable|non-executable)(\\n|$)',
      label: 'Executable property (5.2.2; CycloneDX property bsi:component:executable; the SPDX 3 form is not read)',
    },
    {
      id: 'pkg-archive',
      type: 'package-coverage',
      field: 'properties',
      pattern: '(^|\\n)bsi:component:archive=(archive|no archive)(\\n|$)',
      label: 'Archive property (5.2.2; CycloneDX property bsi:component:archive; the SPDX 3 form is not read)',
    },
    {
      id: 'pkg-structured',
      type: 'package-coverage',
      field: 'properties',
      pattern: '(^|\\n)bsi:component:structured=(structured|unstructured)(\\n|$)',
      label: 'Structured property (5.2.2; CycloneDX property bsi:component:structured; the SPDX 3 form is not read)',
    },
    {
      id: 'pkg-unique-id',
      type: 'package-coverage',
      field: 'uniqueId',
      label:
        'Other unique identifiers where they exist (5.2.4; CPE, purl or SWID: SPDX 3 externalIdentifier, ' +
        'CycloneDX cpe, purl, swid)',
    },
    {
      id: 'sbom-uri',
      type: 'document-field',
      field: 'namespace',
      informational: true,
      label: 'SBOM-URI where it exists (5.2.3; SPDX document spdxId, CycloneDX serialNumber and version)',
    },
  ],
};
