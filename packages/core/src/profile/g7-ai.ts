import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V5 } from './model';

/**
 * Software Bill of Materials for AI: Minimum Elements (G7 Cybersecurity
 * Working Group, 12 May 2026), published jointly by BSI, ACN, ANSSI, CSE,
 * CISA, NCSC and NCO with the EU Commission under the work stream co-led by
 * Italy (ACN) and Germany (BSI). Seven clusters, fifty elements, and an
 * explicit statement that the elements "are not mandatory; do not create
 * requirements, standards, or legislation".
 *
 * Mapping decisions:
 *   - The paper's own framing decides the gating: nothing carries a
 *     threshold. Document facts report pass or fail, component elements are
 *     meters, and a complete report is not a conformance statement.
 *   - Models and datasets are measured on THEIR components only (schema v5
 *     `purposes`): purpose MODEL is an SPDX 3 ai_AIPackage or primaryPurpose
 *     model and the CycloneDX machine-learning-model type; DATA is an SPDX 3
 *     dataset_DatasetPackage or primaryPurpose data and the CycloneDX data
 *     type. Measuring model elements across every library would let a
 *     three-hundred-package SBOM hide a model without a hash. SPDX 2.3 has
 *     no model or data purpose, so on SPDX 2.x these meters read 0/0.
 *   - Model producer is the originator ("the originator or manufacturer of
 *     the model"), which CycloneDX carries as manufacturer or authors.
 *   - The AI-profile detail fields (SPDX 3 ai_* and dataset_* properties,
 *     the CycloneDX model card) are not read by this viewer, so model
 *     properties, training and input/output properties stay manual.
 *   - Elements satisfied by construction in any parsed document are not
 *     checked (data format name and version, model and dataset name, the
 *     component inventory itself); a check that always passes is padding.
 */
export const G7_AI_SBOM_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V5,
  name: 'G7 SBOM for AI minimum elements',
  specUrl: 'https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html',
  description:
    'Measures the machine-checkable elements of Software Bill of Materials ' +
    'for AI: Minimum Elements (G7 Cybersecurity Working Group, 12 May 2026; ' +
    'published jointly by BSI, ACN, ANSSI, CSE, CISA, NCSC and NCO with the ' +
    'EU Commission). The paper states that its elements are not mandatory ' +
    'and do not create requirements, standards, or legislation, so nothing ' +
    'here is a conformance statement: document facts report pass or fail, ' +
    'component elements are coverage meters without thresholds. Of the 50 ' +
    'elements in seven clusters, 17 are measured here; 6 hold by ' +
    'construction in any parsed document (SBOM data format name and version, ' +
    'system components as the inventory itself, model name, dataset name, ' +
    'infrastructure software as the component list); 27 are free-text or ' +
    'organisational elements no SBOM field carries and are reviewed ' +
    'manually: SBOM version, SBOM author signature, SBOM tool version; ' +
    'system producer, version, timestamp, data flow, data usage, ' +
    'input/output properties and intended application area; model ' +
    'timestamp, model properties, model input-output properties, model ' +
    'training properties and model external references; dataset content, ' +
    'provenance, statistical properties, sensitivity and dataset dependency ' +
    'relationship; infrastructure hardware; the four security properties; ' +
    'the two key performance indicators. The model meters run only over ' +
    'components with purpose MODEL (SPDX 3 ai_AIPackage or primaryPurpose ' +
    'model, CycloneDX machine-learning-model), the dataset meters only over ' +
    'purpose DATA (SPDX 3 dataset_DatasetPackage or primaryPurpose data, ' +
    'CycloneDX data); SPDX 2.3 has no such purposes, and a document without ' +
    'such components shows those meters as none in scope. Model producer is ' +
    'the originator (the entity that created the model; CycloneDX ' +
    'manufacturer or authors), model description the component description, ' +
    'and model hash value and hash algorithm are one check. The AI-profile ' +
    'detail fields (SPDX 3 ai_* and dataset_* properties, the CycloneDX ' +
    'model card) are not read by this viewer. SBOM generation context is ' +
    'SPDX 3 sbomType or the CycloneDX lifecycle phase and cannot be ' +
    'expressed in SPDX 2.x, so it is informational.',
  checks: [
    // --- Metadata cluster ---------------------------------------------------
    {
      id: 'sbom-author',
      type: 'document-field',
      field: 'creators',
      // "This element captures the entity operating the tool to generate the
      // SBOM, not the tool itself."
      pattern: '^(Person|Organization):',
      label: 'SBOM author (person or organization, not the tool)',
    },
    { id: 'sbom-tool', type: 'document-field', field: 'creators', pattern: '^Tool:', label: 'SBOM tool name' },
    { id: 'sbom-timestamp', type: 'document-field', field: 'created', label: 'SBOM timestamp' },
    {
      id: 'sbom-generation-context',
      type: 'document-field',
      field: 'sbomType',
      informational: true,
      label: 'SBOM generation context (SPDX 3 sbomType or CycloneDX lifecycle; not expressible in SPDX 2.x)',
    },
    { id: 'sbom-dependency-relationship', type: 'relationships', label: 'SBOM dependency relationship' },
    // --- System level properties -------------------------------------------
    { id: 'system-name', type: 'document-field', field: 'describes', label: 'System name (primary component declared)' },
    // --- Models cluster: purpose MODEL only --------------------------------
    {
      id: 'model-identifier',
      type: 'package-coverage',
      field: 'uniqueId',
      purposes: ['MODEL'],
      label: 'Model identifier (purl, CPE or other reference)',
    },
    { id: 'model-version', type: 'package-coverage', field: 'version', purposes: ['MODEL'], label: 'Model version' },
    {
      id: 'model-producer',
      type: 'package-coverage',
      field: 'originator',
      purposes: ['MODEL'],
      label: 'Model producer (originator or manufacturer)',
    },
    {
      id: 'model-description',
      type: 'package-coverage',
      field: 'description',
      purposes: ['MODEL'],
      label: 'Model description (capabilities, limitations, lineage)',
    },
    {
      id: 'model-hash',
      type: 'package-coverage',
      field: 'checksum',
      purposes: ['MODEL'],
      label: 'Model hash value and algorithm',
    },
    { id: 'model-license', type: 'package-coverage', field: 'license', purposes: ['MODEL'], label: 'Model license' },
    // --- Datasets properties: purpose DATA only ---------------------------
    {
      id: 'dataset-description',
      type: 'package-coverage',
      field: 'description',
      purposes: ['DATA'],
      label: 'Dataset description',
    },
    {
      id: 'dataset-identifier',
      type: 'package-coverage',
      field: 'uniqueId',
      purposes: ['DATA'],
      label: 'Dataset identifier',
    },
    { id: 'dataset-hash', type: 'package-coverage', field: 'checksum', purposes: ['DATA'], label: 'Dataset hash' },
    { id: 'dataset-license', type: 'package-coverage', field: 'license', purposes: ['DATA'], label: 'Dataset license' },
  ],
};
