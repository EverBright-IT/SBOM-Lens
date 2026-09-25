import { describe, expect, it } from 'vitest';
import { loadedFromText } from '../test-fixtures';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { evaluateProfile } from './evaluate';
import { G7_AI_SBOM_PROFILE } from './g7-ai';
import { validateProfile } from './validate';

/**
 * The G7 SBOM-for-AI preset: model and dataset meters run over their own
 * components only, in both formats that can express them, and the profile
 * degrades to "none in scope" rather than to failures on an SPDX 2.x
 * document, which has no model or data purpose.
 */

const SHA = 'aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd';

function load(fileName: string, text: string) {
  const loaded = loadedFromText(fileName, text);
  const ws = addDocument(emptyWorkspace, loaded).workspace;
  return evaluateProfile(ws, loaded, G7_AI_SBOM_PROFILE);
}

const byId = (report: ReturnType<typeof load>) => Object.fromEntries(report.results.map((r) => [r.id, r]));

const spdx3 = JSON.stringify({
  '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
  '@graph': [
    {
      type: 'CreationInfo',
      '@id': '_:ci',
      specVersion: '3.0.1',
      created: '2026-06-01T10:00:00Z',
      createdBy: ['https://acme.example/agent/acme'],
      createdUsing: ['https://acme.example/agent/tool'],
    },
    { type: 'Organization', spdxId: 'https://acme.example/agent/acme', creationInfo: '_:ci', name: 'ACME Corp' },
    { type: 'Tool', spdxId: 'https://acme.example/agent/tool', creationInfo: '_:ci', name: 'acme-sbom-tool 2.0' },
    {
      type: 'SpdxDocument',
      spdxId: 'https://acme.example/doc/recommender',
      creationInfo: '_:ci',
      name: 'recommender',
      rootElement: ['https://acme.example/pkg/model'],
    },
    {
      type: 'ai_AIPackage',
      spdxId: 'https://acme.example/pkg/model',
      creationInfo: '_:ci',
      name: 'recommendation-model',
      software_packageVersion: '2.3.0',
      software_primaryPurpose: 'model',
      originatedBy: ['https://acme.example/agent/acme'],
      description: 'Ranks catalogue items. Not for medical use. Fine-tuned from base-7b.',
      verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: SHA }],
      software_packageUrl: 'pkg:huggingface/acme/recommendation-model@2.3.0',
      ai_typeOfModel: ['transformer'],
    },
    {
      type: 'dataset_DatasetPackage',
      spdxId: 'https://acme.example/pkg/dataset',
      creationInfo: '_:ci',
      name: 'clickstream-2025',
    },
    {
      type: 'software_Package',
      spdxId: 'https://acme.example/pkg/numpy',
      creationInfo: '_:ci',
      name: 'numpy',
      software_packageVersion: '2.1.0',
      software_primaryPurpose: 'library',
    },
    {
      type: 'Relationship',
      spdxId: 'https://acme.example/rel/license',
      creationInfo: '_:ci',
      from: 'https://acme.example/pkg/model',
      relationshipType: 'hasDeclaredLicense',
      to: ['https://spdx.org/licenses/Apache-2.0'],
    },
    {
      type: 'Relationship',
      spdxId: 'https://acme.example/rel/deps',
      creationInfo: '_:ci',
      from: 'https://acme.example/pkg/model',
      relationshipType: 'dependsOn',
      to: ['https://acme.example/pkg/numpy'],
    },
  ],
});

const cdx = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
  version: 1,
  metadata: {
    timestamp: '2026-06-01T10:00:00Z',
    authors: [{ name: 'ACME Security' }],
    tools: { components: [{ type: 'application', name: 'acme-gen', version: '2.0' }] },
    lifecycles: [{ phase: 'build' }],
    component: { type: 'application', name: 'recommender', version: '1.0.0', 'bom-ref': 'app' },
  },
  components: [
    {
      type: 'machine-learning-model',
      'bom-ref': 'model',
      name: 'recommendation-model',
      version: '2.3.0',
      manufacturer: { name: 'ACME Research' },
      description: 'Ranks catalogue items.',
      hashes: [{ alg: 'SHA-256', content: SHA }],
      purl: 'pkg:huggingface/acme/recommendation-model@2.3.0',
      licenses: [{ license: { id: 'Apache-2.0' } }],
    },
    { type: 'data', 'bom-ref': 'data', name: 'clickstream-2025', authors: [{ name: 'ACME Data Team' }] },
    { type: 'library', 'bom-ref': 'numpy', name: 'numpy', version: '2.1.0' },
  ],
  dependencies: [{ ref: 'app', dependsOn: ['model', 'numpy'] }],
});

describe('G7 SBOM for AI profile', () => {
  it('is a valid v5 profile with unique ids and a source link', () => {
    const result = validateProfile(G7_AI_SBOM_PROFILE);
    expect(result.ok).toBe(true);
    expect(G7_AI_SBOM_PROFILE.specUrl).toMatch(/^https:\/\/www\.bsi\.bund\.de\//);
    expect(G7_AI_SBOM_PROFILE.checks).toHaveLength(16);
  });

  it('measures models and datasets on their own components in SPDX 3', () => {
    const report = load('recommender.spdx3.json', spdx3);
    const r = byId(report);
    expect(report.packagesTotal).toBe(3);
    for (const id of ['model-identifier', 'model-version', 'model-producer', 'model-description', 'model-hash', 'model-license']) {
      expect(r[id]!.coverage, id).toMatchObject({ satisfied: 1, total: 1 });
    }
    for (const id of ['dataset-description', 'dataset-identifier', 'dataset-hash', 'dataset-license']) {
      expect(r[id]!.coverage, id).toMatchObject({ satisfied: 0, total: 1 });
    }
    // Document facts: author, tool, timestamp, a dependency relationship, a declared system.
    expect(report.gatedFailed).toBe(0);
    expect(report.gatedPassed).toBe(5);
    expect(r['sbom-generation-context']!.informational).toBe(true);
  });

  it('measures the same clusters on a CycloneDX BOM, with manufacturer as the model producer', () => {
    const report = load('recommender.cdx.json', cdx);
    const r = byId(report);
    expect(r['model-producer']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['model-hash']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['model-license']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['dataset-identifier']!.coverage).toMatchObject({ satisfied: 0, total: 1 });
    expect(r['sbom-generation-context']!.pass).toBe(true); // lifecycle phase "build"
    expect(report.gatedFailed).toBe(0);
  });

  it('shows the model and dataset meters as none in scope on an SPDX 2.3 document', () => {
    const text = [
      'SPDXVersion: SPDX-2.3',
      'DataLicense: CC0-1.0',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: classic',
      'DocumentNamespace: https://acme.example/spdxdocs/classic',
      'Creator: Organization: ACME',
      'Creator: Tool: acme-gen-2.0',
      'Created: 2026-06-01T10:00:00Z',
      '',
      'PackageName: widget',
      'SPDXID: SPDXRef-widget',
      'PackageVersion: 1.0.0',
      'PackageDownloadLocation: NOASSERTION',
      'PrimaryPackagePurpose: LIBRARY',
      '',
      'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-widget',
      '',
    ].join('\n');
    const report = load('classic.spdx', text);
    const r = byId(report);
    expect(r['model-hash']!.coverage).toMatchObject({ satisfied: 0, total: 0, percent: 100 });
    expect(r['model-hash']!.pass).toBe(true);
    expect(r['sbom-generation-context']!.pass).toBe(false); // informational, not a failure
    expect(report.gatedFailed).toBe(0);
  });
});
