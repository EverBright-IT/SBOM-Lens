import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { emptyWorkspace } from '../workspace/workspace';
import { BSI_LICENSING_PROFILE } from './bsi-licensing';
import { evaluateProfile } from './evaluate';
import { validateProfile } from './validate';

/**
 * TR-03183-2 as data, mapped the way its appendix 8.2 maps the fields: the
 * distribution licence is the CONCLUDED licence and gates, the original
 * licence is the DECLARED licence and meters, the effective licence is the
 * bsi:component:effectiveLicense property and meters. All demand SPDX
 * identifiers or expressions with the ScanCode LicenseRef fallback, and
 * the TR's format baseline leads.
 */

const report = (doc: ReturnType<typeof loadedFromText>) => evaluateProfile(emptyWorkspace, doc, BSI_LICENSING_PROFILE);
const byId = (doc: ReturnType<typeof loadedFromText>, id: string) => report(doc).results.find((r) => r.id === id)!;

/** CycloneDX 1.6 so the format baseline passes and the licence fields are the subject. */
function cdx(licenses: unknown[], extra: Record<string, unknown> = {}) {
  return loadedFromText(
    'l.cdx.json',
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      metadata: { authors: [{ name: 'ACME' }] },
      components: [{ type: 'library', 'bom-ref': 'c1', name: 'widget', version: '1.0', licenses, ...extra }],
    }),
  );
}

const concluded = (entry: Record<string, unknown>) => ({ ...entry, acknowledgement: 'concluded' });

describe('BSI_LICENSING_PROFILE', () => {
  it('is valid v4 profile data and refuses to rate licences', () => {
    expect(validateProfile(BSI_LICENSING_PROFILE).ok).toBe(true);
    expect(BSI_LICENSING_PROFILE.description).toContain('nothing about which licence is acceptable');
    expect(BSI_LICENSING_PROFILE.description).toContain('not a conformance statement');
  });

  it('leads with the TR format baseline, like the BSI field-coverage preset', () => {
    const spdx2 = loadedFromText('two.spdx.json', loadFixture('minimal.spdx.json'));
    const results = report(spdx2).results;
    expect(results[0]!.id).toBe('format-baseline');
    expect(results[0]!.pass).toBe(false);
  });

  it('gates the distribution licence and meters the original and effective ones', () => {
    const check = (id: string) => BSI_LICENSING_PROFILE.checks.find((c) => c.id === id)!;
    expect(check('distribution-licence')).toMatchObject({ field: 'licenseConcluded', threshold: 100 });
    expect(check('original-licence')).toMatchObject({ field: 'licenseDeclared' });
    expect(check('original-licence')).not.toHaveProperty('threshold');
    expect(check('effective-licence')).toMatchObject({ field: 'properties' });
    expect(check('effective-licence')).not.toHaveProperty('threshold');
  });

  it.each([
    ['a valid SPDX identifier', [concluded({ license: { id: 'MIT' } })], 1],
    ['a valid expression', [concluded({ expression: 'Apache-2.0 OR MIT' })], 1],
    ['the ScanCode fallback the TR names', [concluded({ license: { id: 'LicenseRef-scancode-proprietary-license' } })], 1],
    ['a deprecated identifier (still an identifier on the list)', [concluded({ license: { id: 'GPL-2.0' } })], 1],
    ['a licence name instead of an identifier', [concluded({ license: { name: 'MIT License' } })], 0],
    ['an identifier not on the list and not a LicenseRef', [concluded({ license: { id: 'Acme-Proprietary-1.0' } })], 0],
    ['a licence without the acknowledgement the mapping names', [{ license: { id: 'MIT' } }], 0],
    ['no licence at all', [], 0],
  ])('distribution licence: %s', (_label, licenses, satisfied) => {
    expect(byId(cdx(licenses), 'distribution-licence').coverage?.satisfied).toBe(satisfied);
  });

  it('maps the fields as appendix 8.2 does: concluded is the distribution licence, declared the original one', () => {
    const both = cdx([{ license: { id: 'MIT' } }, { expression: 'Apache-2.0', acknowledgement: 'concluded' }]);
    expect(byId(both, 'distribution-licence').coverage?.satisfied).toBe(1);
    expect(byId(both, 'original-licence').coverage?.satisfied).toBe(1);
    // No acknowledgement reads as declared: the original licence is stated,
    // the distribution licence is not.
    const declaredOnly = cdx([{ license: { id: 'MIT' } }]);
    expect(byId(declaredOnly, 'distribution-licence').coverage?.satisfied).toBe(0);
    expect(byId(declaredOnly, 'original-licence').coverage?.satisfied).toBe(1);
  });

  it('reads the effective licence from the bsi:component:effectiveLicense property, wherever it sits', () => {
    const stated = cdx([concluded({ license: { id: 'MIT' } })], {
      properties: [
        { name: 'bsi:component:filename', value: 'widget.jar' },
        { name: 'bsi:component:effectiveLicense', value: 'MIT' },
      ],
    });
    expect(byId(stated, 'effective-licence').coverage?.satisfied).toBe(1);
    const empty = cdx([concluded({ license: { id: 'MIT' } })], { properties: [{ name: 'bsi:component:effectiveLicense', value: '' }] });
    expect(byId(empty, 'effective-licence').coverage?.satisfied).toBe(0);
    expect(byId(cdx([concluded({ license: { id: 'MIT' } })]), 'effective-licence').coverage?.satisfied).toBe(0);
  });

  it('reads the SPDX 3 relationships the appendix names', () => {
    const ci = '_:ci';
    const graph = JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': ci, specVersion: '3.0.1', created: '2026-06-01T10:00:00Z' },
        { type: 'SpdxDocument', spdxId: 'https://acme.example/doc/lic', creationInfo: ci, name: 'lic' },
        { type: 'software_Package', spdxId: 'https://acme.example/pkg/a', creationInfo: ci, name: 'a' },
        { type: 'simplelicensing_LicenseExpression', spdxId: 'https://acme.example/lic/1', creationInfo: ci, simplelicensing_licenseExpression: 'MIT' },
        { type: 'simplelicensing_LicenseExpression', spdxId: 'https://acme.example/lic/2', creationInfo: ci, simplelicensing_licenseExpression: 'Apache-2.0' },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/1', creationInfo: ci, from: 'https://acme.example/pkg/a', relationshipType: 'hasConcludedLicense', to: ['https://acme.example/lic/1'] },
        { type: 'Relationship', spdxId: 'https://acme.example/rel/2', creationInfo: ci, from: 'https://acme.example/pkg/a', relationshipType: 'hasDeclaredLicense', to: ['https://acme.example/lic/2'] },
      ],
    });
    const doc = loadedFromText('lic.spdx3.json', graph);
    expect(byId(doc, 'format-baseline').pass).toBe(true);
    expect(byId(doc, 'distribution-licence').coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(byId(doc, 'original-licence').coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(byId(doc, 'effective-licence').coverage).toMatchObject({ satisfied: 0, total: 1 });
  });

  it('fails the gate on a document where one component lacks a distribution licence', () => {
    const doc = loadedFromText(
      'l.cdx.json',
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        components: [
          { type: 'library', 'bom-ref': 'a', name: 'a', licenses: [{ license: { id: 'MIT' }, acknowledgement: 'concluded' }] },
          { type: 'library', 'bom-ref': 'b', name: 'b' },
        ],
      }),
    );
    const r = report(doc);
    expect(r.results.find((x) => x.id === 'distribution-licence')).toMatchObject({ pass: false });
    expect(r.gatedFailed).toBeGreaterThan(0);
  });
});
