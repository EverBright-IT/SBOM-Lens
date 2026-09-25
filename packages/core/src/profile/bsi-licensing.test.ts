import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { emptyWorkspace } from '../workspace/workspace';
import { BSI_LICENSING_PROFILE } from './bsi-licensing';
import { evaluateProfile } from './evaluate';
import { validateProfile } from './validate';

/**
 * TR-03183-2 section 6.1 as data: the distribution licence gates, the
 * effective licence meters, both demand SPDX identifiers or expressions with
 * the ScanCode LicenseRef fallback, and the TR's format baseline leads.
 */

const report = (doc: ReturnType<typeof loadedFromText>) => evaluateProfile(emptyWorkspace, doc, BSI_LICENSING_PROFILE);
const byId = (doc: ReturnType<typeof loadedFromText>, id: string) => report(doc).results.find((r) => r.id === id)!;

/** CycloneDX 1.6 so the format baseline passes and the licence fields are the subject. */
function cdx(licenses: unknown[]) {
  return loadedFromText(
    'l.cdx.json',
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      metadata: { authors: [{ name: 'ACME' }] },
      components: [{ type: 'library', 'bom-ref': 'c1', name: 'widget', version: '1.0', licenses }],
    }),
  );
}

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

  it('gates the distribution licence and meters the effective one', () => {
    const distribution = BSI_LICENSING_PROFILE.checks.find((c) => c.id === 'distribution-licence')!;
    const effective = BSI_LICENSING_PROFILE.checks.find((c) => c.id === 'effective-licence')!;
    expect(distribution.type === 'package-coverage' && distribution.threshold).toBe(100);
    expect(effective.type === 'package-coverage' && effective.threshold).toBeUndefined();
  });

  it.each([
    ['a valid SPDX identifier', [{ license: { id: 'MIT' } }], 1],
    ['a valid expression', [{ expression: 'Apache-2.0 OR MIT' }], 1],
    ['the ScanCode fallback the TR names', [{ license: { id: 'LicenseRef-scancode-proprietary-license' } }], 1],
    ['a deprecated identifier (still an identifier on the list)', [{ license: { id: 'GPL-2.0' } }], 1],
    ['a licence name instead of an identifier', [{ license: { name: 'MIT License' } }], 0],
    ['an identifier not on the list and not a LicenseRef', [{ license: { id: 'Acme-Proprietary-1.0' } }], 0],
    ['no licence at all', [], 0],
  ])('distribution licence: %s', (_label, licenses, satisfied) => {
    expect(byId(cdx(licenses), 'distribution-licence').coverage?.satisfied).toBe(satisfied);
  });

  it('keeps declared and concluded apart', () => {
    const doc = cdx([{ license: { id: 'MIT' } }, { expression: 'Apache-2.0', acknowledgement: 'concluded' }]);
    expect(byId(doc, 'distribution-licence').coverage?.satisfied).toBe(1);
    expect(byId(doc, 'effective-licence').coverage?.satisfied).toBe(1);
    const declaredOnly = cdx([{ license: { id: 'MIT' } }]);
    expect(byId(declaredOnly, 'effective-licence').coverage?.satisfied).toBe(0);
  });

  it('fails the gate on a document where one component lacks a distribution licence', () => {
    const doc = loadedFromText(
      'l.cdx.json',
      JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
        components: [
          { type: 'library', 'bom-ref': 'a', name: 'a', licenses: [{ license: { id: 'MIT' } }] },
          { type: 'library', 'bom-ref': 'b', name: 'b' },
        ],
      }),
    );
    const r = report(doc);
    expect(r.results.find((x) => x.id === 'distribution-licence')).toMatchObject({ pass: false });
    expect(r.gatedFailed).toBeGreaterThan(0);
  });
});
