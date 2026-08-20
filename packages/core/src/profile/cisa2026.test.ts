import { describe, expect, it } from 'vitest';
import { emptyWorkspace } from '../workspace/workspace';
import { loadFixture, loadedFromText } from '../test-fixtures';
import { CISA_2026_PROFILE } from './cisa2026';
import { evaluateProfile } from './evaluate';
import { validateProfile } from './validate';

/**
 * The 2026 preset is plain profile data like the others. What is pinned here
 * are the three mapping decisions that are easy to get wrong and impossible
 * to spot later from the report alone: producer is the originator, the author
 * is not the tool, and nothing in this profile gates.
 */

const resultById = (profile: typeof CISA_2026_PROFILE, doc: ReturnType<typeof loadedFromText>, id: string) =>
  evaluateProfile(emptyWorkspace, doc, profile).results.find((r) => r.id === id)!;

/** SPDX 2.3 tag-value, so each field can be set or omitted in isolation. */
function spdxDoc(lines: { creators?: string[]; pkg?: string[] }): ReturnType<typeof loadedFromText> {
  return loadedFromText(
    't.spdx',
    [
      'SPDXVersion: SPDX-2.3',
      'DataLicense: CC0-1.0',
      'SPDXID: SPDXRef-DOCUMENT',
      'DocumentName: t',
      'DocumentNamespace: https://example.org/spdxdocs/t',
      ...(lines.creators ?? ['Organization: ACME Corp']).map((c) => `Creator: ${c}`),
      'Created: 2026-06-01T10:00:00Z',
      '',
      'PackageName: widget',
      'SPDXID: SPDXRef-Package-widget',
      'PackageDownloadLocation: NOASSERTION',
      ...(lines.pkg ?? []),
      '',
    ].join('\n'),
  );
}

describe('CISA_2026_PROFILE', () => {
  it('is valid profile data and says what it cannot check', () => {
    expect(validateProfile(CISA_2026_PROFILE).ok).toBe(true);
    expect(CISA_2026_PROFILE.description).toContain('updates and replaces');
    expect(CISA_2026_PROFILE.description).toContain('Not checkable by this engine');
  });

  it('sets no coverage threshold: the component elements stay meters', () => {
    // The engine gates every boolean check by construction, so document-level
    // elements report pass/fail. What is a choice, and is pinned here, is that
    // no component check carries a threshold: demanding full coverage of
    // self-declared non-binding guidance would turn it into a verdict.
    for (const check of CISA_2026_PROFILE.checks) {
      if (check.type === 'package-coverage') expect(check.threshold).toBeUndefined();
    }
    const bare = spdxDoc({ creators: ['Tool: syft-1.0'] });
    const report = evaluateProfile(emptyWorkspace, bare, CISA_2026_PROFILE);
    expect(report.informational).toBe(5); // the five component-coverage meters
    expect(report.gatedFailed + report.gatedPassed).toBe(4); // author, timestamp, tool, dependencies
  });

  it('carries no format baseline, unlike the BSI preset', () => {
    expect(CISA_2026_PROFILE.requires).toBeUndefined();
    const spdx2 = spdxDoc({});
    const ids = evaluateProfile(emptyWorkspace, spdx2, CISA_2026_PROFILE).results.map((r) => r.id);
    expect(ids).not.toContain('format-baseline');
  });

  describe('component producer is the originator, not the supplier', () => {
    it('is not satisfied by a supplier alone', () => {
      // The 2026 text replaced "Supplier Name" because supplier denotes the
      // distributor. A document that names only the distributor has not
      // named the producer, and the report must say so.
      const doc = spdxDoc({ pkg: ['PackageSupplier: Organization: Reseller GmbH'] });
      expect(resultById(CISA_2026_PROFILE, doc, 'component-producer').coverage?.satisfied).toBe(0);
    });

    it('is satisfied by an originator', () => {
      const doc = spdxDoc({ pkg: ['PackageOriginator: Organization: ACME Corp'] });
      expect(resultById(CISA_2026_PROFILE, doc, 'component-producer').coverage?.satisfied).toBe(1);
    });
  });

  describe('SBOM author is the entity, not the tool', () => {
    it('a tool-only creator list does not satisfy the author check', () => {
      const doc = spdxDoc({ creators: ['Tool: syft-1.0'] });
      expect(resultById(CISA_2026_PROFILE, doc, 'sbom-author').pass).toBe(false);
      expect(resultById(CISA_2026_PROFILE, doc, 'sbom-tool').pass).toBe(true);
    });

    it('an organization satisfies the author check without carrying a tool', () => {
      const doc = spdxDoc({ creators: ['Organization: ACME Corp'] });
      expect(resultById(CISA_2026_PROFILE, doc, 'sbom-author').pass).toBe(true);
      expect(resultById(CISA_2026_PROFILE, doc, 'sbom-tool').pass).toBe(false);
    });

    it('a person and a tool side by side satisfy both, matched per entry', () => {
      const doc = spdxDoc({ creators: ['Person: Jane Doe', 'Tool: trivy-0.63.0'] });
      expect(resultById(CISA_2026_PROFILE, doc, 'sbom-author').pass).toBe(true);
      expect(resultById(CISA_2026_PROFILE, doc, 'sbom-tool').pass).toBe(true);
    });
  });

  it('reads the same fields on CycloneDX, where creators are normalised', () => {
    const cdx = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      metadata: {
        authors: [{ name: 'ACME Corp' }],
        tools: { components: [{ type: 'application', name: 'cdxgen', version: '11.0.0' }] },
        component: { type: 'application', 'bom-ref': 'root', name: 'app', version: '1.0.0' },
      },
      components: [{ type: 'library', 'bom-ref': 'c1', name: 'widget', version: '2.0.0' }],
    });
    const doc = loadedFromText('app.cdx.json', cdx);
    // metadata.authors becomes "Person: ...", metadata.tools becomes "Tool: ..."
    expect(resultById(CISA_2026_PROFILE, doc, 'sbom-author').pass).toBe(true);
    expect(resultById(CISA_2026_PROFILE, doc, 'sbom-tool').pass).toBe(true);
    expect(resultById(CISA_2026_PROFILE, doc, 'component-version').coverage?.satisfied).toBeGreaterThan(0);
  });

  it('evaluates real fixtures without throwing, on every parsed model', () => {
    for (const name of ['minimal.spdx.json', 'spdx3/webstack.spdx3.json', 'cdx/minimal.cdx.json']) {
      const loaded = loadedFromText(name.split('/').pop()!, loadFixture(name));
      const report = evaluateProfile(emptyWorkspace, loaded, CISA_2026_PROFILE);
      expect(report.results).toHaveLength(CISA_2026_PROFILE.checks.length);
      expect(report.informational).toBe(5); // never a format-baseline precondition
    }
  });
});
