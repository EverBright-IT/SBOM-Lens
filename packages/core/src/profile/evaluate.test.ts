import { describe, expect, it } from 'vitest';
import { documentQuality } from '../analysis/quality';
import { parseOcmComponentDescriptor } from '../parse/ocm/cd';
import { registerOcmParser } from '../parse/parser';
import { loadFixtureDocument, loadedFromText } from '../test-fixtures';
import type { LoadedDocument, WorkspaceState } from '../workspace/workspace';
import { addDocument, emptyWorkspace } from '../workspace/workspace';
import { evaluateProfile } from './evaluate';
import type { ComplianceProfile, ProfileCheck } from './model';
import { PROFILE_SCHEMA_V1 } from './model';
import { profileReportToMarkdown } from './markdown';
import { NTIA_PROFILE } from './ntia';

// The OCM fixtures below parse only once descriptors are wired in.
registerOcmParser(parseOcmComponentDescriptor);

function profileOf(...checks: ProfileCheck[]): ComplianceProfile {
  return { schema: PROFILE_SCHEMA_V1, name: 'Test', checks };
}

/** Tag-value doc with fine-grained control over document + package fields. */
function docFrom(opts: {
  created?: string;
  creators?: string[];
  namespace?: boolean;
  packages?: {
    version?: string;
    supplier?: string;
    purpose?: string;
    purl?: string;
    license?: string;
  }[];
}): { ws: WorkspaceState; loaded: LoadedDocument } {
  const lines = ['SPDXVersion: SPDX-2.3', 'SPDXID: SPDXRef-DOCUMENT', 'DocumentName: t'];
  if (opts.namespace !== false) lines.push('DocumentNamespace: https://example.org/spdxdocs/t');
  if (opts.created) lines.push(`Created: ${opts.created}`);
  for (const creator of opts.creators ?? []) lines.push(`Creator: ${creator}`);
  (opts.packages ?? []).forEach((pkg, i) => {
    lines.push(`PackageName: p${i}`, `SPDXID: SPDXRef-P${i}`, 'PackageDownloadLocation: NOASSERTION');
    if (pkg.version) lines.push(`PackageVersion: ${pkg.version}`);
    if (pkg.supplier) lines.push(`PackageSupplier: ${pkg.supplier}`);
    if (pkg.purpose) lines.push(`PrimaryPackagePurpose: ${pkg.purpose}`);
    if (pkg.license) lines.push(`PackageLicenseConcluded: ${pkg.license}`);
    if (pkg.purl) lines.push(`ExternalRef: PACKAGE-MANAGER purl ${pkg.purl}`);
  });
  const loaded = loadedFromText('t.spdx', lines.join('\n') + '\n');
  return { ws: addDocument(emptyWorkspace, loaded).workspace, loaded };
}

function resultById(report: ReturnType<typeof evaluateProfile>, id: string) {
  return report.results.find((r) => r.id === id)!;
}

describe('evaluateProfile — document checks', () => {
  it('document-field presence, pattern, and values', () => {
    const { ws, loaded } = docFrom({ creators: ['Organization: ACME Corp', 'Tool: gen-1'] });
    const report = evaluateProfile(
      ws,
      loaded,
      profileOf(
        { id: 'present', type: 'document-field', field: 'creators' },
        { id: 'rx-hit', type: 'document-field', field: 'namespace', pattern: '^https://example\\.org/' },
        { id: 'rx-miss', type: 'document-field', field: 'namespace', pattern: '^https://sbom\\.corp/' },
        { id: 'enum-miss', type: 'document-field', field: 'dataLicense', values: ['CC0-1.0'] },
        // creators: SOME quantifier — one matching entry suffices
        { id: 'some', type: 'document-field', field: 'creators', pattern: '^Organization: ' },
      ),
    );
    expect(resultById(report, 'present').pass).toBe(true);
    expect(resultById(report, 'present').actual).toContain('ACME');
    expect(resultById(report, 'rx-hit').pass).toBe(true);
    expect(resultById(report, 'rx-miss').pass).toBe(false);
    expect(resultById(report, 'enum-miss').pass).toBe(false); // dataLicense missing entirely
    expect(resultById(report, 'some').pass).toBe(true);
  });

  it('relationships minCount and created-recency with injected clock', () => {
    const { ws, loaded } = docFrom({ created: '2026-01-01T00:00:00Z' });
    const now = Date.parse('2026-01-31T00:00:00Z');
    const report = evaluateProfile(
      ws,
      loaded,
      profileOf(
        { id: 'rel', type: 'relationships' },
        { id: 'fresh-30', type: 'created-recency', maxAgeDays: 30 },
        { id: 'fresh-29', type: 'created-recency', maxAgeDays: 29 },
      ),
      { now },
    );
    expect(resultById(report, 'rel').pass).toBe(false); // no relationships in doc
    expect(resultById(report, 'fresh-30').pass).toBe(true); // exactly 30 days — boundary inclusive
    expect(resultById(report, 'fresh-29').pass).toBe(false);
  });

  it('created-recency fails on missing created', () => {
    const { ws, loaded } = docFrom({});
    const report = evaluateProfile(ws, loaded, profileOf({ id: 'r', type: 'created-recency', maxAgeDays: 30 }));
    expect(resultById(report, 'r').pass).toBe(false);
    expect(resultById(report, 'r').actual).toBe('missing');
  });
});

describe('evaluateProfile — package coverage', () => {
  it('gates by exact cross-multiplication, not rounded percent', () => {
    // 19/20 = 95% exactly → passes 95; 18/19 ≈ 94.7% displays as 95 but fails 95.
    const nineteenOfTwenty = docFrom({
      packages: Array.from({ length: 20 }, (_, i) => (i < 19 ? { version: '1.0' } : {})),
    });
    const eighteenOfNineteen = docFrom({
      packages: Array.from({ length: 19 }, (_, i) => (i < 18 ? { version: '1.0' } : {})),
    });
    const gate = profileOf({ id: 'v', type: 'package-coverage', field: 'version', threshold: 95 });

    const pass = evaluateProfile(nineteenOfTwenty.ws, nineteenOfTwenty.loaded, gate);
    expect(resultById(pass, 'v').pass).toBe(true);
    expect(resultById(pass, 'v').coverage).toMatchObject({ satisfied: 19, total: 20, percent: 95 });

    const fail = evaluateProfile(eighteenOfNineteen.ws, eighteenOfNineteen.loaded, gate);
    expect(resultById(fail, 'v').pass).toBe(false);
    expect(resultById(fail, 'v').coverage?.percent).toBe(95); // display rounds up, gate is exact
  });

  it('threshold edges: 0 always passes, 100 needs all, absent is informational', () => {
    const { ws, loaded } = docFrom({ packages: [{ version: '1' }, {}] });
    const report = evaluateProfile(
      ws,
      loaded,
      profileOf(
        { id: 'zero', type: 'package-coverage', field: 'version', threshold: 0 },
        { id: 'hundred', type: 'package-coverage', field: 'version', threshold: 100 },
        { id: 'info', type: 'package-coverage', field: 'version' },
      ),
    );
    expect(resultById(report, 'zero').pass).toBe(true);
    expect(resultById(report, 'hundred').pass).toBe(false);
    expect(resultById(report, 'info').pass).toBe(true);
    expect(resultById(report, 'info').coverage?.threshold).toBeUndefined();
    expect(report.gatedPassed).toBe(1);
    expect(report.gatedFailed).toBe(1);
    expect(report.informational).toBe(1);
  });

  it('vacuous pass on documents without packages', () => {
    const { ws, loaded } = docFrom({});
    const report = evaluateProfile(
      ws,
      loaded,
      profileOf({ id: 'v', type: 'package-coverage', field: 'version', threshold: 100 }),
    );
    expect(report.packagesTotal).toBe(0);
    expect(resultById(report, 'v').pass).toBe(true);
    expect(resultById(report, 'v').coverage).toMatchObject({ satisfied: 0, total: 0, percent: 100 });
  });

  it('NOASSERTION suppliers do not count; pattern and values filter coverage', () => {
    const { ws, loaded } = docFrom({
      packages: [
        { supplier: 'Organization: ACME Corp', purpose: 'APPLICATION' },
        { supplier: 'Organization: Other Inc', purpose: 'CONTAINER' },
        { supplier: 'NOASSERTION', purpose: 'LIBRARY' },
      ],
    });
    const report = evaluateProfile(
      ws,
      loaded,
      profileOf(
        { id: 'sup', type: 'package-coverage', field: 'supplier' },
        { id: 'acme', type: 'package-coverage', field: 'supplier', pattern: '^Organization: ACME' },
        { id: 'purposes', type: 'package-coverage', field: 'purpose', values: ['APPLICATION', 'CONTAINER'] },
      ),
    );
    expect(resultById(report, 'sup').coverage?.satisfied).toBe(2);
    expect(resultById(report, 'acme').coverage?.satisfied).toBe(1);
    expect(resultById(report, 'purposes').coverage?.satisfied).toBe(2);
  });
});

describe('NTIA profile parity with documentQuality', () => {
  const fixtures = [
    'minimal.spdx',
    'minimal.spdx.json',
    'quirks.spdx',
    'syft-style.spdx.json',
    'trivy-style.spdx.json',
    'cascade/root.spdx',
    'cascade/mid.spdx',
    'cascade/leaf.spdx.json',
  ];

  it.each(fixtures)('matches on %s', (name) => {
    const loaded = loadFixtureDocument(name);
    const ws = addDocument(emptyWorkspace, loaded).workspace;
    const quality = documentQuality(ws, loaded);
    const report = evaluateProfile(ws, loaded, NTIA_PROFILE);

    expect(resultById(report, 'creators').pass).toBe(quality.document.hasCreators);
    expect(resultById(report, 'created').pass).toBe(quality.document.hasCreated);
    expect(resultById(report, 'namespace').pass).toBe(quality.document.hasNamespace);
    expect(resultById(report, 'relationships').pass).toBe(quality.document.hasRelationships);

    expect(report.packagesTotal).toBe(quality.packages.total);
    expect(resultById(report, 'pkg-version').coverage?.satisfied).toBe(quality.packages.withVersion);
    expect(resultById(report, 'pkg-supplier').coverage?.satisfied).toBe(quality.packages.withSupplier);
    expect(resultById(report, 'pkg-unique-id').coverage?.satisfied).toBe(quality.packages.withUniqueId);
    expect(resultById(report, 'pkg-checksum').coverage?.satisfied).toBe(quality.packages.withChecksum);
    expect(resultById(report, 'pkg-license').coverage?.satisfied).toBe(quality.packages.withLicense);
  });
});

describe('profileReportToMarkdown', () => {
  it('renders header, checkboxes, coverage table, and issues', () => {
    const { ws, loaded } = docFrom({
      creators: ['Organization: ACME'],
      packages: [{ version: '1' }, {}],
    });
    const report = evaluateProfile(
      ws,
      loaded,
      profileOf(
        { id: 'c', type: 'document-field', field: 'creators', label: 'Author' },
        { id: 'v', type: 'package-coverage', field: 'version', threshold: 100, label: 'Version' },
      ),
    );
    const md = profileReportToMarkdown(report, {
      docName: 't',
      sourceFileName: 't.spdx',
      issues: { danglingLocalRefs: 1, unresolvedStructuralRefs: 0, duplicateSpdxIds: 0 },
      generatedAt: '2026-07-11',
    });
    expect(md).toContain('# Quality report: t');
    expect(md).toContain('**Test**');
    expect(md).toContain('1/2 gated checks passed');
    expect(md).toContain('- [x] Author');
    expect(md).toContain('| Version | 1/2 | 50% | ≥ 100% | **fail** |');
    expect(md).toContain('1 dangling relationship target(s)');
  });
});

describe('OCM essentials profile on a component descriptor', () => {
  it('gates version coverage and meters digests/access informationally', async () => {
    const { OCM_ESSENTIALS_PROFILE } = await import('./ocm');
    const { loadFixtureDocument } = await import('../test-fixtures');
    const { addDocument, emptyWorkspace } = await import('../workspace/workspace');
    const loaded = loadFixtureDocument('ocm/cd-v2.yaml');
    const { workspace } = addDocument(emptyWorkspace, loaded);

    const report = evaluateProfile(workspace, loaded, OCM_ESSENTIALS_PROFILE);
    expect(report.profileName).toBe('OCM component essentials');
    expect(report.packagesTotal).toBeGreaterThan(0);

    const version = report.results.find((r) => r.id === 'res-version')!;
    expect(version.coverage?.threshold).toBe(100);
    expect(version.pass).toBe(true); // every fixture artifact carries a version

    const digest = report.results.find((r) => r.id === 'res-digest')!;
    expect(digest.coverage?.threshold).toBeUndefined(); // informational meter
    expect(digest.coverage!.total).toBe(report.packagesTotal);

    const provider = report.results.find((r) => r.id === 'provider')!;
    expect(provider.pass).toBe(true);
  });
});
