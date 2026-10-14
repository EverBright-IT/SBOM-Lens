import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { readOcmBundle } from '../parse/ocm/bundle';
import { cd, ctfOf } from '../parse/ocm/test-ctf';
import { acceptanceReport } from './report';
import { verifyRawSignatures } from './verify';

function fixture(name: string): Uint8Array {
  return new Uint8Array(readFileSync(new URL(`../../fixtures/${name}`, import.meta.url)));
}

describe('verifyRawSignatures', () => {
  it('verifies the CLI-signed fixture descriptor against the test public key', async () => {
    const root = JSON.parse(new TextDecoder().decode(fixture('ocm/signed-descriptor.json'))) as Record<string, unknown>;
    const pem = new TextDecoder().decode(fixture('ocm/keys/test-rsa.pub.pem'));
    const results = await verifyRawSignatures(root, pem);
    expect(results).toHaveLength(1);
    expect(results[0]!.verdict).toBe('valid');
  });

  it('returns an empty list for an unsigned root', async () => {
    expect(await verifyRawSignatures({ component: {} }, 'irrelevant')).toEqual([]);
  });
});

describe('acceptanceReport', () => {
  async function openBundle() {
    const signed =
      cd('acme.org/app', '1.0.0', [
        ['acme.org/lib', '2.0.0'],
        ['acme.org/elsewhere', '9.9.9'],
      ]).replace(
        '  resources: []\n',
        '  resources:\n    - name: gateway\n      version: 1.0.0\n      type: ociImage\n      relation: external\n      access:\n        type: ociArtifact\n        imageReference: registry.example.org/acme/gateway:1.0.0\n',
      ) +
      'signatures:\n  - name: acme-test\n    digest:\n      hashAlgorithm: SHA-256\n      normalisationAlgorithm: jsonNormalisation/v4alpha1\n      value: abc123\n    signature:\n      algorithm: RSASSA-PSS\n      value: deadbeef\n      mediaType: application/vnd.ocm.signature.rsa.pss\n';
    const bytes = ctfOf([signed, cd('acme.org/lib', '2.0.0', [])]);
    const result = await readOcmBundle('acme-app.ctf.tar', bytes);
    return result.bundle!;
  }

  it('renders the full Markdown report deterministically', async () => {
    const bundle = await openBundle();
    const { markdown } = acceptanceReport({
      bundle,
      signatures: [
        { cvId: 'acme.org/app@1.0.0', name: 'acme-test', verdict: 'valid', keyLabel: 'acme-release' },
      ],
      toolVersion: '2.0.0-test',
      generatedAt: '2026-10-14T12:00:00Z',
    });
    expect(markdown).toMatchInlineSnapshot(`
      "# Delivery acceptance report

      | | |
      | --- | --- |
      | Delivery | \`acme-app.ctf.tar\` |
      | Layout | CTF |
      | Size | 6.5 KB |
      | Generated | 2026-10-14T12:00:00Z by OCM Lens 2.0.0-test (client-side, nothing uploaded) |

      ## Verdict

      **NEEDS NETWORK TO DEPLOY.** 1 resource(s) live outside the bundle (external access); 1 component reference(s) point outside the bundle.

      - 2 component version(s), 1 root(s)
      - Resources: 0 transported, 1 external, 0 broken, 0 unknown
      - Reference closure: 1 reference(s) open
      - Blob digests: 0 checked, 0 match, 0 mismatch
      - Signatures: 1 of 1 signed component version(s) verified valid
      - SBOMs: 0 of 2 component version(s) carry embedded SBOMs

      ## Component versions

      | Component | Version | Provider | Resources | References | Signed | SBOM |
      | --- | --- | --- | --- | --- | --- | --- |
      | acme.org/app | 1.0.0 | ACME Corp | 1 | 2 (1 open) | yes | - |
      | acme.org/lib | 2.0.0 | ACME Corp | 0 | 0 | - | - |

      ## Transport gaps

      - acme.org/app@1.0.0: resource \`gateway\` (ociImage) is external via \`ociArtifact\` — registry.example.org/acme/gateway:1.0.0
      - acme.org/app@1.0.0: reference \`elsewhere\` → acme.org/elsewhere@9.9.9 is not in this bundle

      ## Integrity (blob digests)

      No resources with bytes in the bundle.

      ## Signatures

      | Component | Signature | Verdict | Key | Detail |
      | --- | --- | --- | --- | --- |
      | acme.org/app@1.0.0 | acme-test | valid | acme-release | - |

      ## Embedded SBOMs

      No embedded SBOMs.

      ## Findings (1)

      - info: 1 reference(s) point outside this bundle (by-reference delivery, or an incomplete closure).
      "
    `);
  });

  it('mirrors the facts into schema-stable JSON', async () => {
    const bundle = await openBundle();
    const { json } = acceptanceReport({
      bundle,
      toolVersion: '2.0.0-test',
      generatedAt: '2026-10-14T12:00:00Z',
    });
    expect(json.schema).toBe('ocm-lens-acceptance-report/v1');
    expect(json.verdict).toEqual({
      airGapReady: false,
      reasons: [
        '1 resource(s) live outside the bundle (external access)',
        '1 component reference(s) point outside the bundle',
      ],
    });
    const cvs = json.componentVersions as { id: string; references: { resolved: boolean }[] }[];
    expect(cvs.map((c) => c.id)).toEqual(['acme.org/app@1.0.0', 'acme.org/lib@2.0.0']);
    expect(cvs[0]!.references.map((r) => r.resolved)).toEqual([true, false]);
    expect(json.signatures).toBeNull();
  });
});
