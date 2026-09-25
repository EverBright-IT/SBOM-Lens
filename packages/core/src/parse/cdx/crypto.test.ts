import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../../test-fixtures';
import { addDocument, emptyWorkspace } from '../../workspace/workspace';
import { evaluateProfile } from '../../profile/evaluate';
import { CRYPTO_BSI_TR02102_PROFILE } from '../../profile/crypto-bsi-tr02102';
import { CRYPTO_DORA_PROFILE } from '../../profile/crypto-dora';
import { CRYPTO_EU_ROADMAP_PROFILE } from '../../profile/crypto-eu-roadmap';
import { CRYPTO_PCI_PROFILE } from '../../profile/crypto-pci';
import { validateProfile } from '../../profile/validate';
import { canonicalCurve, isKnownCryptoFamily, isKnownCurve, resolveCryptoFamily } from '../../spec/cdx-crypto-registry';
import { parseDocument } from '../parser';

/**
 * CBOM ingestion: cryptoProperties become the crypto extension from JSON and
 * from XML alike (parity pinned), provides[] becomes PROVIDES, the registry
 * knows its families and curves, and the four crypto profiles count what
 * the fixture states without rating anything.
 */

function load(fixture: string) {
  const loaded = loadedFromText(fixture.split('/').pop()!, loadFixture(fixture));
  return { loaded, ws: addDocument(emptyWorkspace, loaded).workspace };
}

const byRef = (doc: ReturnType<typeof load>['loaded']['document']) => Object.fromEntries(doc.elements.map((e) => [e.spdxId, e]));

describe('cryptoProperties mapping', () => {
  it('reads algorithms, certificates, material and protocols into the crypto extension', () => {
    const { loaded } = load('cdx/crypto.cdx.json');
    const e = byRef(loaded.document);
    expect(e['alg-aes']!.purpose).toBe('CRYPTOGRAPHIC-ASSET');
    expect(e['alg-aes']!.crypto).toEqual({
      assetType: 'algorithm',
      oid: '2.16.840.1.101.3.4.1.46',
      algorithm: {
        primitive: 'ae',
        family: 'AES',
        parameterSet: '256',
        mode: 'gcm',
        executionEnvironment: 'software-plain-ram',
        implementationPlatform: 'x86_64',
        cryptoFunctions: ['encrypt', 'decrypt'],
        classicalSecurityLevel: 256,
        nistQuantumSecurityLevel: 5,
      },
    });
    expect(e['cert-server']!.crypto).toMatchObject({
      assetType: 'certificate',
      certificate: { subjectName: 'CN=vpn.acme.example', notValidAfter: '2027-01-01T00:00:00Z', fileExtension: 'pem', states: ['active'] },
      related: [
        { type: 'signatureAlgorithm', ref: 'alg-rsa' },
        { type: 'subjectPublicKey', ref: 'key-server' },
      ],
    });
    expect(e['key-server']!.crypto).toMatchObject({
      material: { type: 'private-key', state: 'active', size: 3072, securedBy: { mechanism: 'HSM', algorithmRef: 'alg-aes' } },
      related: [{ type: 'algorithm', ref: 'alg-rsa' }],
    });
    expect(e['proto-tls']!.crypto).toMatchObject({
      protocol: { type: 'tls', version: '1.3', cipherSuites: [{ name: 'TLS_AES_256_GCM_SHA384', algorithms: ['alg-aes'], identifiers: ['0x13', '0x02'] }] },
      related: [{ type: 'certificate', ref: 'cert-server' }],
    });
    expect(e['lib-openssl']!.crypto).toBeUndefined();
  });

  it('turns dependencies[].provides into PROVIDES relationships', () => {
    const { loaded } = load('cdx/crypto.cdx.json');
    const provides = loaded.document.relationships.filter((r) => r.type === 'PROVIDES');
    expect(provides).toHaveLength(5);
    expect(provides.every((r) => r.from.kind === 'local' && r.from.spdxId === 'lib-openssl')).toBe(true);
  });

  it('reads the same CBOM from XML', () => {
    const json = load('cdx/crypto.cdx.json').loaded.document;
    const xml = load('cdx/crypto.cdx.xml').loaded.document;
    expect(xml.spec.serialization).toBe('xml');
    const cryptoOf = (doc: typeof json) => doc.elements.map((e) => [e.spdxId, e.purpose, e.crypto]);
    expect(cryptoOf(xml)).toEqual(cryptoOf(json));
    expect(xml.relationships.filter((r) => r.type === 'PROVIDES')).toHaveLength(5);
  });

  it('keeps the 1.6 fields that 1.7 deprecated, without a finding on a 1.6 BOM', () => {
    const bom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [
        {
          type: 'cryptographic-asset',
          'bom-ref': 'ecdsa',
          name: 'ECDSA',
          cryptoProperties: {
            assetType: 'algorithm',
            algorithmProperties: { primitive: 'signature', curve: 'brainpoolP256r1' },
          },
        },
        {
          type: 'cryptographic-asset',
          'bom-ref': 'cert',
          name: 'cert',
          cryptoProperties: {
            assetType: 'certificate',
            certificateProperties: { subjectName: 'CN=x', signatureAlgorithmRef: 'ecdsa', certificateExtension: 'crt' },
          },
        },
      ],
    });
    const result = parseDocument({ fileName: 'legacy.cdx.json', text: bom, sha1: 'd'.repeat(40), byteSize: bom.length });
    const e = byRef(result.document!);
    expect(e['ecdsa']!.crypto?.algorithm?.curve).toBe('brainpoolP256r1');
    expect(e['cert']!.crypto).toMatchObject({ certificate: { fileExtension: 'crt' }, related: [{ type: 'signatureAlgorithm', ref: 'ecdsa' }] });
    expect(result.diagnostics.map((d) => d.code)).not.toContain('CDX_SCHEMA_CRYPTO_DEPRECATED_FIELD');
  });
});

describe('cryptography registry', () => {
  it('knows families exactly and resolves casing for messages', () => {
    expect(isKnownCryptoFamily('AES')).toBe(true);
    expect(isKnownCryptoFamily('aes')).toBe(false);
    expect(resolveCryptoFamily('aes')?.family).toBe('AES');
    expect(resolveCryptoFamily('AES')?.primitives).toContain('block-cipher');
    expect(isKnownCryptoFamily('FrodoKEM')).toBe(false); // BSI-recommended, not in the registry yet
  });

  it('knows curves as category/name and maps bare spellings to a canonical one', () => {
    expect(isKnownCurve('nist/P-256')).toBe(true);
    expect(isKnownCurve('brainpool/brainpoolP256r1')).toBe(true);
    expect(isKnownCurve('P-256')).toBe(false);
    // A bare spelling resolves to ONE of the registry's category/name values
    // for that curve (P-256, prime256v1 and secp256r1 are the same curve).
    expect(canonicalCurve('P-256')).toMatch(/^(nist\/P-256|secg\/secp256r1|x962\/prime256v1)$/);
    expect(isKnownCurve(canonicalCurve('prime256v1')!)).toBe(true);
    expect(canonicalCurve('no-such-curve')).toBeUndefined();
  });
});

describe('crypto profiles', () => {
  const all = [CRYPTO_EU_ROADMAP_PROFILE, CRYPTO_DORA_PROFILE, CRYPTO_PCI_PROFILE, CRYPTO_BSI_TR02102_PROFILE];

  it.each(all.map((p) => [p.name, p] as const))('%s is a valid v5 profile with unique ids', (_name, profile) => {
    const result = validateProfile(profile);
    expect(result.ok, result.ok ? '' : (result as { errors: string[] }).errors.join('; ')).toBe(true);
    expect(profile.requires).toEqual({ spec: 'cdx-1.6' });
  });

  it('counts what the fixture states for the EU roadmap inventory', () => {
    const { ws, loaded } = load('cdx/crypto.cdx.json');
    const report = evaluateProfile(ws, loaded, CRYPTO_EU_ROADMAP_PROFILE);
    const r = Object.fromEntries(report.results.map((x) => [x.id, x]));
    expect(r['format-baseline']!.pass).toBe(true);
    expect(r['asset-type']!.coverage).toMatchObject({ satisfied: 8, total: 8 });
    expect(r['algorithm-family']!.coverage).toMatchObject({ satisfied: 5, total: 5 });
    expect(r['algorithm-security-level']!.coverage).toMatchObject({ satisfied: 2, total: 5 });
    expect(r['quantum-safe-kem']!.coverage).toMatchObject({ satisfied: 1, total: 2 }); // ML-KEM yes, ECDH no
    expect(r['quantum-safe-signature']!.coverage).toMatchObject({ satisfied: 0, total: 1 });
    expect(r['certificate-validity']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['protocol-cipher-suites']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(report.gatedFailed).toBe(0);
  });

  it('meters the DORA certificate register and the PCI protocol inventory', () => {
    const { ws, loaded } = load('cdx/crypto.cdx.json');
    const dora = Object.fromEntries(evaluateProfile(ws, loaded, CRYPTO_DORA_PROFILE).results.map((x) => [x.id, x]));
    expect(dora['certificate-signature']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(dora['material-secured-by']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    const pci = Object.fromEntries(evaluateProfile(ws, loaded, CRYPTO_PCI_PROFILE).results.map((x) => [x.id, x]));
    expect(pci['protocol-version']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(pci['protocol-related']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
  });

  it('cites TR-02102-1 tables and counts matches without rating', () => {
    const { ws, loaded } = load('cdx/crypto.cdx.json');
    const r = Object.fromEntries(evaluateProfile(ws, loaded, CRYPTO_BSI_TR02102_PROFILE).results.map((x) => [x.id, x]));
    expect(r['rsa-modulus']!.coverage).toMatchObject({ satisfied: 1, total: 1 }); // 3072 >= 3000
    expect(r['ec-order']!.coverage).toMatchObject({ satisfied: 1, total: 1 }); // nist/P-256
    expect(r['ec-brainpool']!.coverage).toMatchObject({ satisfied: 0, total: 1 });
    expect(r['aes-key-length']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['aes-mode']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['hash-family']!.coverage).toMatchObject({ satisfied: 0, total: 1 }); // SHA-1 is not SHA-2/SHA-3
    expect(r['hash-length']!.coverage).toMatchObject({ satisfied: 0, total: 0 }); // no SHA-2/3 asset in scope
    expect(r['pq-kem']!.coverage).toMatchObject({ satisfied: 1, total: 1 }); // ML-KEM-768
    expect(r['classical-key-agreement']!.coverage).toMatchObject({ satisfied: 1, total: 2 }); // ECDH of ECDH + ML-KEM
    expect(r['pq-signature-family']!.coverage).toMatchObject({ satisfied: 0, total: 1 });
    expect(r['ml-dsa-parameter-set']!.coverage).toMatchObject({ satisfied: 0, total: 0 });
    expect(r['ml-dsa-parameter-set']!.pass).toBe(true);
    for (const result of Object.values(r)) expect(result.label + (result.coverage ? '' : '')).not.toMatch(/insecure|unsafe|non-compliant/i);
  });

  it('reads none in scope on an SBOM without cryptographic assets', () => {
    const { ws, loaded } = load('cdx/minimal.cdx.json');
    const report = evaluateProfile(ws, loaded, CRYPTO_EU_ROADMAP_PROFILE);
    const meters = report.results.filter((x) => x.kind === 'coverage');
    expect(meters.length).toBeGreaterThan(5);
    expect(meters.every((x) => x.coverage?.total === 0 && x.pass)).toBe(true);
  });
});
