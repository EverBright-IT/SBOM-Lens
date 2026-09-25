import { describe, expect, it } from 'vitest';
import { loadFixture, loadedFromText } from '../../test-fixtures';
import { addDocument, emptyWorkspace } from '../../workspace/workspace';
import { evaluateProfile } from '../../profile/evaluate';
import { CRYPTO_BSI_TR02102_PROFILE } from '../../profile/crypto-bsi-tr02102';
import { CRYPTO_DORA_PROFILE } from '../../profile/crypto-dora';
import { CRYPTO_EU_ROADMAP_PROFILE } from '../../profile/crypto-eu-roadmap';
import { CRYPTO_PCI_PROFILE } from '../../profile/crypto-pci';
import { profileReportToMarkdown } from '../../profile/markdown';
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
const SHA = 'aabb00112233445566778899aabbccddeeff00112233445566778899aabbccdd';

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
        certificationLevel: ['fips140-3-l1'],
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

  it('reads the same CBOM from XML, including the unwrapped repeat elements, fingerprint and authors', () => {
    const json = load('cdx/crypto.cdx.json').loaded.document;
    const xml = load('cdx/crypto.cdx.xml').loaded.document;
    expect(xml.spec.serialization).toBe('xml');
    const cryptoOf = (doc: typeof json) => doc.elements.map((e) => [e.spdxId, e.purpose, e.originator, e.crypto]);
    expect(cryptoOf(xml)).toEqual(cryptoOf(json));
    expect(xml.relationships.filter((r) => r.type === 'PROVIDES')).toHaveLength(5);
    expect(byRef(xml)['alg-aes']!.crypto!.algorithm?.certificationLevel).toEqual(['fips140-3-l1']);
    expect(byRef(xml)['cert-server']!.crypto!.certificate?.fingerprint).toEqual({ algorithm: 'SHA-256', value: SHA });
    expect(byRef(xml)['lib-openssl']!.originator).toBe('OpenSSL Project');
  });

  it('reads 1.6 XML protocol cryptoRef elements and dependencies nested deeper than one level', () => {
    const xml = [
      '<?xml version="1.0"?>',
      '<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">',
      '  <components>',
      '    <component type="cryptographic-asset" bom-ref="tls"><name>TLS</name>',
      '      <cryptoProperties><assetType>protocol</assetType>',
      '        <protocolProperties><type>tls</type><version>1.2</version><cryptoRef>alg-aes</cryptoRef></protocolProperties>',
      '      </cryptoProperties>',
      '    </component>',
      '    <component type="library" bom-ref="a"><name>a</name></component>',
      '    <component type="library" bom-ref="b"><name>b</name></component>',
      '    <component type="library" bom-ref="c"><name>c</name></component>',
      '  </components>',
      '  <dependencies>',
      '    <dependency ref="a"><dependency ref="b"><dependency ref="c"/></dependency></dependency>',
      '  </dependencies>',
      '</bom>',
    ].join('\n');
    const result = parseDocument({ fileName: 'legacy.cdx.xml', text: xml, sha1: 'f'.repeat(40), byteSize: xml.length });
    const e = byRef(result.document!);
    expect(e['tls']!.crypto?.related).toEqual([{ type: 'protocolCrypto', ref: 'alg-aes' }]);
    const deps = result
      .document!.relationships.filter((r) => r.type === 'DEPENDS_ON')
      .map((r) => [r.from.kind === 'local' ? r.from.spdxId : '?', r.to.kind === 'local' ? r.to.spdxId : '?'])
      .sort();
    expect(deps).toEqual([
      ['a', 'b'],
      ['b', 'c'],
    ]);
    // cryptoRef is the 1.6 field: no deprecation finding on a 1.6 BOM.
    expect(result.diagnostics.map((d) => d.code)).not.toContain('CDX_SCHEMA_CRYPTO_DEPRECATED_FIELD');
  });

  it('notes a cryptographic-asset component without cryptoProperties instead of calling it a schema violation', () => {
    const bom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      version: 1,
      components: [{ type: 'cryptographic-asset', 'bom-ref': 'x', name: 'x' }],
    });
    const result = parseDocument({ fileName: 'bare.cdx.json', text: bom, sha1: '1'.repeat(40), byteSize: bom.length });
    const codes = result.diagnostics.map((d) => d.code);
    expect(codes).toContain('CDX_CRYPTO_PROPERTIES_MISSING');
    expect(codes).not.toContain('CDX_SCHEMA_CRYPTO_MISSING_ASSET_TYPE');
  });

  it('names a registry family the 1.7 JSON-schema enum lacks, and keeps a BOM-Link with a malformed escape verbatim', () => {
    const bom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      version: 1,
      components: [
        {
          type: 'cryptographic-asset',
          'bom-ref': 'kdf',
          name: 'TLS PRF',
          cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'kdf', algorithmFamily: 'TLS-PRF' } },
        },
        {
          type: 'library',
          'bom-ref': 'lib',
          name: 'lib',
          externalReferences: [{ type: 'bom', url: 'urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#%E0%A4%A' }],
        },
      ],
    });
    const result = parseDocument({ fileName: 'enum.cdx.json', text: bom, sha1: '2'.repeat(40), byteSize: bom.length });
    expect(result.document).not.toBeNull();
    const finding = result.diagnostics.find((d) => d.code === 'CDX_SCHEMA_CRYPTO_UNKNOWN_FAMILY')!;
    expect(finding.message).toContain('TLS-PRF (in the registry, not in the 1.7 JSON-schema enum)');
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
    expect(r['pq-kem-parameter-set']!.coverage).toMatchObject({ satisfied: 1, total: 2 }); // ML-KEM-768 named; ECDH is not
    expect(r['ml-kem-parameter-set']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['key-agreement-quantum-safe']!.coverage).toMatchObject({ satisfied: 1, total: 2 }); // ML-KEM of ECDH + ML-KEM
    expect(r['block-cipher-aes']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['pq-signature']!.coverage).toMatchObject({ satisfied: 0, total: 1 });
    expect(r['ml-dsa-parameter-set']!.coverage).toMatchObject({ satisfied: 0, total: 0 });
    expect(r['ml-dsa-parameter-set']!.pass).toBe(true);
  });

  it('never rates: no verdict vocabulary in any label or description', () => {
    const verdicts = /insecure|unsafe|non-compliant|advisable|weak|broken|compliant with/i;
    for (const profile of all) {
      expect(profile.description).not.toMatch(verdicts);
      for (const check of profile.checks) expect(check.label ?? '').not.toMatch(verdicts);
    }
  });

  it('reads names where 1.6 has no family field, and family rows say none in scope there', () => {
    const bom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [
        { type: 'cryptographic-asset', 'bom-ref': 'aes', name: 'AES-128-GCM', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'ae', parameterSetIdentifier: '128', mode: 'gcm' } } },
        { type: 'cryptographic-asset', 'bom-ref': 'kem', name: 'mlkem768', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'kem' } } },
        { type: 'cryptographic-asset', 'bom-ref': 'sig', name: 'RSA-2048', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'signature', parameterSetIdentifier: '2048' } } },
        { type: 'cryptographic-asset', 'bom-ref': 'hash', name: 'sha256', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'hash' } } },
      ],
    });
    const loaded = loadedFromText('legacy.cdx.json', bom);
    const ws = addDocument(emptyWorkspace, loaded).workspace;
    const report = evaluateProfile(ws, loaded, CRYPTO_BSI_TR02102_PROFILE);
    const r = Object.fromEntries(report.results.map((x) => [x.id, x]));
    expect(r['aes-key-length']!.coverage).toMatchObject({ satisfied: 0, total: 0 }); // the families filter needs 1.7 algorithmFamily
    expect(r['block-cipher-aes']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['key-agreement-quantum-safe']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['pq-kem-parameter-set']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(r['pq-signature']!.coverage).toMatchObject({ satisfied: 0, total: 1 });
    expect(r['hash-family']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(report.cryptoAssetsTotal).toBe(4);
    expect(report.noneInScope).toBeGreaterThan(0);
    const meters = report.results.filter((x) => x.kind === 'coverage');
    expect(meters.every((x) => x.subject === 'crypto')).toBe(true);
    const eu = Object.fromEntries(evaluateProfile(ws, loaded, CRYPTO_EU_ROADMAP_PROFILE).results.map((x) => [x.id, x]));
    expect(eu['quantum-safe-kem']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    expect(eu['algorithm-family']!.coverage).toMatchObject({ satisfied: 0, total: 4 });
  });

  it('compares crypto values case-insensitively and accepts an algorithm-typed signature link', () => {
    const bom = JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      version: 1,
      components: [
        { type: 'cryptographic-asset', 'bom-ref': 'sig', name: 'ECDSA', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'signature', algorithmFamily: 'ECDSA', ellipticCurve: 'nist/P-384' } } },
        { type: 'cryptographic-asset', 'bom-ref': 'cert', name: 'leaf', cryptoProperties: { assetType: 'certificate', certificateProperties: { subjectName: 'CN=leaf', relatedCryptographicAssets: [{ type: 'algorithm', ref: 'sig' }] } } },
        { type: 'cryptographic-asset', 'bom-ref': 'aes', name: 'AES', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'block-cipher', algorithmFamily: 'aes', mode: 'GCM' } } },
        { type: 'cryptographic-asset', 'bom-ref': 'oid-curve', name: 'ECDH', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'key-agree', algorithmFamily: 'ECDH', ellipticCurve: '1.2.840.10045.3.1.7' } } },
      ],
    });
    const loaded = loadedFromText('mixed.cdx.json', bom);
    const ws = addDocument(emptyWorkspace, loaded).workspace;
    const dora = Object.fromEntries(evaluateProfile(ws, loaded, CRYPTO_DORA_PROFILE).results.map((x) => [x.id, x]));
    expect(dora['certificate-signature']!.coverage).toMatchObject({ satisfied: 1, total: 1 });
    const tr = Object.fromEntries(evaluateProfile(ws, loaded, CRYPTO_BSI_TR02102_PROFILE).results.map((x) => [x.id, x]));
    expect(tr['aes-mode']!.coverage).toMatchObject({ satisfied: 1, total: 1 }); // "GCM" against the profile's "gcm"
    // P-384 counts; an OID in place of a curve name does not match a bit length by accident.
    expect(tr['ec-order']!.coverage).toMatchObject({ satisfied: 1, total: 2 });
  });

  it('splits package and crypto meters in the Markdown export and marks informational facts', () => {
    const { ws, loaded } = load('cdx/crypto.cdx.json');
    const md = profileReportToMarkdown(evaluateProfile(ws, loaded, CRYPTO_PCI_PROFILE), { docName: 'x' });
    expect(md).toContain('## Cryptographic asset coverage (8 assets)');
    expect(md).not.toContain('## Package coverage');
    expect(md).toContain('(informational)');
  });

  it('reads none in scope on an SBOM without cryptographic assets', () => {
    const { ws, loaded } = load('cdx/minimal.cdx.json');
    const report = evaluateProfile(ws, loaded, CRYPTO_EU_ROADMAP_PROFILE);
    const meters = report.results.filter((x) => x.kind === 'coverage');
    expect(meters.length).toBeGreaterThan(5);
    expect(meters.every((x) => x.coverage?.total === 0 && x.pass)).toBe(true);
  });
});
