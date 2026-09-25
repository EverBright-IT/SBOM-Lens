import type { ComplianceProfile } from './model';
import { PROFILE_SCHEMA_V5 } from './model';

/**
 * PCI DSS v4.0.1, Requirement 12.3.3 (mandatory since 31 March 2025):
 * "Cryptographic cipher suites and protocols in use are documented and
 * reviewed at least once every 12 months, including at least the following:
 * An up-to-date inventory of all cryptographic cipher suites and protocols
 * in use, including purpose and where used; active monitoring of industry
 * trends regarding continued viability of all cryptographic cipher suites
 * and protocols in use; documentation of a plan to respond to anticipated
 * changes in cryptographic vulnerabilities."
 *
 * The inventory part is what a CBOM can carry: protocols with their version
 * and cipher suites, the suites naming their algorithms, and relationships
 * that say where a protocol is used. Review cadence, trend monitoring and
 * the response plan are organisational and stay with the assessor.
 */
export const CRYPTO_PCI_PROFILE: ComplianceProfile = {
  schema: PROFILE_SCHEMA_V5,
  name: 'PCI DSS 12.3.3: cipher suite and protocol inventory',
  specUrl: 'https://www.pcisecuritystandards.org/document_library/',
  requires: { spec: 'cdx-1.6' },
  description:
    'Measures the inventory part of PCI DSS v4.0.1 Requirement 12.3.3 ' +
    '(mandatory since 31 March 2025), which asks for an up-to-date ' +
    'inventory of all cryptographic cipher suites and protocols in use, ' +
    'including purpose and where used, reviewed at least once every 12 ' +
    'months, together with monitoring of industry trends and a plan to ' +
    'respond to anticipated changes. A CycloneDX CBOM can carry the ' +
    'inventory: this profile meters whether every protocol asset states ' +
    'its version and lists its cipher suites, whether the ' +
    'algorithms the suites rely on are described (family and parameter ' +
    'set), and whether relationships say where a protocol is used. The ' +
    'review cadence, the trend monitoring and the response plan cannot be ' +
    'read off a file and remain with the assessor; nothing gates except ' +
    'the format baseline. A BOM without protocol assets reads none in scope.',
  checks: [
    { id: 'protocol-version', type: 'crypto-coverage', field: 'protocolVersion', assetTypes: ['protocol'], label: 'Protocols: version stated' },
    { id: 'protocol-cipher-suites', type: 'crypto-coverage', field: 'cipherSuites', assetTypes: ['protocol'], label: 'Protocols: cipher suites listed' },
    { id: 'protocol-related', type: 'crypto-coverage', field: 'related', assetTypes: ['protocol'], label: 'Protocols: related algorithms or keys linked' },
    { id: 'algorithm-family', type: 'crypto-coverage', field: 'family', assetTypes: ['algorithm'], label: 'Algorithms: family named' },
    { id: 'algorithm-parameter-set', type: 'crypto-coverage', field: 'parameterSet', assetTypes: ['algorithm'], label: 'Algorithms: parameter set stated' },
    { id: 'relationships', type: 'relationships', informational: true, label: 'Relationships stated (where a protocol or algorithm is used)' },
  ],
};
