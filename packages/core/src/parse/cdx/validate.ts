import type { Diagnostic } from '../../model/diagnostics';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import { checksumProblem, createLint, licenseExpressionError } from '../spec-lint';

/**
 * Spec lint for CycloneDX BOMs, the counterpart to the SPDX and OCM ones. The
 * CDX parser is deliberately version-agnostic (it maps 1.x without insisting
 * on a version), so the lint carries the version expectations instead: an
 * unknown specVersion, a serial number that is not a URN, component types
 * outside the vocabulary, digests that cannot be digests.
 */

/** Known CycloneDX specification versions (1.0 through 1.7). */
const SPEC_VERSIONS = new Set(['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7']);

/** component.type vocabulary as of CycloneDX 1.6. */
const COMPONENT_TYPES = new Set([
  'application',
  'framework',
  'library',
  'container',
  'platform',
  'operating-system',
  'device',
  'device-driver',
  'firmware',
  'file',
  'machine-learning-model',
  'data',
  'cryptographic-asset',
]);

const URN_UUID = /^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function validateCdxStructure(root: Record<string, unknown>): Diagnostic[] {
  const lint = createLint();
  const { warn, warnAll } = lint;

  // The parser accepts any specVersion so a future BOM still opens; the lint
  // is where that tolerance gets a voice.
  const specVersion = asString(root.specVersion);
  if (specVersion !== undefined && !SPEC_VERSIONS.has(specVersion)) {
    warn('CDX_SCHEMA_UNKNOWN_SPEC_VERSION', `specVersion "${specVersion}" is not a known CycloneDX version; it was read as 1.x.`);
  }

  // serialNumber is the BOM's identity and the anchor of every BOM-Link, so a
  // malformed one breaks cross-document references.
  const serialNumber = asString(root.serialNumber);
  if (serialNumber !== undefined && !URN_UUID.test(serialNumber)) {
    warn('CDX_SCHEMA_BAD_SERIAL_NUMBER', `serialNumber "${serialNumber}" is not a urn:uuid: URN.`);
  }

  // version counts the revisions of one serialNumber; it is a positive integer.
  const version = root.version;
  if (version !== undefined && (typeof version !== 'number' || !Number.isInteger(version) || version < 1)) {
    warn('CDX_SCHEMA_BAD_VERSION', `version ${JSON.stringify(version)} is not a positive integer.`);
  }

  const badType: string[] = [];
  const badHash: string[] = [];
  const badPurl: string[] = [];
  const badLicense: string[] = [];
  const duplicateRef = new Set<string>();
  const seenRefs = new Set<string>();

  const visit = (component: Record<string, unknown>) => {
    const name = asString(component.name) ?? '(unnamed component)';

    const type = asString(component.type);
    if (type !== undefined && !COMPONENT_TYPES.has(type)) badType.push(`${name} (${type})`);

    // bom-refs address components from dependencies and BOM-Links; a duplicate
    // makes those references ambiguous.
    const bomRef = asString(component['bom-ref']);
    if (bomRef !== undefined) {
      if (seenRefs.has(bomRef)) duplicateRef.add(bomRef);
      else seenRefs.add(bomRef);
    }

    for (const entry of asRecordArray(component.hashes)) {
      const algorithm = asString(entry.alg);
      const content = asString(entry.content);
      if (algorithm === undefined || content === undefined) continue;
      const problem = checksumProblem(algorithm, content);
      if (problem) badHash.push(`${name}: ${problem}`);
    }

    const purl = asString(component.purl);
    if (purl !== undefined && !purl.startsWith('pkg:')) badPurl.push(`${name} (${purl})`);

    for (const entry of asRecordArray(component.licenses)) {
      const expression = asString(entry.expression);
      if (expression !== undefined) {
        const problem = licenseExpressionError(expression);
        if (problem) badLicense.push(`${name}: ${problem}`);
      }
      // license is either an id or a name, never both (the schema says oneOf).
      if (isRecord(entry.license) && asString(entry.license.id) && asString(entry.license.name)) {
        badLicense.push(`${name}: license carries both id and name`);
      }
    }

    for (const nested of asRecordArray(component.components)) visit(nested);
  };

  const metadataComponent = isRecord(root.metadata) ? root.metadata.component : undefined;
  if (isRecord(metadataComponent)) visit(metadataComponent);
  for (const component of asRecordArray(root.components)) visit(component);

  warnAll('CDX_SCHEMA_BAD_COMPONENT_TYPE', badType, (count, list) => `${count} component(s) with a type outside the CycloneDX vocabulary: ${list}.`);
  warnAll('CDX_SCHEMA_DUPLICATE_BOM_REF', [...duplicateRef], (count, list) => `${count} bom-ref(s) are used more than once, which makes references ambiguous: ${list}.`);
  warnAll('CDX_SCHEMA_BAD_HASH', badHash, (count, list) => `${count} hash(es) do not match their algorithm: ${list}.`);
  warnAll('CDX_SCHEMA_BAD_PURL', badPurl, (count, list) => `${count} purl(s) do not start with "pkg:": ${list}.`);
  warnAll('CDX_SCHEMA_BAD_LICENSE_EXPRESSION', badLicense, (count, list) => `${count} license entr(y|ies) are malformed: ${list}.`);

  return lint.diagnostics;
}
