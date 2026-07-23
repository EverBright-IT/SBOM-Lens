import type { Diagnostic } from '../../model/diagnostics';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import type { Tally } from '../spec-lint';
import { checksumProblem, createLint, createTally, isAbsoluteUri } from '../spec-lint';

/**
 * Spec lint for SPDX 3.0.x documents. Deliberately limited to the JSON-LD
 * level — node shape, identifier form, creation info, hashes, relationship
 * completeness, and references that point nowhere. The full 3.x model is
 * expressed in SHACL; reimplementing it would be a second product, and every
 * rule that cannot be checked cheaply would only produce noise.
 *
 * One vocabulary is deliberately NOT checked: relationshipType. SPDX 3 defines
 * its own (camelCase) set, we vendor no list of it, and reusing the 2.3
 * vocabulary would flag legal 3.x types like `hasDeclaredLicense`. A wrong
 * warning is worse than a missing one.
 *
 * Nor is @context checked: content detection already requires an
 * spdx.org/rdf/3.x context, so a document without one never reaches this
 * parser. A rule that cannot fire is worse than no rule, because it suggests
 * a check that is not actually happening.
 */

/** Concrete element types we know require creationInfo (§ 5.2 Element). */
const ELEMENT_TYPES = new Set([
  'SpdxDocument',
  'Sbom',
  'Bom',
  'Package',
  'File',
  'Snippet',
  'Relationship',
  'LifecycleScopedRelationship',
  'Person',
  'Organization',
  'Tool',
  'Agent',
  'SoftwareAgent',
]);

/** `software_Package` and `Package` are the same type in different profiles. */
function localType(node: Record<string, unknown>): string {
  const type = asString(node.type) ?? asString(node['@type']) ?? '';
  const underscore = type.lastIndexOf('_');
  return underscore === -1 ? type : type.slice(underscore + 1);
}

function nodeId(node: Record<string, unknown>): string | undefined {
  return asString(node.spdxId) ?? asString(node['@id']);
}

export function validateSpdx3Structure(
  graph: Record<string, unknown>[],
  byId: Map<string, Record<string, unknown>>,
): Diagnostic[] {
  const lint = createLint();
  const { warn } = lint;

  const missingType = createTally();
  const badId = createTally();
  const missingCreationInfo = createTally();
  const badHash = createTally();
  const incompleteRelationship = createTally();

  for (const node of graph) {
    const type = localType(node);
    const id = nodeId(node);
    const label = id ?? `(${type || 'untyped node'})`;

    if (type === '') missingType.add(id ?? '(node without spdxId)');

    // § 5.2: spdxId is an IRI. Blank nodes (`_:x`) are legal JSON-LD and used
    // by real generators for CreationInfo, so they are not IRIs and not wrong.
    if (id !== undefined && !id.startsWith('_:') && !isAbsoluteUri(id)) badId.add(id);

    // Every Element carries creationInfo; helper objects (CreationInfo, Hash,
    // ExternalMap, ...) do not. Checked against a whitelist of element types so
    // that unknown types never produce a false warning.
    if (ELEMENT_TYPES.has(type) && node.creationInfo === undefined) missingCreationInfo.add(label);

    for (const problem of hashProblems(node.verifiedUsing)) badHash.add(`${label}: ${problem}`);

    if (type === 'Relationship' || type === 'LifecycleScopedRelationship') {
      const missing = ['from', 'relationshipType'].filter((field) => node[field] === undefined);
      if (missing.length > 0) incompleteRelationship.add(`${label} (no ${missing.join('/')})`);
    }
  }

  lint.warnTally('SPDX3_SCHEMA_MISSING_TYPE', missingType, (count, list) => `${count} graph node(s) without a type: ${list}.`);
  lint.warnTally('SPDX3_SCHEMA_BAD_SPDXID', badId, (count, list) => `${count} spdxId(s) are neither an absolute IRI nor a blank node: ${list}.`);
  lint.warnTally(
    'SPDX3_SCHEMA_MISSING_CREATION_INFO',
    missingCreationInfo,
    (count, list) => `${count} element(s) without creationInfo, which SPDX 3 requires on every element: ${list}.`,
  );
  lint.warnTally('SPDX3_SCHEMA_BAD_HASH', badHash, (count, list) => `${count} hash(es) do not match their algorithm: ${list}.`);
  lint.warnTally(
    'SPDX3_SCHEMA_INCOMPLETE_RELATIONSHIP',
    incompleteRelationship,
    (count, list) => `${count} relationship(s) without from/relationshipType: ${list}.`,
  );

  validateSpecVersion(graph, warn);
  validateReferences(graph, byId, lint);

  return lint.diagnostics;
}

/** § 5.3 CreationInfo: specVersion states which model version applies. */
function validateSpecVersion(graph: Record<string, unknown>[], warn: (code: string, message: string) => void): void {
  for (const node of graph) {
    if (localType(node) !== 'CreationInfo') continue;
    const specVersion = asString(node.specVersion);
    if (specVersion === undefined) {
      warn('SPDX3_SCHEMA_BAD_SPEC_VERSION', 'CreationInfo has no specVersion.');
    } else if (!/^3\.\d+(\.\d+)?$/.test(specVersion)) {
      warn('SPDX3_SCHEMA_BAD_SPEC_VERSION', `CreationInfo specVersion "${specVersion}" is not an SPDX 3 version.`);
    }
    return; // one report is enough; documents carry one creation info in practice
  }
}

/**
 * Relationship ends must resolve: either inside this graph, or through an
 * ExternalMap import that names the external IRI. An end pointing nowhere
 * silently loses an edge downstream.
 */
function validateReferences(
  graph: Record<string, unknown>[],
  byId: Map<string, Record<string, unknown>>,
  lint: { warnTally: (code: string, tally: Tally, render: (count: number, sample: string) => string) => void },
): void {
  const imported = new Set<string>();
  for (const node of graph) {
    for (const entry of asRecordArray(node.import)) {
      const externalId = asString(entry.externalSpdxId);
      if (externalId) imported.add(externalId);
    }
  }

  const dangling = createTally({ unique: true });
  const resolves = (ref: string) => ref.startsWith('_:') || byId.has(ref) || imported.has(ref);

  for (const node of graph) {
    const type = localType(node);
    if (type !== 'Relationship' && type !== 'LifecycleScopedRelationship') continue;
    const ends = [asString(node.from), ...toRefs(node.to)].filter((r): r is string => r !== undefined);
    for (const ref of ends) {
      if (!resolves(ref)) dangling.add(ref);
    }
  }

  lint.warnTally(
    'SPDX3_SCHEMA_DANGLING_REF',
    dangling,
    (count, list) => `${count} relationship end(s) point at an spdxId that is neither in the graph nor imported: ${list}.`,
  );
}

/** `to` is a list in 3.x, but single-value shorthand appears in the wild. */
function toRefs(value: unknown): (string | undefined)[] {
  if (Array.isArray(value)) return value.map((v) => (typeof v === 'string' ? v : isRecord(v) ? nodeId(v) : undefined));
  return [typeof value === 'string' ? value : isRecord(value) ? nodeId(value) : undefined];
}

function hashProblems(value: unknown): string[] {
  const problems: string[] = [];
  for (const entry of asRecordArray(value)) {
    const algorithm = asString(entry.algorithm);
    const hashValue = asString(entry.hashValue);
    if (algorithm === undefined || hashValue === undefined) continue; // dropped by the parser
    const problem = checksumProblem(algorithm, hashValue);
    if (problem) problems.push(problem);
  }
  return problems;
}
