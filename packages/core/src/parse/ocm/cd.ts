import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import type {
  Checksum,
  ExternalDocumentRef,
  Relationship,
  SbomDocument,
  SbomElement,
  SpecInfo,
} from '../../model/document';
import type { OcmBlobInfo, OcmDigest, OcmLabel, OcmRepositoryContext, OcmSignatureInfo } from '../../model/ocm';
import { makeDocumentId, makeElementId } from '../../model/ids';
import { asRecordArray, asString, isRecord } from '../../util/narrow';
import type { ParseResult, SourceInput } from '../parser';
import { dedupeBySpdxId } from '../spdx2/common';

/**
 * OCM Component Descriptors map onto the SPDX document model so the whole
 * app (tree, map, inventory, diff, profiles) works on deliveries unchanged:
 * component → document + root pseudo-package, resources/sources → package
 * elements, componentReferences → external document refs with a synthetic
 * `ocm://name/version` namespace (two loaded CDs auto-link via the existing
 * namespace matcher), SBOM resources → refs the archive walker wires up by
 * byte checksum. Read-only: blob digests inside a loaded delivery are checked
 * against the actual bytes; component and reference digests are displayed,
 * not verified (signature verification is roadmap).
 */

export interface OcmBlobContext {
  /** Resolve a localBlob access to its bytes' SHA-1, when extracted. */
  sbomChecksumFor(localReference: string): string | undefined;
  /**
   * Inspection summary for one artifact's localBlob, when available. Keyed
   * by the artifact's own raw node (NOT the localReference): two artifacts
   * may share a blob but declare different digests, so the verdict is theirs.
   */
  blobInfoFor?(artifact: Record<string, unknown>): OcmBlobInfo | undefined;
}

export function ocmNamespace(name: string, version: string): string {
  return `ocm://${name}/${version}`;
}

interface NormalizedCd {
  schemaLabel: string;
  name: string;
  version: string;
  provider?: string;
  providerLabels?: OcmLabel[];
  creationTime?: string;
  labels?: OcmLabel[];
  repositoryContexts: Record<string, unknown>[];
  resources: Record<string, unknown>[];
  sources: Record<string, unknown>[];
  references: Record<string, unknown>[];
  signatures: Record<string, unknown>[];
  /** The verbatim component node — the root element's raw/source view. */
  componentNode: Record<string, unknown>;
  v3: boolean;
}

export function parseOcmComponentDescriptor(
  input: SourceInput,
  root: Record<string, unknown>,
  serialization: 'json' | 'yaml',
  blobContext?: OcmBlobContext,
): ParseResult {
  const diagnostics: Diagnostic[] = [];
  const cd = normalize(root);
  if (!cd) {
    return {
      document: null,
      diagnostics: [diag('error', 'OCM_CD_MALFORMED', 'Component descriptor has no component name/version.')],
    };
  }
  if (cd.v3) {
    diagnostics.push(
      diag('info', 'OCM_V3ALPHA1', 'OCM v3alpha1 descriptor: mapped best-effort (v2 is the primary format).'),
    );
  }

  const namespace = ocmNamespace(cd.name, cd.version);
  const documentId = makeDocumentId(namespace, input.sha1);
  const spec: SpecInfo = {
    model: 'ocm',
    version: `OCM-CD/${cd.v3 ? 'v3alpha1' : 'v2'}`,
    serialization,
  };

  const elements: SbomElement[] = [];
  const relationships: Relationship[] = [];
  const externalDocumentRefs: ExternalDocumentRef[] = [];
  const usedRefNames = new Set<string>();
  const supplier = cd.provider ? `Organization: ${cd.provider}` : undefined;

  const rootSpdxId = 'SPDXRef-component';
  elements.push({
    id: makeElementId(documentId, rootSpdxId),
    documentId,
    spdxId: rootSpdxId,
    kind: 'package',
    name: cd.name,
    version: cd.version,
    supplier,
    purpose: 'APPLICATION',
    ocm: { role: 'component', labels: cd.labels },
    raw: { kind: 'json', value: cd.componentNode },
  });
  relationships.push({
    from: { kind: 'local', spdxId: 'SPDXRef-DOCUMENT' },
    type: 'DESCRIBES',
    to: { kind: 'local', spdxId: rootSpdxId },
  });

  const unsupportedAccess = new Map<string, number>();
  let checkedBlobs = 0;

  const addArtifact = (raw: Record<string, unknown>, role: 'resource' | 'source'): void => {
    const name = asString(raw.name);
    if (!name) {
      diagnostics.push(diag('warning', 'OCM_RESOURCE_MALFORMED', `A ${role} without a name was skipped.`));
      return;
    }
    const spdxId = sanitizeSpdxId(`SPDXRef-${role}-${name}`, elements);
    const access = isRecord(raw.access) ? raw.access : {};
    const accessType = asString(access.type)?.toLowerCase() ?? '';
    const version = asString(raw.version);
    const blob = blobContext?.blobInfoFor?.(raw);
    if (blob?.digestCheck === 'mismatch') {
      diagnostics.push(
        diag(
          'warning',
          'OCM_DIGEST_MISMATCH',
          `${role === 'source' ? 'Source' : 'Resource'} "${name}": the blob in this delivery does not match its declared digest.`,
        ),
      );
    }
    if (blob?.digestCheck === 'match' || blob?.digestCheck === 'mismatch') checkedBlobs++;
    const element: SbomElement = {
      id: makeElementId(documentId, spdxId),
      documentId,
      spdxId,
      kind: 'package',
      name,
      version,
      supplier: raw.relation === 'local' ? supplier : undefined,
      purpose: role === 'source' ? 'SOURCE' : asString(raw.type) ?? undefined,
      downloadLocation: artifactLocation(access),
      checksums: digestChecksum(raw.digest),
      purl: ociPurl(access, version),
      ocm: {
        role,
        type: asString(raw.type),
        relation: asString(raw.relation),
        extraIdentity: stringRecord(raw.extraIdentity),
        access: Object.keys(access).length > 0 ? { type: asString(access.type), raw: access } : undefined,
        digest: ocmDigest(raw.digest),
        labels: ocmLabels(raw.labels),
        blob,
      },
      raw: { kind: 'json', value: raw },
    };
    elements.push(element);
    relationships.push({
      from: { kind: 'local', spdxId: rootSpdxId },
      type: 'CONTAINS',
      to: { kind: 'local', spdxId },
    });

    if (role === 'resource') {
      if (isSbomResource(raw, access)) {
        wireSbomResource(access, name, spdxId);
      } else if (accessType && !KNOWN_ACCESS.has(accessType)) {
        unsupportedAccess.set(accessType, (unsupportedAccess.get(accessType) ?? 0) + 1);
      }
    }
  };

  const wireSbomResource = (
    access: Record<string, unknown>,
    name: string,
    ownerSpdxId: string,
  ): void => {
    const localReference = asString(access.localReference) ?? asString(access.filename);
    if (!localReference) {
      // Remote SBOM (e.g. ociArtifact) — reference it informationally.
      return;
    }
    const sha1 = blobContext?.sbomChecksumFor(localReference);
    if (!sha1) {
      diagnostics.push(
        diag(
          'info',
          'OCM_SBOM_IN_ARCHIVE',
          `SBOM resource "${name}" is stored in the delivery archive. Load the CTF/component archive to see its contents.`,
        ),
      );
      return;
    }
    const docRef = uniqueDocRef(`DocumentRef-sbom-${sanitizeRefName(name)}`, usedRefNames);
    externalDocumentRefs.push({
      docRef,
      uri: `ocm-blob://${cd.name}/${cd.version}/${name}`,
      checksum: { algorithm: 'SHA1', value: sha1 },
    });
    relationships.push({
      from: { kind: 'local', spdxId: ownerSpdxId },
      type: 'DESCRIBED_BY',
      to: { kind: 'external', docRef, spdxId: null },
    });
  };

  for (const resource of cd.resources) addArtifact(resource, 'resource');
  for (const source of cd.sources) addArtifact(source, 'source');

  for (const reference of cd.references) {
    const refName = asString(reference.name);
    const componentName = asString(reference.componentName);
    const refVersion = asString(reference.version);
    if (!refName || !componentName || !refVersion) {
      diagnostics.push(diag('warning', 'OCM_REF_MALFORMED', 'A componentReference without name/componentName/version was skipped.'));
      continue;
    }
    const docRef = uniqueDocRef(`DocumentRef-ref-${sanitizeRefName(refName)}`, usedRefNames);
    // Deliberately NO checksum: the OCM digest hashes the normalized CD,
    // never a droppable file's bytes — the namespace matcher does the work.
    // The OCM digest itself rides in `ocm.digest` for display/verification.
    externalDocumentRefs.push({
      docRef,
      uri: ocmNamespace(componentName, refVersion),
      ocm: {
        componentName,
        digest: ocmDigest(reference.digest),
        extraIdentity: stringRecord(reference.extraIdentity),
        labels: ocmLabels(reference.labels),
      },
    });
    relationships.push({
      from: { kind: 'local', spdxId: rootSpdxId },
      type: 'CONTAINS',
      to: { kind: 'external', docRef, spdxId: null },
    });
  }

  for (const [type, count] of unsupportedAccess) {
    diagnostics.push(
      diag('info', 'OCM_ACCESS_UNSUPPORTED', `${count} resource(s) use access type "${type}": listed without download location.`),
    );
  }
  const blobNote =
    checkedBlobs > 0 ? `Blob digests of ${checkedBlobs} artifact(s) were checked against the delivery contents. ` : '';
  const signatureNote =
    cd.signatures.length > 0
      ? 'Signatures can be verified against a public key in the Signatures section.'
      : 'Component and reference digests are displayed, not verified.';
  diagnostics.push(diag('info', 'OCM_DIGESTS_NOT_VERIFIED', `${blobNote}${signatureNote}`.trim()));

  const document: SbomDocument = {
    id: documentId,
    spec,
    spdxId: 'SPDXRef-DOCUMENT',
    name: cd.name,
    namespace,
    created: cd.creationTime,
    creators: supplier ? [supplier] : [],
    comment: `OCM component descriptor (schema ${cd.schemaLabel})`,
    describes: [rootSpdxId],
    externalDocumentRefs,
    elements: dedupeBySpdxId(elements, diagnostics),
    relationships,
    diagnostics,
    ocm: {
      schemaVersion: cd.schemaLabel,
      provider: cd.provider || cd.providerLabels ? { name: cd.provider, labels: cd.providerLabels } : undefined,
      labels: cd.labels,
      repositoryContexts: repositoryContexts(cd.repositoryContexts),
      signatures: signatures(cd.signatures),
    },
  };
  return { document, diagnostics };
}

function normalize(root: Record<string, unknown>): NormalizedCd | null {
  if (isRecord(root.component)) {
    const component = root.component;
    const name = asString(component.name);
    const version = asString(component.version);
    if (!name || !version) return null;
    return {
      schemaLabel: asString((root.meta as Record<string, unknown>)?.schemaVersion) ?? 'v2',
      name,
      version,
      provider: providerName(component.provider),
      providerLabels: isRecord(component.provider) ? ocmLabels(component.provider.labels) : undefined,
      creationTime: asString(component.creationTime) ?? labelValue(component.labels, 'ocm.software/creationTime'),
      labels: ocmLabels(component.labels),
      repositoryContexts: asRecordArray(component.repositoryContexts),
      resources: asRecordArray(component.resources),
      sources: asRecordArray(component.sources),
      references: asRecordArray(component.componentReferences),
      signatures: asRecordArray(root.signatures),
      componentNode: component,
      v3: false,
    };
  }
  // v3alpha1: metadata + spec
  const metadata = isRecord(root.metadata) ? root.metadata : null;
  const specNode = isRecord(root.spec) ? root.spec : {};
  const name = asString(metadata?.name);
  const version = asString(metadata?.version);
  if (!name || !version) return null;
  return {
    schemaLabel: 'v3alpha1',
    name,
    version,
    provider: providerName(metadata?.provider),
    providerLabels: isRecord(metadata?.provider) ? ocmLabels(metadata.provider.labels) : undefined,
    creationTime: asString(metadata?.creationTime) ?? labelValue(metadata?.labels, 'ocm.software/creationTime'),
    labels: ocmLabels(metadata?.labels),
    repositoryContexts: asRecordArray(root.repositoryContexts),
    resources: asRecordArray(specNode.resources),
    sources: asRecordArray(specNode.sources),
    references: asRecordArray(specNode.references),
    signatures: asRecordArray(root.signatures),
    componentNode: { metadata: root.metadata, spec: root.spec },
    v3: true,
  };
}

function providerName(provider: unknown): string | undefined {
  if (typeof provider === 'string') return provider;
  if (isRecord(provider)) return asString(provider.name);
  return undefined;
}

function labelValue(labels: unknown, key: string): string | undefined {
  for (const label of asRecordArray(labels)) {
    if (label.name === key) return asString(label.value);
  }
  return undefined;
}

const KNOWN_ACCESS = new Set([
  'localblob',
  'localfilesystemblob',
  'ociartifact',
  'ociimage',
  'ociregistry',
  'github',
  'git',
]);

function artifactLocation(access: Record<string, unknown>): string | undefined {
  return (
    asString(access.imageReference) ??
    asString(access.url) ??
    asString(access.repoUrl) ??
    asString(access.localReference) ??
    asString(access.filename)
  );
}

function digestChecksum(digest: unknown): Checksum[] | undefined {
  if (!isRecord(digest)) return undefined;
  const algorithm = asString(digest.hashAlgorithm);
  const value = asString(digest.value);
  if (!algorithm || !value) return undefined;
  return [{ algorithm: algorithm.toUpperCase().replace(/-/g, ''), value: value.toLowerCase() }];
}

/** Best-effort pkg:oci purl from an imageReference — a dedupe key, not truth. */
function ociPurl(access: Record<string, unknown>, version?: string): string | undefined {
  const image = asString(access.imageReference);
  if (!image) return undefined;
  const [repoAndTag] = image.split('@');
  // A ':' only means "tag" after the last path segment — otherwise it is a
  // registry port (registry.example.org:5000/acme/gateway).
  const lastSlash = repoAndTag!.lastIndexOf('/');
  const tagColon = repoAndTag!.indexOf(':', lastSlash + 1);
  const withoutTag = tagColon === -1 ? repoAndTag! : repoAndTag!.slice(0, tagColon);
  const tag = tagColon === -1 ? undefined : repoAndTag!.slice(tagColon + 1);
  const segments = withoutTag.split('/');
  const artifact = segments.pop();
  if (!artifact) return undefined;
  const digest = image.includes('@') ? image.slice(image.indexOf('@') + 1) : undefined;
  const qualifier = segments.length > 0 ? `?repository_url=${segments.join('/')}` : '';
  const versionPart = digest ?? tag ?? version;
  return `pkg:oci/${artifact}${versionPart ? `@${versionPart}` : ''}${qualifier}`;
}

export function isSbomResource(raw: Record<string, unknown>, access: Record<string, unknown>): boolean {
  const type = asString(raw.type)?.toLowerCase();
  if (type === 'sbom' || type === 'spdx') return true;
  const mediaType = asString(access.mediaType)?.toLowerCase() ?? '';
  return mediaType.includes('spdx');
}

function sanitizeSpdxId(candidate: string, existing: SbomElement[]): string {
  let id = candidate.replace(/[^A-Za-z0-9.-]/g, '-');
  if (existing.some((el) => el.spdxId === id)) {
    let suffix = 2;
    while (existing.some((el) => el.spdxId === `${id}-${suffix}`)) suffix++;
    id = `${id}-${suffix}`;
  }
  return id;
}

function sanitizeRefName(name: string): string {
  return name.replace(/[^A-Za-z0-9.-]/g, '-');
}

function uniqueDocRef(candidate: string, used: Set<string>): string {
  let ref = candidate;
  let suffix = 2;
  while (used.has(ref)) ref = `${candidate}-${suffix++}`;
  used.add(ref);
  return ref;
}

// -- ocm-extension mapping helpers --------------------------------------------

function ocmLabels(labels: unknown): OcmLabel[] | undefined {
  const list = asRecordArray(labels)
    .map((label): OcmLabel | null => {
      const name = asString(label.name);
      if (!name) return null;
      return {
        name,
        value: label.value,
        signing: label.signing === true ? true : undefined,
        version: asString(label.version),
      };
    })
    .filter((l): l is OcmLabel => l !== null);
  return list.length > 0 ? list : undefined;
}

function ocmDigest(digest: unknown): OcmDigest | undefined {
  if (!isRecord(digest)) return undefined;
  const result: OcmDigest = {
    hashAlgorithm: asString(digest.hashAlgorithm),
    normalisationAlgorithm: asString(digest.normalisationAlgorithm),
    value: asString(digest.value),
  };
  return result.hashAlgorithm || result.value ? result : undefined;
}

function stringRecord(value: unknown): Record<string, string> | undefined {
  if (!isRecord(value)) return undefined;
  const entries = Object.entries(value).filter((e): e is [string, string] => typeof e[1] === 'string');
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function repositoryContexts(contexts: Record<string, unknown>[]): OcmRepositoryContext[] | undefined {
  const list = contexts.map((ctx) => ({
    type: asString(ctx.type),
    baseUrl: asString(ctx.baseUrl),
    subPath: asString(ctx.subPath),
    componentNameMapping: asString(ctx.componentNameMapping),
  }));
  return list.length > 0 ? list : undefined;
}

function signatures(nodes: Record<string, unknown>[]): OcmSignatureInfo[] | undefined {
  const list = nodes.map((node) => {
    const signature = isRecord(node.signature) ? node.signature : {};
    return {
      name: asString(node.name),
      digest: ocmDigest(node.digest),
      algorithm: asString(signature.algorithm),
      value: asString(signature.value),
      mediaType: asString(signature.mediaType),
      issuer: asString(signature.issuer),
    } satisfies OcmSignatureInfo;
  });
  return list.length > 0 ? list : undefined;
}
