import type {
  Checksum,
  ExternalDocumentRef,
  ExternalRef,
  Relationship,
  SbomElement,
} from '../../model/document';
import type { Diagnostic } from '../../model/diagnostics';
import { diag } from '../../model/diagnostics';
import { makeDocumentId, makeElementId } from '../../model/ids';
import type { ParseResult, SourceInput } from '../parser';
import {
  checkRelationshipDocRefs,
  dedupeBySpdxId,
  extractPurl,
  normalizeDescribes,
  normalizeRelType,
  parseElementRef,
  versionFromPurl,
} from './common';

/**
 * Single-pass line state machine for SPDX 2.x tag-value.
 *
 * Tolerance over strictness: real documents interleave fields in arbitrary
 * order, comment out fields with '#', omit checksums, and carry unknown tags.
 * Anomalies become diagnostics; parsing never aborts mid-file.
 */

interface ElementDraft {
  kind: 'package' | 'file';
  spdxId?: string;
  name: string;
  startLine: number;
  pairs: [string, string][];
  version?: string;
  supplier?: string;
  originator?: string;
  downloadLocation?: string;
  licenseConcluded?: string;
  licenseDeclared?: string;
  copyright?: string;
  purpose?: string;
  description?: string;
  comment?: string;
  checksums: Checksum[];
  externalRefs: ExternalRef[];
}

/** Tags that always describe the document, regardless of the current block. */
const DOC_TAGS = new Set([
  'SPDXVersion',
  'DataLicense',
  'DocumentName',
  'DocumentNamespace',
  'DocumentComment',
  'Creator',
  'Created',
  'CreatorComment',
  'LicenseListVersion',
]);

/** Element-scope tag → ElementDraft field for plain string values. */
const ELEMENT_STRING_TAGS: Record<string, keyof ElementDraft> = {
  PackageVersion: 'version',
  PackageSupplier: 'supplier',
  PackageOriginator: 'originator',
  PackageDownloadLocation: 'downloadLocation',
  PackageLicenseConcluded: 'licenseConcluded',
  LicenseConcluded: 'licenseConcluded',
  PackageLicenseDeclared: 'licenseDeclared',
  PackageCopyrightText: 'copyright',
  FileCopyrightText: 'copyright',
  PrimaryPackagePurpose: 'purpose',
  PackageDescription: 'description',
  PackageComment: 'comment',
  FileComment: 'comment',
};

export function parseSpdx2TagValue(input: SourceInput): ParseResult {
  const diagnostics: Diagnostic[] = [];
  const lines = input.text.split(/\r\n|\r|\n/);

  const doc = {
    spdxId: undefined as string | undefined,
    version: undefined as string | undefined,
    dataLicense: undefined as string | undefined,
    name: undefined as string | undefined,
    namespace: undefined as string | undefined,
    comment: undefined as string | undefined,
    created: undefined as string | undefined,
    creators: [] as string[],
  };
  const externalDocumentRefs: ExternalDocumentRef[] = [];
  const relationships: Relationship[] = [];
  const drafts: ElementDraft[] = [];

  let current: ElementDraft | null = null;
  let context: 'document' | 'element' | 'skip' = 'document';
  const skipped = { snippets: 0, licenses: 0, annotations: 0 };
  const orphanTags = new Set<string>();

  const closeElement = () => {
    if (current) drafts.push(current);
    current = null;
  };

  let i = 0;
  while (i < lines.length) {
    const lineNo = i + 1;
    const line = lines[i]!;
    i++;

    const stripped = line.trim();
    if (stripped === '' || stripped.startsWith('#')) continue;

    const match = stripped.match(/^([A-Za-z][A-Za-z0-9]*):(.*)$/);
    if (!match) {
      diagnostics.push(
        diag('warning', 'TV_MALFORMED_LINE', `Not a "Tag: value" line: "${truncate(stripped)}"`, lineNo),
      );
      continue;
    }
    const tag = match[1]!;
    let value = match[2]!.trim();

    // Multi-line <text>…</text> values.
    if (value.startsWith('<text>')) {
      const inline = value.indexOf('</text>');
      if (inline !== -1) {
        value = value.slice(6, inline).trim();
      } else {
        const buf: string[] = [value.slice(6)];
        let closed = false;
        while (i < lines.length) {
          const cont = lines[i]!;
          i++;
          const end = cont.indexOf('</text>');
          if (end !== -1) {
            buf.push(cont.slice(0, end));
            closed = true;
            break;
          }
          buf.push(cont);
        }
        if (!closed) {
          diagnostics.push(diag('warning', 'TV_UNTERMINATED_TEXT', `Unterminated <text> for ${tag}.`, lineNo));
        }
        value = buf.join('\n').trim();
      }
    }

    // -- Block starters ------------------------------------------------------
    if (tag === 'PackageName' || tag === 'FileName') {
      closeElement();
      context = 'element';
      current = {
        kind: tag === 'PackageName' ? 'package' : 'file',
        name: value,
        startLine: lineNo,
        pairs: [[tag, value]],
        checksums: [],
        externalRefs: [],
      };
      continue;
    }
    if (tag === 'SnippetSPDXID' || tag === 'LicenseID' || tag === 'Annotator') {
      closeElement();
      context = 'skip';
      if (tag === 'SnippetSPDXID') skipped.snippets++;
      else if (tag === 'LicenseID') skipped.licenses++;
      else skipped.annotations++;
      continue;
    }

    // -- Document-scope records (position-independent) -----------------------
    if (tag === 'Relationship') {
      const parts = value.split(/\s+/);
      if (parts.length !== 3) {
        diagnostics.push(
          diag('warning', 'REL_MALFORMED', `Relationship needs "<a> <TYPE> <b>": "${truncate(value)}"`, lineNo),
        );
        continue;
      }
      relationships.push({
        from: parseElementRef(parts[0]!),
        type: normalizeRelType(parts[1]!),
        to: parseElementRef(parts[2]!),
      });
      continue;
    }
    if (tag === 'RelationshipComment') {
      const last = relationships[relationships.length - 1];
      if (last) last.comment = value;
      continue;
    }
    if (tag === 'ExternalDocumentRef') {
      parseExternalDocumentRef(value, lineNo, externalDocumentRefs, diagnostics);
      continue;
    }
    if (tag === 'SPDXID') {
      if (context === 'element' && current) {
        current.pairs.push([tag, value]);
        if (current.spdxId !== undefined) {
          diagnostics.push(
            diag('warning', 'TV_DUP_ELEMENT_SPDXID', `Second SPDXID in one block; keeping "${current.spdxId}".`, lineNo),
          );
        } else {
          current.spdxId = value;
        }
      } else if (doc.spdxId !== undefined) {
        diagnostics.push(diag('warning', 'TV_DUP_DOC_SPDXID', 'Second document SPDXID; keeping the first.', lineNo));
      } else {
        doc.spdxId = value;
      }
      continue;
    }
    if (DOC_TAGS.has(tag)) {
      switch (tag) {
        case 'SPDXVersion':
          doc.version = value;
          break;
        case 'DataLicense':
          doc.dataLicense = value;
          break;
        case 'DocumentName':
          doc.name = value;
          break;
        case 'DocumentNamespace':
          doc.namespace = value;
          break;
        case 'DocumentComment':
          doc.comment = value;
          break;
        case 'Creator':
          doc.creators.push(value);
          break;
        case 'Created':
          doc.created = value;
          break;
      }
      continue;
    }

    // -- Element-scope tags ---------------------------------------------------
    if (context === 'element' && current) {
      current.pairs.push([tag, value]);
      const field = ELEMENT_STRING_TAGS[tag];
      if (field) {
        (current as unknown as Record<string, string>)[field as string] = value;
      } else if (tag === 'PackageChecksum' || tag === 'FileChecksum') {
        const checksum = parseChecksum(value);
        if (checksum) current.checksums.push(checksum);
        else diagnostics.push(diag('warning', 'TV_BAD_CHECKSUM', `Unparseable checksum: "${truncate(value)}"`, lineNo));
      } else if (tag === 'ExternalRef') {
        const parts = value.split(/\s+/);
        if (parts.length === 3) {
          current.externalRefs.push({ category: parts[0]!, type: parts[1]!, locator: parts[2]! });
        } else {
          diagnostics.push(diag('warning', 'TV_BAD_EXTERNAL_REF', `ExternalRef needs "<category> <type> <locator>".`, lineNo));
        }
      }
      // Unmapped tags (FilesAnalyzed, PackageHomePage, …) live on in `pairs`.
      continue;
    }
    if (context === 'skip') continue;

    orphanTags.add(tag);
  }
  closeElement();

  if (orphanTags.size > 0) {
    diagnostics.push(
      diag('info', 'TV_ORPHAN_TAGS', `Tags outside any known block were ignored: ${[...orphanTags].slice(0, 5).join(', ')}${orphanTags.size > 5 ? ', …' : ''}.`),
    );
  }
  const skippedTotal = skipped.snippets + skipped.licenses + skipped.annotations;
  if (skippedTotal > 0) {
    diagnostics.push(
      diag('info', 'TV_BLOCKS_SKIPPED', `Skipped ${skipped.snippets} snippet(s), ${skipped.licenses} extracted licensing info(s), ${skipped.annotations} annotation(s) — not displayed in this version.`),
    );
  }
  if (!doc.namespace) {
    diagnostics.push(diag('warning', 'DOC_NO_NAMESPACE', 'Document has no DocumentNamespace; using a content-hash id instead.'));
  }

  const documentId = makeDocumentId(doc.namespace ?? null, input.sha1);
  const docSpdxId = doc.spdxId ?? 'SPDXRef-DOCUMENT';

  let anonCounter = 0;
  const elements: SbomElement[] = drafts.map((draft) => {
    let spdxId = draft.spdxId;
    if (!spdxId) {
      spdxId = `SPDXRef-sbomlens-anonymous-${++anonCounter}`;
      diagnostics.push(
        diag('warning', 'TV_MISSING_SPDXID', `${draft.kind} "${draft.name}" has no SPDXID; assigned ${spdxId}.`, draft.startLine),
      );
    }
    const purl = extractPurl(draft.externalRefs);
    return {
      id: makeElementId(documentId, spdxId),
      documentId,
      spdxId,
      kind: draft.kind,
      name: draft.name,
      version: draft.version ?? (purl ? versionFromPurl(purl) : undefined),
      purl,
      supplier: draft.supplier,
      originator: draft.originator,
      downloadLocation: draft.downloadLocation,
      licenseConcluded: draft.licenseConcluded,
      licenseDeclared: draft.licenseDeclared,
      copyright: draft.copyright,
      purpose: draft.purpose,
      description: draft.description,
      comment: draft.comment,
      checksums: draft.checksums.length > 0 ? draft.checksums : undefined,
      externalRefs: draft.externalRefs.length > 0 ? draft.externalRefs : undefined,
      raw: { kind: 'tv', pairs: draft.pairs },
    };
  });

  const deduped = dedupeBySpdxId(elements, diagnostics);
  const { relationships: allRelationships, describes } = normalizeDescribes(docSpdxId, [], relationships);
  checkRelationshipDocRefs(allRelationships, externalDocumentRefs, diagnostics);

  const document = {
    id: documentId,
    spec: { model: 'spdx-2' as const, version: doc.version ?? 'SPDX-2.x', serialization: 'tag-value' as const },
    spdxId: docSpdxId,
    name: doc.name ?? input.fileName,
    namespace: doc.namespace ?? null,
    created: doc.created,
    creators: doc.creators,
    comment: doc.comment,
    dataLicense: doc.dataLicense,
    describes,
    externalDocumentRefs,
    elements: deduped,
    relationships: allRelationships,
    diagnostics,
  };
  return { document, diagnostics };
}

/** `DocumentRef-X <uri> [ALG:<hex> | ALG: <hex>]` — checksum spacing varies in the wild. */
function parseExternalDocumentRef(
  value: string,
  lineNo: number,
  out: ExternalDocumentRef[],
  diagnostics: Diagnostic[],
): void {
  const match = value.match(/^(\S+)\s+(\S+)(?:\s+(.+))?$/);
  if (!match) {
    diagnostics.push(diag('warning', 'EXTREF_MALFORMED', `Unparseable ExternalDocumentRef: "${truncate(value)}"`, lineNo));
    return;
  }
  const [, docRef, uri, rest] = match;
  let checksum: Checksum | undefined;
  if (rest) {
    checksum = parseChecksum(rest.trim());
    if (!checksum) {
      diagnostics.push(
        diag('warning', 'EXTREF_BAD_CHECKSUM', `ExternalDocumentRef ${docRef} has an unparseable checksum; resolution falls back to namespace/manual matching.`, lineNo),
      );
    }
  } else {
    diagnostics.push(
      diag('warning', 'EXTREF_NO_CHECKSUM', `ExternalDocumentRef ${docRef} has no checksum (the spec requires one); resolution falls back to namespace/manual matching.`, lineNo),
    );
  }
  if (!docRef!.startsWith('DocumentRef-')) {
    diagnostics.push(diag('warning', 'EXTREF_BAD_ID', `External document id "${docRef}" should start with "DocumentRef-".`, lineNo));
  }
  out.push({ docRef: docRef!, uri: uri!, checksum });
}

/** `SHA1:abc`, `SHA1: abc`, `SHA256:…` → normalized Checksum. */
function parseChecksum(value: string): Checksum | undefined {
  const match = value.match(/^([A-Za-z0-9-]+)\s*:\s*([0-9a-fA-F]+)$/);
  if (!match) return undefined;
  return { algorithm: match[1]!.toUpperCase(), value: match[2]!.toLowerCase() };
}

function truncate(s: string): string {
  return s.length > 80 ? `${s.slice(0, 77)}…` : s;
}
