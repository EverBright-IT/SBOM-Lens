import type { SbomDocument } from '../model/document';
import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import { detect } from './detect';
import { parseSpdx2Json } from './spdx2/json';
import { parseSpdx3Json } from './spdx3/json';
import { parseSpdx2TagValue } from './spdx2/tag-value';

export interface SourceInput {
  fileName: string;
  text: string;
  /** Lowercase hex SHA-1 of the raw bytes; drives cascade resolution and dedupe. */
  sha1: string;
  byteSize: number;
}

export interface ParseResult {
  /** null only when nothing salvageable (unrecognized/unsupported format). */
  document: SbomDocument | null;
  /** Always present; equals document.diagnostics when a document was produced. */
  diagnostics: Diagnostic[];
}

/**
 * OCM is registered, not imported — the same seam `registerYamlParser` uses.
 * Only products that want component descriptors pull in `@sbomlens/core/ocm`
 * and wire it up; an SPDX-only build carries no mapper, tar reader, or gzip
 * path at all, and still recognizes a descriptor well enough to say so.
 */
export type OcmParser = (
  input: SourceInput,
  root: Record<string, unknown>,
  serialization: 'json' | 'yaml',
) => ParseResult;
let ocmParser: OcmParser | null = null;

export function registerOcmParser(parser: OcmParser): void {
  ocmParser = parser;
}

export function parseDocument(input: SourceInput): ParseResult {
  const detection = detect(input.text);
  switch (detection.format) {
    case 'spdx2-json':
      return parseSpdx2Json(input, detection.parsed, detection.serialization);
    case 'spdx2-tag-value':
      return parseSpdx2TagValue(input);
    case 'spdx3-json':
      return parseSpdx3Json(input, detection.parsed);
    case 'ocm-cd':
      return ocmParser
        ? ocmParser(input, detection.parsed, detection.serialization)
        : {
            document: null,
            diagnostics: [
              diag(
                'error',
                'OCM_CD_UNSUPPORTED',
                'This is an OCM component descriptor, not an SPDX document.',
              ),
            ],
          };
    case 'unsupported':
      return {
        document: null,
        diagnostics: [diag('error', detection.code, detection.reason)],
      };
  }
}
