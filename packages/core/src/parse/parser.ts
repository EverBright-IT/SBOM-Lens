import type { SbomDocument } from '../model/document';
import type { Diagnostic } from '../model/diagnostics';
import { diag } from '../model/diagnostics';
import { detect } from './detect';
import { parseOcmComponentDescriptor } from './ocm/cd';
import { parseSpdx2Json } from './spdx2/json';
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

export function parseDocument(input: SourceInput): ParseResult {
  const detection = detect(input.text);
  switch (detection.format) {
    case 'spdx2-json':
      return parseSpdx2Json(input, detection.parsed, detection.serialization);
    case 'spdx2-tag-value':
      return parseSpdx2TagValue(input);
    case 'ocm-cd':
      return parseOcmComponentDescriptor(input, detection.parsed, detection.serialization);
    case 'unsupported':
      return {
        document: null,
        diagnostics: [diag('error', detection.code, detection.reason)],
      };
  }
}
