import { describe, expect, it } from 'vitest';
import { loadFixture, fakeSha1 } from '../test-fixtures';
import { detect } from './detect';
import { parseDocument } from './parser';

/**
 * The SPDX-only side of the OCM seam. This file deliberately imports nothing
 * from `../ocm` — no registration happens, exactly like a SBOM Lens build.
 * Vitest isolates module state per file, so registrations elsewhere cannot
 * leak in and make these pass by accident.
 */
describe('component descriptors without a registered OCM parser', () => {
  const name = 'ocm/cd-v2.yaml';
  const text = loadFixture(name);

  it('still recognizes the format — the classifier is model-agnostic', () => {
    expect(detect(text).format).toBe('ocm-cd');
  });

  it('refuses to parse, and says what the file actually is', () => {
    const result = parseDocument({ fileName: name, text, sha1: fakeSha1(name), byteSize: text.length });
    expect(result.document).toBeNull();
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]!.code).toBe('OCM_CD_UNSUPPORTED');
    expect(result.diagnostics[0]!.message).toContain('not an SPDX document');
  });
});
