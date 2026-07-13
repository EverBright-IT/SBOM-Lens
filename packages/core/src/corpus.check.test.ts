import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseDocument } from './parse/parser';

/**
 * Optional check against a private SBOM corpus that must never be committed.
 * Runs only when SBOM_CORPUS_DIR is set:
 *
 *   SBOM_CORPUS_DIR=~/sboms npm run check-corpus
 *
 * Asserts that every tag-value .spdx file yields a document, and prints a
 * summary of formats and diagnostic codes across the whole corpus.
 */
const corpusDir = process.env.SBOM_CORPUS_DIR;

describe.skipIf(!corpusDir)('private corpus', () => {
  it('parses every SPDX file in the corpus', () => {
    const files = walk(corpusDir!).filter((f) => /\.(spdx|json)$/i.test(f));
    expect(files.length).toBeGreaterThan(0);

    const stats = { parsed: 0, unsupported: 0, failed: [] as string[] };
    const diagnosticCodes = new Map<string, number>();

    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      const sha1 = createHash('sha1').update(text, 'utf8').digest('hex');
      const { document, diagnostics } = parseDocument({
        fileName: file,
        text,
        sha1,
        byteSize: text.length,
      });
      for (const d of diagnostics) {
        diagnosticCodes.set(d.code, (diagnosticCodes.get(d.code) ?? 0) + 1);
      }
      if (document) {
        stats.parsed++;
      } else if (file.toLowerCase().endsWith('.spdx')) {
        stats.failed.push(`${file}: ${diagnostics[0]?.message}`);
      } else {
        stats.unsupported++; // .json files may legitimately be Trivy-native etc.
      }
    }

    console.log(
      `corpus: ${stats.parsed} parsed, ${stats.unsupported} recognized-unsupported, ${stats.failed.length} failed of ${files.length} files`,
    );
    console.log(
      'diagnostics:',
      Object.fromEntries([...diagnosticCodes.entries()].sort((a, b) => b[1] - a[1])),
    );
    expect(stats.failed, stats.failed.join('\n')).toEqual([]);
  });
});

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else if (entry.isFile()) out.push(path);
  }
  return out;
}
