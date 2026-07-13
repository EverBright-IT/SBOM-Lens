import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { buildIndexes } from './graph/indexes';
import type { SourceInput } from './parse/parser';
import { parseDocument } from './parse/parser';
import type { LoadedDocument } from './workspace/workspace';

export function loadFixture(name: string): string {
  return readFileSync(new URL(`../fixtures/${name}`, import.meta.url), 'utf8');
}

/** Deterministic fake SHA-1 so tests don't need async hashing. */
export function fakeSha1(seed: string): string {
  let hex = '';
  for (let i = 0; hex.length < 40; i++) {
    hex += (seed.charCodeAt(i % seed.length) % 16).toString(16);
  }
  return hex.slice(0, 40);
}

export function fixtureInput(name: string, text = loadFixture(name)): SourceInput {
  return { fileName: name, text, sha1: fakeSha1(name), byteSize: text.length };
}

/** Fully loaded document (parsed + indexed) with the REAL SHA-1 of the fixture bytes. */
export function loadFixtureDocument(name: string): LoadedDocument {
  return loadedFromText(name.split('/').pop()!, loadFixture(name));
}

export function loadedFromText(fileName: string, text: string): LoadedDocument {
  const sha1 = createHash('sha1').update(text, 'utf8').digest('hex');
  const byteSize = Buffer.byteLength(text, 'utf8');
  const { document } = parseDocument({ fileName, text, sha1, byteSize });
  if (!document) throw new Error(`fixture ${fileName} did not produce a document`);
  return {
    document,
    indexes: buildIndexes(document),
    source: { fileName, byteSize, sha1, text },
  };
}
