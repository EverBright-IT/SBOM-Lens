import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The SBOM Lens extension names the files it opens in three places that must
 * agree: the custom-editor selector and the explorer menu in its manifest,
 * and the glob the folder and workspace scans walk. A name missing from one
 * of them opens one way and not the other; `bom.json`, the name the
 * CycloneDX specification recommends, was missing from all three.
 */
const extensionRoot = fileURLToPath(new URL('../../../apps/vscode/', import.meta.url));
const manifest = JSON.parse(readFileSync(`${extensionRoot}package.json`, 'utf8')) as {
  contributes: {
    customEditors: { selector: { filenamePattern: string }[] }[];
    menus: Record<string, { command: string; when?: string }[]>;
  };
};
const extensionSource = readFileSync(`${extensionRoot}src/extension.ts`, 'utf8');

/** A file-name glob with `*` as its only wildcard, as the manifest and the scan glob use it. */
const globToRegExp = (glob: string): RegExp =>
  new RegExp(`^${glob.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);

const selector = manifest.contributes.customEditors[0]!.selector.map((entry) => globToRegExp(entry.filenamePattern));

const menuWhen = manifest.contributes.menus['explorer/context']!.find((entry) => entry.command === 'sbomlens.openWith')!.when!;
const menu = new RegExp(/resourceFilename =~ \/(.*)\/$/.exec(menuWhen)![1]!);

const scanGlob = /fileGlob:\s*'\{([^}]*)\}'/.exec(extensionSource)![1]!;
const scan = scanGlob.split(',').map((glob) => {
  expect(glob.startsWith('**/')).toBe(true);
  return globToRegExp(glob.slice('**/'.length));
});

const opens = [
  'app.spdx',
  'app.spdx.json',
  'app.spdx3.json',
  'app.spdx.jsonld',
  'app.spdx.yaml',
  'app.spdx.yml',
  'app.cdx.json',
  'app.cdx.xml',
  'bom.json',
  'bom.xml',
  'app.bom.json',
  'app.bom.xml',
];
const staysOut = ['package.json', 'sbom.json', 'mybom.json', 'bom.json.bak', 'tsconfig.json', 'pom.xml', 'notes.yaml'];

describe('SBOM Lens extension file names', () => {
  it.each(opens)('%s opens from the editor picker, the explorer menu and the scans alike', (name) => {
    expect(selector.some((pattern) => pattern.test(name))).toBe(true);
    expect(menu.test(name)).toBe(true);
    expect(scan.some((pattern) => pattern.test(name))).toBe(true);
  });

  it.each(staysOut)('%s is claimed by none of the three', (name) => {
    expect(selector.some((pattern) => pattern.test(name))).toBe(false);
    expect(menu.test(name)).toBe(false);
    expect(scan.some((pattern) => pattern.test(name))).toBe(false);
  });

  it('offers "Open with" in the command palette, for files of any other name', () => {
    const palette = manifest.contributes.menus.commandPalette!.find((entry) => entry.command === 'sbomlens.openWith');
    expect(palette?.when).toBe('editorIsOpen');
  });
});
