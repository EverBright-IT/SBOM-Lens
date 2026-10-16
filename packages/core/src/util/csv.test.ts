import { describe, expect, it } from 'vitest';
import { csvCell } from './csv';

/**
 * Pinned: a cell a spreadsheet would read as a formula becomes text through
 * a leading single quote, npm scopes keep their name, everything else comes
 * out as before, and separators inside a value cannot start a new cell.
 */

describe('csvCell', () => {
  it('turns the OWASP formula starts into text', () => {
    expect(csvCell('=1+1')).toBe("'=1+1");
    expect(csvCell('+1+1')).toBe("'+1+1");
    expect(csvCell('-2+3')).toBe("'-2+3");
    expect(csvCell('@SUM(A1:A2)')).toBe("'@SUM(A1:A2)");
    expect(csvCell("=cmd|' /C calc'!A0")).toBe("'=cmd|' /C calc'!A0");
    // Spreadsheets may skip a leading tab or line break; quoted, as any value with one.
    expect(csvCell('\t=1+1')).toBe(`"'\t=1+1"`);
    expect(csvCell('\r=1+1')).toBe(`"'\r=1+1"`);
    expect(csvCell('\n=1+1')).toBe(`"'\n=1+1"`);
    // Full-width = + - @
    for (const start of ['＝', '＋', '－', '＠']) {
      expect(csvCell(`${start}1+1`)).toBe(`'${start}1+1`);
    }
  });

  it('guards first and quotes after, so the quote mark ends up inside the cell', () => {
    expect(csvCell('=HYPERLINK("http://example.org/?"&A1,"click")')).toBe(
      `"'=HYPERLINK(""http://example.org/?""&A1,""click"")"`,
    );
  });

  it('keeps npm scopes, whatever their case', () => {
    expect(csvCell('@types/node')).toBe('@types/node');
    expect(csvCell('@babel/plugin-transform-runtime')).toBe('@babel/plugin-transform-runtime');
    expect(csvCell('@Azure/core-auth')).toBe('@Azure/core-auth');
    expect(csvCell('@socket.io/component-emitter')).toBe('@socket.io/component-emitter');
    expect(csvCell('@types/lodash.merge')).toBe('@types/lodash.merge');
  });

  it('does not take a formula for a scope', () => {
    expect(csvCell('@SUM(A1)/2')).toBe("'@SUM(A1)/2");
    expect(csvCell('@a/b|c')).toBe("'@a/b|c");
    expect(csvCell('@a/b/c')).toBe("'@a/b/c");
    expect(csvCell('@-a/b')).toBe("'@-a/b");
    expect(csvCell('@types/')).toBe("'@types/");
    expect(csvCell('@types')).toBe("'@types");
    expect(csvCell('＠types/node')).toBe("'＠types/node");
  });

  it('leaves ordinary values alone', () => {
    for (const value of [
      '',
      'left-pad',
      '1.3.0-rc.1',
      'MIT OR Apache-2.0',
      'pkg:npm/%40types/node@20.11.0',
      'Organization: ACME',
      'SPDXRef-Package-1',
      'a=b',
      "O'Brien",
    ]) {
      expect(csvCell(value)).toBe(value);
    }
  });

  it('quotes quotes, separators and line breaks', () => {
    expect(csvCell('weird, "pkg"')).toBe('"weird, ""pkg"""');
    expect(csvCell('a;b')).toBe('"a;b"');
    expect(csvCell('a\tb')).toBe('"a\tb"');
    expect(csvCell('a\nb')).toBe('"a\nb"');
    expect(csvCell('a\r\nb')).toBe('"a\r\nb"');
  });

  it('keeps a formula behind a separator inside its cell', () => {
    // Unquoted, each of these would hand the importer a cell starting with =.
    expect(csvCell('x,=1+1')).toBe('"x,=1+1"');
    expect(csvCell('x;=1+1')).toBe('"x;=1+1"');
    expect(csvCell('x\t=1+1')).toBe('"x\t=1+1"');
  });
});
