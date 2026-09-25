/**
 * A small XML reader for the subset CycloneDX XML needs: elements,
 * attributes, text, CDATA, comments, processing instructions, the five
 * predefined entities and numeric character references. Nothing else.
 *
 * Deliberately not a general XML parser. Document type declarations are
 * rejected outright (`<!DOCTYPE`, `<!ENTITY`): entity expansion and external
 * references are the classic XML attack surface (billion laughs, XXE), and
 * no BOM needs them. Rejecting them is smaller than configuring a library
 * to be safe, and it keeps the core free of runtime dependencies - the same
 * reason YAML is injected rather than bundled.
 *
 * Namespaces are handled as far as CycloneDX needs: the prefix is split off
 * the element name, and `xmlns` / `xmlns:*` attributes are kept so the
 * caller can read the BOM's schema namespace. Elements from foreign
 * namespaces (say, an enveloped xmldsig `ds:Signature`) still parse; the
 * mapper decides what to do with them.
 */

export interface XmlElement {
  /** Local name, prefix stripped. */
  name: string;
  /** Namespace prefix, if the tag carried one. */
  prefix?: string;
  attrs: Record<string, string>;
  children: XmlElement[];
  /** Concatenated, entity-decoded character data, trimmed. */
  text: string;
}

export type XmlErrorCode = 'XML_INVALID' | 'XML_DOCTYPE_REJECTED' | 'XML_TOO_DEEP';

export class XmlError extends Error {
  constructor(
    readonly code: XmlErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'XmlError';
  }
}

/** Nesting cap; a hostile document must not overflow the worker stack. */
/**
 * Two XML levels per nested CycloneDX assembly (components/component), so
 * this stays above the JSON mapper's 64-assembly cap, which then degrades
 * with CDX_NESTING_CAPPED instead of this hard refusal.
 */
const MAX_DEPTH = 160;

const ENTITIES: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

/** Parses one XML document and returns its root element. Throws XmlError. */
export function parseXml(text: string, options: { maxDepth?: number } = {}): XmlElement {
  const maxDepth = options.maxDepth ?? MAX_DEPTH;
  const s = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const n = s.length;
  let i = 0;
  let root: XmlElement | null = null;
  const stack: XmlElement[] = [];
  const textParts: string[][] = [];

  const fail = (message: string): never => {
    throw new XmlError('XML_INVALID', `${message} (at offset ${i}).`);
  };
  const current = (): XmlElement | null => stack[stack.length - 1] ?? null;
  const appendText = (chunk: string): void => {
    const parts = textParts[textParts.length - 1];
    if (parts && chunk.length > 0) parts.push(chunk);
  };

  while (i < n) {
    if (s[i] !== '<') {
      // Character data up to the next markup. Outside the root only
      // whitespace is allowed.
      const next = s.indexOf('<', i);
      const end = next === -1 ? n : next;
      const raw = s.slice(i, end);
      if (stack.length === 0) {
        if (raw.trim() !== '') fail('Text outside the root element');
      } else {
        appendText(decodeEntities(raw));
      }
      i = end;
      continue;
    }

    if (s.startsWith('<?', i)) {
      const end = s.indexOf('?>', i + 2);
      if (end === -1) fail('Unterminated processing instruction');
      i = end + 2;
      continue;
    }
    if (s.startsWith('<!--', i)) {
      const end = s.indexOf('-->', i + 4);
      if (end === -1) fail('Unterminated comment');
      i = end + 3;
      continue;
    }
    if (s.startsWith('<![CDATA[', i)) {
      const end = s.indexOf(']]>', i + 9);
      if (end === -1) fail('Unterminated CDATA section');
      if (stack.length === 0) fail('CDATA outside the root element');
      appendText(s.slice(i + 9, end));
      i = end + 3;
      continue;
    }
    if (s.startsWith('<!', i)) {
      // <!DOCTYPE ...>, <!ENTITY ...> and friends: refused, never parsed.
      throw new XmlError(
        'XML_DOCTYPE_REJECTED',
        'Document type declarations are not accepted: a BOM needs no DTD, and entity expansion is a known attack surface.',
      );
    }

    if (s.startsWith('</', i)) {
      const end = s.indexOf('>', i + 2);
      if (end === -1) fail('Unterminated closing tag');
      const closing = s.slice(i + 2, end).trim();
      const open = current();
      if (!open) fail(`Closing tag </${closing}> without an open element`);
      const { name, prefix } = splitName(closing);
      if (open!.name !== name || (open!.prefix ?? '') !== (prefix ?? '')) {
        fail(`Closing tag </${closing}> does not match <${qualified(open!)}>`);
      }
      finish(stack.pop()!, textParts.pop()!);
      i = end + 1;
      continue;
    }

    // Opening tag.
    i += 1;
    const nameStart = i;
    while (i < n && !isNameEnd(s[i]!)) i++;
    if (i === nameStart) fail('Element name expected');
    const { name, prefix } = splitName(s.slice(nameStart, i));
    const element: XmlElement = prefix ? { name, prefix, attrs: {}, children: [], text: '' } : { name, attrs: {}, children: [], text: '' };

    // Attributes.
    let selfClosing = false;
    for (;;) {
      while (i < n && isSpace(s[i]!)) i++;
      if (i >= n) fail('Unterminated start tag');
      if (s[i] === '>') {
        i += 1;
        break;
      }
      if (s.startsWith('/>', i)) {
        selfClosing = true;
        i += 2;
        break;
      }
      const attrStart = i;
      while (i < n && !isNameEnd(s[i]!) && s[i] !== '=') i++;
      const attrName = s.slice(attrStart, i);
      if (attrName === '') fail('Attribute name expected');
      while (i < n && isSpace(s[i]!)) i++;
      if (s[i] !== '=') fail(`Attribute "${attrName}" has no value`);
      i += 1;
      while (i < n && isSpace(s[i]!)) i++;
      const quote: '"' | "'" = s[i] === '"' ? '"' : s[i] === "'" ? "'" : fail(`Attribute "${attrName}" value must be quoted`);
      i += 1;
      const valueEnd = s.indexOf(quote, i);
      if (valueEnd === -1) fail(`Unterminated value for attribute "${attrName}"`);
      element.attrs[attrName] = decodeEntities(s.slice(i, valueEnd));
      i = valueEnd + 1;
    }

    const parent = current();
    if (parent) {
      parent.children.push(element);
    } else {
      if (root) fail('More than one root element');
      root = element;
    }
    if (!selfClosing) {
      if (stack.length + 1 > maxDepth) {
        throw new XmlError('XML_TOO_DEEP', `Element nesting exceeds ${maxDepth} levels.`);
      }
      stack.push(element);
      textParts.push([]);
    }
  }

  if (stack.length > 0) fail(`Unclosed element <${qualified(stack[stack.length - 1]!)}>`);
  if (!root) throw new XmlError('XML_INVALID', 'No root element found.');
  return root;
}

function finish(element: XmlElement, parts: string[]): void {
  element.text = parts.join('').trim();
}

function splitName(raw: string): { name: string; prefix?: string } {
  const colon = raw.indexOf(':');
  return colon === -1 ? { name: raw } : { prefix: raw.slice(0, colon), name: raw.slice(colon + 1) };
}

function qualified(element: XmlElement): string {
  return element.prefix ? `${element.prefix}:${element.name}` : element.name;
}

function isSpace(ch: string): boolean {
  return ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r';
}

function isNameEnd(ch: string): boolean {
  return isSpace(ch) || ch === '>' || ch === '/';
}

/**
 * The predefined entities and numeric references. Anything else is left as
 * written: without a DTD there is nothing to expand it with, and keeping the
 * literal is more honest than dropping it.
 */
function decodeEntities(raw: string): string {
  if (raw.indexOf('&') === -1) return raw;
  return raw.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (match, body: string) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    }
    return ENTITIES[body] ?? match;
  });
}
