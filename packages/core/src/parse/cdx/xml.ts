import type { XmlElement } from '../xml/tokenizer';

/**
 * CycloneDX XML → the JSON-shaped object `parseCdxJson` already reads.
 *
 * The two serializations describe the same model, so rather than a second
 * mapper the XML is turned into the JSON form and handed to the existing
 * one; the spec lint then covers both for free. The conversion has to know
 * the schema, though: XML puts `type`, `bom-ref`, `alg`, `acknowledgement`
 * and friends in attributes, wraps every list in a container element
 * (`<components><component>`), and nests dependencies as elements instead
 * of a `dependsOn` array. A generic xml2json would get all of that wrong.
 *
 * `bomFormat` and `specVersion` do not exist in XML; both come from the
 * schema namespace `http://cyclonedx.org/schema/bom/<version>`. Unknown
 * 1.x versions are passed through on purpose so the lint's
 * UNKNOWN_SPEC_VERSION can report them instead of the detector hiding them.
 */

const NAMESPACE = /^http:\/\/cyclonedx\.org\/schema\/bom\/(\d+\.\d+)$/;

/** Returns null when the root is not a CycloneDX `<bom>` in a CycloneDX namespace. */
export function bomObjectFromXml(root: XmlElement): Record<string, unknown> | null {
  if (root.name !== 'bom') return null;
  const xmlns = root.prefix ? root.attrs[`xmlns:${root.prefix}`] : root.attrs.xmlns;
  const version = xmlns ? NAMESPACE.exec(xmlns)?.[1] : undefined;
  if (!version) return null;

  const bom: Record<string, unknown> = { bomFormat: 'CycloneDX', specVersion: version };
  setIf(bom, 'serialNumber', root.attrs.serialNumber);
  if (root.attrs.version !== undefined) {
    // Numeric when it is one; anything else is left for the lint to flag.
    bom.version = /^\d+$/.test(root.attrs.version) ? Number(root.attrs.version) : root.attrs.version;
  }

  for (const child of ownChildren(root)) {
    switch (child.name) {
      case 'metadata':
        bom.metadata = readMetadata(child);
        break;
      case 'components':
        bom.components = ownChildren(child).filter((c) => c.name === 'component').map(readComponent);
        break;
      case 'dependencies':
        bom.dependencies = readDependencies(child);
        break;
      case 'externalReferences':
        bom.externalReferences = readExternalReferences(child);
        break;
      case 'properties':
        bom.properties = readProperties(child);
        break;
      default:
        // Anything else (services, compositions, vulnerabilities, ...) is
        // converted generically so it stays visible in the source view.
        bom[child.name] = generic(child);
    }
  }
  return bom;
}

function readMetadata(el: XmlElement): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const child of ownChildren(el)) {
    switch (child.name) {
      case 'timestamp':
        setIf(out, 'timestamp', child.text);
        break;
      case 'component':
        out.component = readComponent(child);
        break;
      case 'tools': {
        // 1.5+: <tools><components><component>...; legacy: <tools><tool>...
        const components = ownChildren(child).find((c) => c.name === 'components');
        if (components) {
          out.tools = { components: ownChildren(components).filter((c) => c.name === 'component').map(readComponent) };
        } else {
          out.tools = ownChildren(child)
            .filter((c) => c.name === 'tool')
            .map((tool) => readNamed(tool, ['vendor', 'name', 'version']));
        }
        break;
      }
      case 'authors':
        out.authors = ownChildren(child)
          .filter((c) => c.name === 'author')
          .map((a) => readNamed(a, ['name', 'email', 'phone']));
        break;
      case 'supplier':
      case 'manufacturer':
      case 'manufacture':
        out[child.name] = readNamed(child, ['name']);
        break;
      case 'lifecycles':
        out.lifecycles = ownChildren(child)
          .filter((c) => c.name === 'lifecycle')
          .map((l) => readNamed(l, ['phase', 'name', 'description']));
        break;
      case 'properties':
        out.properties = readProperties(child);
        break;
      default:
        out[child.name] = generic(child);
    }
  }
  return out;
}

function readComponent(el: XmlElement): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  setIf(out, 'type', el.attrs.type);
  setIf(out, 'bom-ref', el.attrs['bom-ref']);
  for (const child of ownChildren(el)) {
    switch (child.name) {
      case 'supplier':
      case 'manufacturer':
        out[child.name] = readNamed(child, ['name']);
        break;
      case 'authors':
        // <authors><author><name>..</name></author></authors>, the 1.6 list
        // the JSON mapper reads as the originator.
        out.authors = ownChildren(child)
          .filter((c) => c.name === 'author')
          .map((a) => readNamed(a, ['name', 'email']));
        break;
      case 'hashes':
        out.hashes = ownChildren(child)
          .filter((c) => c.name === 'hash')
          .map((h) => ({ alg: h.attrs.alg, content: h.text }));
        break;
      case 'licenses':
        out.licenses = readLicenses(child);
        break;
      case 'externalReferences':
        out.externalReferences = readExternalReferences(child);
        break;
      case 'properties':
        out.properties = readProperties(child);
        break;
      case 'components':
        out.components = ownChildren(child).filter((c) => c.name === 'component').map(readComponent);
        break;
      case 'cryptoProperties':
        out.cryptoProperties = readCryptoProperties(child);
        break;
      case 'name':
      case 'version':
      case 'description':
      case 'purl':
      case 'cpe':
      case 'copyright':
      case 'publisher':
      case 'author':
      case 'group':
      case 'scope':
      case 'mime-type':
        setIf(out, child.name, child.text);
        break;
      default:
        out[child.name] = generic(child);
    }
  }
  return out;
}

/**
 * `<licenses>` holds either `<license>` entries (id or name, optional text)
 * or `<expression>` entries; `acknowledgement` is an attribute on either.
 * Shaped exactly like the JSON form so the declared/concluded split works.
 */
function readLicenses(el: XmlElement): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const entry of ownChildren(el)) {
    if (entry.name === 'expression') {
      const item: Record<string, unknown> = { expression: entry.text };
      setIf(item, 'acknowledgement', entry.attrs.acknowledgement);
      out.push(item);
    } else if (entry.name === 'license') {
      const license: Record<string, unknown> = {};
      for (const field of ownChildren(entry)) {
        if (field.name === 'id' || field.name === 'name' || field.name === 'url') setIf(license, field.name, field.text);
        else if (field.name === 'text') license.text = { content: field.text, ...attrsOf(field) };
      }
      setIf(license, 'acknowledgement', entry.attrs.acknowledgement);
      setIf(license, 'bom-ref', entry.attrs['bom-ref']);
      out.push({ license });
    }
  }
  return out;
}

function readExternalReferences(el: XmlElement): Record<string, unknown>[] {
  return ownChildren(el)
    .filter((c) => c.name === 'reference')
    .map((ref) => {
      const out: Record<string, unknown> = {};
      setIf(out, 'type', ref.attrs.type);
      for (const field of ownChildren(ref)) {
        if (field.name === 'url' || field.name === 'comment') setIf(out, field.name, field.text);
        else if (field.name === 'hashes') {
          out.hashes = ownChildren(field)
            .filter((c) => c.name === 'hash')
            .map((h) => ({ alg: h.attrs.alg, content: h.text }));
        }
      }
      return out;
    });
}

function readProperties(el: XmlElement): Record<string, unknown>[] {
  return ownChildren(el)
    .filter((c) => c.name === 'property')
    .map((p) => ({ name: p.attrs.name, value: p.text }));
}

/** `<dependency ref="a"><dependency ref="b"/></dependency>` → { ref: a, dependsOn: [b] }. */
/**
 * `<dependency ref="a"><dependency ref="b"><dependency ref="c"/></dependency></dependency>`:
 * the XSD nests dependencies recursively, the JSON form lists them flat, so
 * every nested element with children of its own becomes an entry too.
 */
function readDependencies(el: XmlElement): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  const stack = ownChildren(el).filter((c) => c.name === 'dependency');
  while (stack.length > 0) {
    const node = stack.shift()!;
    const entry: Record<string, unknown> = {};
    setIf(entry, 'ref', node.attrs.ref);
    const children = ownChildren(node).filter((c) => c.name === 'dependency');
    entry.dependsOn = children
      .map((c) => c.attrs.ref)
      .filter((ref): ref is string => typeof ref === 'string' && ref.length > 0);
    const provides = ownChildren(node)
      .filter((c) => c.name === 'provides')
      .map((c) => c.attrs.ref)
      .filter((ref): ref is string => typeof ref === 'string' && ref.length > 0);
    if (provides.length > 0) entry.provides = provides;
    out.push(entry);
    for (const child of children) if (ownChildren(child).length > 0) stack.push(child);
  }
  return out;
}

/**
 * `<cryptoProperties>` into the JSON shape: the generic reader, with the
 * XML list wrappers (`<cryptoFunctions><cryptoFunction>`, `<cipherSuites>
 * <cipherSuite>`, `<relatedCryptographicAssets><relatedCryptographicAsset>`,
 * ...) unwrapped into the arrays the JSON schema uses, so one reader in the
 * JSON mapper serves both serializations.
 */
function readCryptoProperties(el: XmlElement): Record<string, unknown> {
  const value = generic(el);
  const out = isPlainObject(value) ? value : {};
  // <wrapper><item>..</item></wrapper> lists (XSD 1.6/1.7).
  const listWrappers: Record<string, string> = {
    cryptoFunctions: 'cryptoFunction',
    certificateExtensions: 'certificateExtension',
    relatedCryptographicAssets: 'relatedCryptographicAsset',
    cipherSuites: 'cipherSuite',
    algorithms: 'algorithm',
    identifiers: 'identifier',
  };
  // Elements the XSD repeats directly, without a wrapper; one occurrence
  // must read as a one-element list.
  const repeated = new Set(['certificationLevel', 'certificateState', 'cryptoRef']);
  // <fingerprint alg="..">hex</fingerprint> is a hashType, like <hash>.
  const hashLike = new Set(['fingerprint']);
  const unwrap = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(unwrap);
    if (!isPlainObject(node)) return node;
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(node)) {
      const item = listWrappers[key];
      if (item !== undefined && isPlainObject(child) && item in child) {
        const inner = child[item];
        result[key] = (Array.isArray(inner) ? inner : [inner]).map(unwrap);
      } else if (repeated.has(key)) {
        const list = (Array.isArray(child) ? child : [child]).map(unwrap);
        // 1.6 XML spells the protocol references <cryptoRef>; the JSON field
        // (and the 1.7 deprecation) is cryptoRefArray.
        result[key === 'cryptoRef' ? 'cryptoRefArray' : key] = list;
      } else if (hashLike.has(key) && isPlainObject(child)) {
        result[key] = { alg: child.alg, content: child['#text'] };
      } else {
        result[key] = unwrap(child);
      }
    }
    return result;
  };
  return unwrap(out) as Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Simple `<name>`, `<version>`, ... children into an object. */
function readNamed(el: XmlElement, fields: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const child of ownChildren(el)) {
    if (fields.includes(child.name)) setIf(out, child.name, child.text);
  }
  return out;
}

/**
 * Generic fallback for subtrees the mapper does not model: leaf → text,
 * attributes as keys, repeated sibling names → array. Good enough for the
 * source view and for a later reader (e.g. cryptoProperties) to build on.
 */
function generic(el: XmlElement): unknown {
  const children = ownChildren(el);
  if (children.length === 0) {
    const attrs = attrsOf(el);
    return Object.keys(attrs).length === 0 ? el.text : { ...attrs, ...(el.text ? { '#text': el.text } : {}) };
  }
  const out: Record<string, unknown> = attrsOf(el);
  const counts = new Map<string, number>();
  for (const child of children) counts.set(child.name, (counts.get(child.name) ?? 0) + 1);
  for (const child of children) {
    const value = generic(child);
    if ((counts.get(child.name) ?? 0) > 1) {
      const list = (out[child.name] as unknown[] | undefined) ?? [];
      list.push(value);
      out[child.name] = list;
    } else {
      out[child.name] = value;
    }
  }
  return out;
}

/** Children in the BOM's own namespace: foreign-namespace elements (xmldsig etc.) are skipped. */
function ownChildren(el: XmlElement): XmlElement[] {
  return el.children.filter((c) => (c.prefix ?? '') === (el.prefix ?? ''));
}

function attrsOf(el: XmlElement): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(el.attrs)) {
    if (key === 'xmlns' || key.startsWith('xmlns:')) continue;
    out[key] = value;
  }
  return out;
}

function setIf(target: Record<string, unknown>, key: string, value: string | undefined): void {
  if (value !== undefined && value !== '') target[key] = value;
}
