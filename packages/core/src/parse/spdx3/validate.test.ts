import { describe, expect, it } from 'vitest';
import { loadFixture } from '../../test-fixtures';
import { validateSpdx3Structure } from './validate';

/**
 * Spec lint (SPDX3_SCHEMA_*): one negative case per rule, plus the
 * counter-proof that the 3.x fixtures — including the two-document cascade
 * that uses ExternalMap imports — produce ZERO spec findings.
 */

type Node = Record<string, unknown>;

function graphOf(root: Record<string, unknown>): Node[] {
  return (root['@graph'] as Node[]) ?? [];
}

function indexOf(graph: Node[]): Map<string, Node> {
  const byId = new Map<string, Node>();
  for (const node of graph) {
    const id = (node.spdxId ?? node['@id']) as string | undefined;
    if (id) byId.set(id, node);
  }
  return byId;
}

function lint(root: Record<string, unknown>) {
  const graph = graphOf(root);
  return validateSpdx3Structure(graph, indexOf(graph));
}

function codes(root: Record<string, unknown>): string[] {
  return lint(root).map((d) => d.code);
}

/** A spec-clean 3.0.1 document, so each test breaks exactly one thing. */
function clean(graph: Node[] = []): Record<string, unknown> {
  return {
    '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
    '@graph': [
      { type: 'CreationInfo', '@id': '_:creationinfo', specVersion: '3.0.1', created: '2026-07-23T10:00:00Z' },
      {
        type: 'SpdxDocument',
        spdxId: 'https://acme.example/doc/acme-1.0',
        creationInfo: '_:creationinfo',
        name: 'acme',
      },
      {
        type: 'software_Package',
        spdxId: 'https://acme.example/pkg/acme',
        creationInfo: '_:creationinfo',
        name: 'acme',
      },
      ...graph,
    ],
  };
}

describe('validateSpdx3Structure', () => {
  it('passes a clean document', () => {
    expect(codes(clean())).toEqual([]);
  });



  it('reports a graph node without a type', () => {
    expect(codes(clean([{ spdxId: 'https://acme.example/x' }]))).toContain('SPDX3_SCHEMA_MISSING_TYPE');
  });

  it('reports an spdxId that is not an IRI', () => {
    const root = clean([{ type: 'software_File', spdxId: 'file-1', creationInfo: '_:creationinfo' }]);
    expect(codes(root)).toContain('SPDX3_SCHEMA_BAD_SPDXID');
  });

  it('accepts blank node identifiers', () => {
    const root = clean([{ type: 'software_File', spdxId: '_:file1', creationInfo: '_:creationinfo' }]);
    expect(codes(root)).toEqual([]);
  });

  it('reports an element without creationInfo', () => {
    const root = clean([{ type: 'software_File', spdxId: 'https://acme.example/f' }]);
    expect(codes(root)).toContain('SPDX3_SCHEMA_MISSING_CREATION_INFO');
  });

  it('does not require creationInfo on helper objects', () => {
    const root = clean([{ type: 'PositiveIntegerRange', '@id': '_:range', beginIntegerRange: 1 }]);
    expect(codes(root)).toEqual([]);
  });

  it('reports a specVersion that is not SPDX 3', () => {
    const root = clean();
    const creationInfo = (root['@graph'] as Node[])[0];
    if (creationInfo) creationInfo.specVersion = '2.3';
    expect(codes(root)).toContain('SPDX3_SCHEMA_BAD_SPEC_VERSION');
  });

  it('reports a hash whose length does not match its algorithm', () => {
    const root = clean([
      {
        type: 'software_File',
        spdxId: 'https://acme.example/f',
        creationInfo: '_:creationinfo',
        verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'abcd' }],
      },
    ]);
    expect(codes(root)).toContain('SPDX3_SCHEMA_BAD_HASH');
  });

  it('accepts lowercase SPDX 3 hash algorithm names', () => {
    const root = clean([
      {
        type: 'software_File',
        spdxId: 'https://acme.example/f',
        creationInfo: '_:creationinfo',
        verifiedUsing: [{ type: 'Hash', algorithm: 'sha3_256', hashValue: 'a'.repeat(64) }],
      },
    ]);
    expect(codes(root)).toEqual([]);
  });

  it('reports a relationship without from/relationshipType', () => {
    const root = clean([
      { type: 'Relationship', spdxId: 'https://acme.example/rel', creationInfo: '_:creationinfo', to: ['https://acme.example/pkg/acme'] },
    ]);
    expect(codes(root)).toContain('SPDX3_SCHEMA_INCOMPLETE_RELATIONSHIP');
  });

  it('reports a relationship end that points nowhere', () => {
    const root = clean([
      {
        type: 'Relationship',
        spdxId: 'https://acme.example/rel',
        creationInfo: '_:creationinfo',
        from: 'https://acme.example/pkg/acme',
        relationshipType: 'contains',
        to: ['https://acme.example/pkg/ghost'],
      },
    ]);
    expect(codes(root)).toContain('SPDX3_SCHEMA_DANGLING_REF');
  });

  it('accepts a relationship end that an ExternalMap import declares', () => {
    const root = clean([
      {
        type: 'Relationship',
        spdxId: 'https://acme.example/rel',
        creationInfo: '_:creationinfo',
        from: 'https://acme.example/pkg/acme',
        relationshipType: 'contains',
        to: ['https://other.example/pkg/lib'],
        import: [{ type: 'ExternalMap', externalSpdxId: 'https://other.example/pkg/lib' }],
      },
    ]);
    expect(codes(root)).toEqual([]);
  });

  it('keeps every finding a warning', () => {
    const root = clean([{ spdxId: 'not-an-iri' }]);
    const found = lint(root);
    expect(found.length).toBeGreaterThan(0);
    expect(found.every((d) => d.severity === 'warning')).toBe(true);
  });

  describe('counter-proof: shipped 3.x fixtures stay silent', () => {
    it.each(['spdx3/webstack.spdx3.json', 'spdx3/cascade-platform.spdx3.json', 'spdx3/cascade-auth.spdx3.json'])(
      '%s produces no spec findings',
      (fixture) => {
        const root = JSON.parse(loadFixture(fixture)) as Record<string, unknown>;
        expect(lint(root)).toEqual([]);
      },
    );
  });
});
