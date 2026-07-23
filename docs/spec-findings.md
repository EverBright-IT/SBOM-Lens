# Spec findings

SBOM Lens parses tolerantly: a document that breaks a rule still loads, and
what could not be read becomes a diagnostic instead of a refusal. That answers
"can I look at this?" but not "is this document actually correct?".

Spec findings answer the second question. They are structural checks against
the specification a document claims to follow, reported next to the document
rather than instead of it.

## What you see

The document detail shows two separate rows, because they mean different
things:

- **Spec findings** — the document violates its own specification. A
  relationship type outside the vocabulary, a digest that cannot be a digest,
  a license expression no tool can parse.
- **Parser notes** — SBOM Lens had trouble reading something: a skipped
  malformed entry, an unresolved reference, a capped nesting level.

Both open the diagnostics drawer, pre-filtered to what the row counted. The
drawer has a "Spec findings only" toggle and tags spec rows, so the two stay
distinguishable in a mixed list.

Every spec finding is a **warning**. Nothing in this feature can stop a
document from loading, and nothing here fails a build.

## What is checked

Findings carry a stable code with a `_SCHEMA_` infix, prefixed by the format:

| Prefix | Format | Rules |
|---|---|---|
| `SPDX2_SCHEMA_*` | SPDX 2.x (JSON, YAML) | 13 |
| `SPDX3_SCHEMA_*` | SPDX 3.0.x (JSON-LD) | 7 |
| `CDX_SCHEMA_*` | CycloneDX 1.x (JSON) | 8 |
| `OCM_SCHEMA_*` | OCM component descriptors | 9 |

**SPDX 2.x**: the version literal, `dataLicense` (the spec mandates CC0-1.0),
the `SPDXRef-<idstring>` identifier grammar, `documentNamespace` as an absolute
URI without a fragment, the UTC form of `created`, the
`Person:`/`Organization:`/`Tool:` creator prefix, the mandatory
`downloadLocation`, checksum algorithms and their hex lengths, package
verification codes, purl-typed external references, `primaryPackagePurpose`,
the 45-value relationship vocabulary, and license expression grammar.

**SPDX 3.0.x**: nodes without a type, identifiers that are neither an absolute
IRI nor a blank node, elements without `creationInfo`, `specVersion`, hash
shape, relationships without `from`/`relationshipType`, and relationship ends
pointing at an id that is neither in the graph nor imported through an
ExternalMap.

**CycloneDX 1.x**: unknown `specVersion`, `serialNumber` that is not a
`urn:uuid:`, non-positive `version`, component types outside the vocabulary,
duplicate `bom-ref`s, hash shape, purls without a `pkg:` scheme, and license
entries that are malformed or carry both an `id` and a `name`.

Findings of one kind are aggregated into a single entry with a count and the
first three subjects, so a BOM with thousands of components stays readable.

## What is deliberately not checked

- **License identifiers.** Expressions are checked for *grammar* only —
  operators, parentheses, `LicenseRef-` shape. Whether `MIT` is a real license
  id is not checked; no SPDX license list is vendored, and rating licenses is
  a stated non-goal.
- **SPDX 3 relationship types.** SPDX 3 defines its own vocabulary, no list is
  vendored, and reusing the 2.3 one would flag legal types like
  `hasDeclaredLicense`. A wrong warning is worse than a missing one.
- **Field presence for a policy.** That is what the compliance profiles
  measure (see [compliance-profiles.md](compliance-profiles.md)). Spec findings
  cover spec legality; the only presence checks here are fields the
  specification itself declares mandatory.
- **SPDX tag-value.** The tag-value parser reports malformed input with line
  numbers already; the structural rules run on the JSON and YAML
  serializations for now.
- **Anything detection rejects.** Content detection needs an `SPDX-2*` version
  literal or an `spdx.org/rdf/3.x` context before a document is treated as
  SPDX at all. A file failing that never reaches the lint; it surfaces as an
  unsupported-format message instead.

## When you need authoritative verification

These findings are a high-signal subset for reading a document, not a
conformance verdict. For an authoritative check, use the SPDX project's own
reference implementation:

- [spdx/tools-java](https://github.com/spdx/tools-java) — its `Verify`
  command validates against the full typed SPDX model (2.x and 3.x) via
  [Spdx-Java-Library](https://github.com/spdx/Spdx-Java-Library), covers every
  serialization including RDF/XML and spreadsheets, and validates license
  identifiers against the official SPDX license list, which the library
  bundles and can refresh from spdx.org.
- [tools.spdx.org](https://tools.spdx.org/) — the same validation online.

The two are complementary, and the split mirrors how the compliance profiles
relate to sbomqs: the reference tool owns breadth and authority, SBOM Lens
owns immediacy. Spec findings appear while you read the document, need no
install, work offline, and cover CycloneDX and OCM in the same idiom. When a
finding matters for a contract or an audit, confirm it with tools-java.
