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
| `SPDX2_SCHEMA_*` | SPDX 2.x (JSON, YAML, tag-value) | 14 |
| `SPDX3_SCHEMA_*` | SPDX 3.0.x (JSON-LD) | 8 |
| `CDX_SCHEMA_*` | CycloneDX 1.x (JSON, XML) | 14 |
| `CSAF_SCHEMA_*` | CSAF 2.x advisories (the overlay, not the SBOM) | 5 |
| `OCM_SCHEMA_*` | OCM component descriptors | 9 |

**SPDX 2.x**: the version literal, `dataLicense` (the spec mandates CC0-1.0),
the `SPDXRef-<idstring>` identifier grammar, `documentNamespace` as an absolute
URI without a fragment, the UTC form of `created`, the
`Person:`/`Organization:`/`Tool:` creator prefix, the mandatory
`downloadLocation`, checksum algorithms and their hex lengths, package
verification codes, purl-typed external references, `primaryPackagePurpose`,
the 45-value relationship vocabulary, license expression grammar, and
`LicenseRef-` identifiers that the document uses but never defines in its
other licensing information (`hasExtractedLicensingInfos`, or a `LicenseID`
block in tag-value; section 10; identifiers compare case-insensitively).
References into another document (`DocumentRef-x:LicenseRef-y`) are that
document's business and stay silent.

Both serializations run the same rules. Tag-value documents are checked on the
parser's intermediates, with two exceptions that the parser reports better
itself: checksums (`TV_BAD_CHECKSUM`) and external document references
(`EXTREF_*`) already come with a line number there.

**SPDX 3.0.x**: nodes without a type, identifiers that are neither an absolute
IRI nor a blank node, elements without `creationInfo`, `specVersion`, hash
shape, relationships without `from`/`relationshipType`, relationship ends
pointing at an id that is neither in the graph nor imported through an
ExternalMap (the SPDX License List IRIs and the vocabulary individuals such as
`NoAssertionLicense` count as known), and `LicenseExpression` elements whose
expression does not parse in the 3.0.1 dialect (lower-case operators and
`AdditionRef-` after WITH are legal there and are mapped to the 2.x
spelling).

**CycloneDX 1.x**: unknown `specVersion`, `serialNumber` that is not a
`urn:uuid:`, non-positive `version`, component types outside the vocabulary,
duplicate `bom-ref`s, hash shape, purls without a `pkg:` scheme, license
entries that are malformed or carry both an `id` and a `name`, and a license
`acknowledgement` outside the 1.6 vocabulary (`declared`, `concluded`). The XML
serialization is mapped onto the JSON shape first, so both run the same rules.

**CycloneDX CBOM** (`cryptoProperties`): a cryptographic asset without
`assetType`, values outside the closed vocabularies (primitive, mode,
padding, execution environment, platform, functions, material type and
state, protocol type), an `algorithmFamily` or `ellipticCurve` the
[CycloneDX Cryptography Registry](https://cyclonedx.org/registry/cryptography/)
does not list (curves are `category/name`, e.g. `nist/P-256`; a bare
`P-256` is reported with the registry spelling), and the 1.6 fields that 1.7
deprecated (`curve`, the per-field refs, `certificateExtension`,
`cryptoRefArray`) when they appear in a 1.7 or later BOM, where they are
still valid. A `cryptographic-asset` component without any
`cryptoProperties` is legal and gets a parser note, not a finding; the
finding is for a block without the required `assetType`. The registry is a
vocabulary and is used as one: a family it does not list yet (FrodoKEM,
Classic McEliece) is reported as unknown, not as wrong, and the crypto
profiles still count such assets by name; a family the registry lists but
the 1.7 JSON-schema enum does not (a few key-derivation families) is named
as such, because a schema validator would reject it.

Findings of one kind are aggregated into a single entry per rule, with a count
and the first three subjects, so a BOM with thousands of components stays
readable and the cost of checking does not grow with the number of offenders.

## What is deliberately not checked

- **License identifiers.** Expressions are checked for *grammar* only —
  operators, parentheses, `LicenseRef-` shape. Whether `MIT` is on the SPDX
  License List is not a spec finding: the list grows with every SPDX release,
  and a document may legitimately use an id newer than the snapshot a build
  carries, so a warning here would age into a false positive. Identifier
  validity is measured by the compliance profiles (`licenseIds` modifier,
  schema v4) and the Licenses view, both backed by a generated list of ids
  and deprecation flags only, matched case-insensitively as Annex D.2 asks;
  the Licenses view and its Markdown export name the list version they used. No
  license texts and no obligations are vendored; rating licenses is a stated
  non-goal.
- **SPDX 3 relationship types.** SPDX 3 defines its own vocabulary, no list is
  vendored, and reusing the 2.3 one would flag legal types like
  `hasDeclaredLicense`. A wrong warning is worse than a missing one.
- **Field presence for a policy.** That is what the compliance profiles
  measure (see [compliance-profiles.md](compliance-profiles.md)). Spec findings
  cover spec legality; the only presence checks here are fields the
  specification itself declares mandatory.
- **Anything detection rejects.** Content detection needs an `SPDX-2*` version
  literal or an `spdx.org/rdf/3.x` context before a document is treated as
  SPDX at all. A file failing that never reaches the lint; it surfaces as an
  unsupported-format message instead.

## Stability

Two things are a contract, not an implementation detail:

- **`isSpecFinding(code)`**, exported from `@sbomlens/core`. The viewer splits
  its diagnostics rows on it, and the CLI makes the same split.
- **The `_SCHEMA_` infix.** Every lint code carries it (`SPDX2_SCHEMA_*`,
  `SPDX3_SCHEMA_*`, `CDX_SCHEMA_*`, `CSAF_SCHEMA_*`, `OCM_SCHEMA_*`), and no
  parser code may. The TR-03191 measurement on CSAF documents is neither: it
  is a list of facts with clause numbers, kept apart from both.
  A test pins that partition over every code the fixtures emit, so an
  accidental collision fails CI instead of silently mislabelling a note as a
  spec violation.

Individual codes are additive: new ones may appear in a minor release,
existing ones do not change meaning. A rule that turns out to produce false
positives is removed rather than quietly loosened, and the removal is noted in
the changelog.

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
