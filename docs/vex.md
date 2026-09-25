# VEX overlay: what the supplier says about vulnerabilities

> **A communication channel, not a scanner.** SBOM Lens displays what a
> supplier states about known vulnerabilities in their product (VEX,
> Vulnerability Exploitability eXchange). It performs no CVE-database
> lookup, no version-range analysis, and no scanning — if nobody issued a
> statement, the viewer shows nothing, and says so.

Load an [OpenVEX](https://github.com/openvex/spec) or
[CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
document next to your SBOMs — drop it, pick it, or fetch it from a URL,
exactly like any other file; the content sniff recognizes both — and every
statement is matched against the loaded inventory by package URL. The two
formats share one overlay: load them together and their findings merge,
arbitrated by the same time rule.

## What you see

- **Per package**: a *Vulnerability communication* section in the detail
  pane listing each vulnerability with the supplier's status, justification,
  impact and action statements, the issuing document, and the statement
  date.
- **Inventory**: a VEX column with the package's worst status, status
  filter chips (including *no statement*), and both exports (CSV/JSON)
  carry the findings.
- **Per document**: a *VEX and advisory documents* overview with format,
  profile, TLP label, statement counts, the TR-03191 measurement for CSAF
  and one-click removal; the overlay recomputes live as SBOMs and
  advisories come and go. Advisories dropped before any SBOM are listed
  on the start screen until an inventory arrives.

Statuses render exactly as OpenVEX defines them: `affected` (red),
`under_investigation` (amber), `fixed` (emerald), `not_affected` (slate).
Each loaded document is tagged **OpenVEX** or **CSAF** in the overview.

## CSAF 2.0: product-tree resolution

CSAF separates identity from assertion. A `product_tree` names products —
through `full_product_names`, a recursive `branches` tree, and
`relationships` — and hangs a `product_identification_helper` on each; the
`vulnerabilities[].product_status` buckets then reference those products by
id. SBOM Lens resolves that indirection before matching:

- The four buckets map onto the VEX statuses: `known_affected` →
  *affected*, `known_not_affected` → *not affected*, `fixed` → *fixed*,
  `under_investigation` → *under investigation*.
- A **relationship** product (e.g. *openssl as a component of api-server*)
  resolves to the **component** it installs (`product_reference`) — that is
  the package that appears in an SBOM — unless it carries its own
  identifier.
- `flags` become the justification (they share OpenVEX's vocabulary),
  `remediations` stay structured (category, details, link, date, restart
  requirement; the first details text doubles as the action statement),
  `threats` of category `impact` the impact statement, and the first
  description/summary note the description. `document.tracking` supplies
  the id, timestamp, version and status; `document.category` (the profile),
  `title` and the TLP label are shown next to the document.
- Annotations aimed at a `group_ids` entry resolve through `product_groups`
  to the members; an annotation without any product or group applies to
  every product of that vulnerability, one aimed at an unknown group to
  nobody.
- Products identified **only by CPE** (no purl) match through the CPE key,
  the common case in BSI-CERT advisories. purl stays preferred when both are
  present. Products carrying **file hashes** in the
  `product_identification_helper` match against the checksums of the loaded
  elements, which is the link BSI TR-03191 section 4.4 asks for and works
  when no purl exists at all.
- The base and informational profiles carry no vulnerabilities; they load
  as documents with no statements, so an advisory folder loads whole.

## BSI TR-03191 measured

Every CSAF document is measured against the machine-checkable clauses of
[BSI TR-03191](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03191/BSI-TR-03191.html)
(v1.0.1): a CVE and a CVSS for every vulnerability, the Security Advisory,
VEX or Security Incident Response profile, fixing versions as `fixed`,
`first_fixed` or `recommended` status next to the affected ones (or a
no-fix remediation), the TLP label (4.3), a vendor / product_name /
product_version tree, file hashes of the referenced products (4.4, "where
an SBOM is mandatory", resolved through relationships like the matcher
does), and `current_release_date` with a `revision_history` (4.6). The
result is a list of facts with clause numbers under each document, never a
conformance verdict. A clause with nothing to apply to (no vulnerabilities,
no referenced products) reads as not applicable rather than as failed, and
the count of version ranges is reported without a verdict, because the TR
allows ranges where enumeration is impossible and a file cannot show which
case applies. Distribution as a trusted provider, signature validity
windows and the 48-hour reaction to BSI warnings cannot be read off a file
and are not measured.

A handful of CSAF schema facts this reader relies on are reported as spec
findings (`CSAF_SCHEMA_*`): the 2.x version, the mandatory tracking and
publisher fields, the CVE id pattern, product ids referenced anywhere but
never defined in the product tree (mandatory test 6.1.1), and remediations
or flags that name no product (6.1.29, 6.1.32). This is not a schema
validator; the OASIS csaf-validator owns that.

## Matching rules (deliberately conservative)

- Matching happens on **package URLs** (purl), **CPEs** and, for CSAF,
  **file hashes**: the statement's `products` (their `@id` or
  `identifiers.purl`/`.cpe23`/`.cpe22`, or the hashes of a CSAF
  `product_identification_helper`) and `subcomponents` against each
  element's purl, its SECURITY `cpe22Type`/`cpe23Type` external references
  and, for packages, its checksums. A finding says which key matched
  (`matchedBy`: purl, cpe or hash); a product reachable through several
  keys yields one finding, attributed to the first of purl, CPE, hash.
  Elements with none of these never match.
- Normalisation: the purl **type and namespace are case-folded**, the name
  and version compare **exactly** (after percent-decoding); **qualifiers
  and subpath are ignored** on both sides.
- A **versioned** VEX purl matches only that exact version. A
  **versionless** VEX purl covers every version of the package. There is
  no version-range interpretation.
- **CPEs** (2.3 formatted strings and 2.2 URIs) normalise onto
  `part:vendor:product`, case-folded and unescaped — both forms match each
  other. The same version rule applies (`*`, `-`, or absent = every
  version); update/edition/target attributes are ignored, and a wildcarded
  vendor or product never matches (that would be a guess, not a statement).
- A `subcomponents` match marks the inner package and is labeled *via
  subcomponent*.

## Multiple documents and conflicts

Load as many VEX documents as you like. When several statements target the
same (vulnerability, package) pair, the one with the **newest timestamp**
wins — the OpenVEX time rule; a statement's own timestamp beats the
document's. Ties fall to the later-loaded document, so the hand-over
**order is part of the contract**: the app matches in ingest order, and a
programmatic consumer should sort its inputs stably (e.g. by path) before
calling `matchVex`. Re-loading a document with the same `@id` replaces the
earlier version — deliberately, so an updated advisory supersedes its
predecessor. The flip side: two *different* advisories that sloppily share
one `@id` displace each other in the viewer. OpenVEX requires document ids
to be unique; if you need both loaded, give them distinct `@id`s (a
programmatic consumer calling `matchVex` with its own list is unaffected).
A CSAF document is keyed by publisher namespace plus tracking id, the
globally unique form the standard defines, so two publishers reusing one
tracking id never displace each other. Each finding carries `source` (the
document's id) plus `sourceFile` as an unambiguous join key, and
`supersededCount` says how many older statements the time rule discarded.
`vexCoverage()` quantifies the counterpart: how many packages are covered,
uncovered (a purl or CPE to match on, no statement), or unmatchable (no
usable purl or CPE; a checksum alone does not count, because advisories
rarely carry file hashes, but a package that matched by hash counts as
covered).

## Limits (deliberate)

- **Matching is by purl, CPE and file hash.** CPE matching is name-exact:
  no NIST-style wildcard evaluation, no version ranges, no update/edition
  comparison; a CPE the normalisation cannot pin to a concrete
  vendor+product stays unmatched rather than guessed. A hash matches only
  the package whose checksum is byte-identical (files are not matched by
  hash: a product hash names a delivered artifact, and every file with the
  same bytes would otherwise carry the statement); there is no version
  dimension to widen.
- **Annotations reach only the products they name.** A CSAF remediation or
  flag without `product_ids` or `group_ids` is a schema violation (mandatory
  tests 6.1.29 and 6.1.32), reported as such, and applied to nobody; a
  threat without either describes the vulnerability for every product.
- CSAF `relationships` are resolved one level deep (to the component); a
  relationship whose reference is itself another relationship is not
  chased further.
- Statements that name no products, carry an unknown status, or are
  malformed are skipped with a diagnostic — the overlay never guesses.
- OpenVEX documents are capped at 4 MB; CSAF (larger product trees) at
  8 MB.
- The overlay lives outside the document model: exports of the SBOM itself
  are unaffected, and removing the VEX document removes every trace.

The demo cascade ships two synthetic advisories over the same packages —
`examples/acme-advisories.openvex.json` and
`examples/acme-advisories.csaf.json` (fictional CVE ids marked as demo
data) — so *Load example* in the SBOM flavor shows both formats in one
overlay with one click.
