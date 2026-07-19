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
- **Per document**: a *VEX documents* overview with statement counts and
  one-click removal; the overlay recomputes live as SBOMs and VEX
  documents come and go.

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
  `remediations[].details` the action statement, `threats` of category
  `impact` the impact statement, and the first description/summary note the
  description. `document.tracking` supplies the id, timestamp, and version.
- Products identified **only by CPE** (no purl) match through the CPE key —
  the common case in BSI-CERT advisories. purl stays preferred when both are
  present.

## Matching rules (deliberately conservative)

- Matching happens on **package URLs** (purl) and **CPEs**: the statement's
  `products` (their `@id` or `identifiers.purl`/`.cpe23`/`.cpe22`) and
  `subcomponents` against each element's purl and its SECURITY `cpe22Type`/
  `cpe23Type` external references. Elements with neither never match.
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
programmatic consumer calling `matchVex` with its own list is unaffected). Each finding carries `source` (the document's @id) plus
`sourceFile` as an unambiguous join key, and `supersededCount` says how
many older statements the time rule discarded. `vexCoverage()` quantifies
the counterpart: how many packages are covered, uncovered (matchable purl,
no statement), or unmatchable (no usable purl).

## Limits (deliberate)

- **Matching is by purl and CPE.** CSAF products identified only by a file
  hash are parsed but not matched. CPE matching is name-exact: no NIST-style
  wildcard evaluation, no version ranges, no update/edition comparison — a
  CPE the normalisation cannot pin to a concrete vendor+product stays
  unmatched rather than guessed.
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
