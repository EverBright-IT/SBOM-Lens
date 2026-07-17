# VEX overlay: what the supplier says about vulnerabilities

> **A communication channel, not a scanner.** SBOM Lens displays what a
> supplier states about known vulnerabilities in their product (VEX,
> Vulnerability Exploitability eXchange). It performs no CVE-database
> lookup, no version-range analysis, and no scanning — if nobody issued a
> statement, the viewer shows nothing, and says so.

Load an [OpenVEX](https://github.com/openvex/spec) document next to your
SBOMs — drop it, pick it, or fetch it from a URL, exactly like any other
file; the content sniff recognizes it — and every statement is matched
against the loaded inventory by package URL.

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

## Matching rules (deliberately conservative)

- Matching happens on **package URLs** (purl): the statement's `products`
  (their `@id` or `identifiers.purl`) and `subcomponents` against each
  element's purl. Elements without a purl never match.
- Normalisation: the purl **type and namespace are case-folded**, the name
  and version compare **exactly** (after percent-decoding); **qualifiers
  and subpath are ignored** on both sides.
- A **versioned** VEX purl matches only that exact version. A
  **versionless** VEX purl covers every version of the package. There is
  no version-range interpretation.
- A `subcomponents` match marks the inner package and is labeled *via
  subcomponent*.

## Multiple documents and conflicts

Load as many VEX documents as you like. When several statements target the
same (vulnerability, package) pair, the one with the **newest timestamp**
wins — the OpenVEX time rule; a statement's own timestamp beats the
document's. Re-loading a document with the same `@id` replaces the earlier
version.

## Limits (deliberate)

- **OpenVEX only** for now (JSON, current shape and the early spec's
  string forms). CSAF 2.0 — the BSI exchange format — needs product-tree
  resolution and is a planned follow-up, not a quick variant.
- Statements that name no products, carry an unknown status, or are
  malformed are skipped with a diagnostic — the overlay never guesses.
- VEX documents are capped at 4 MB (real ones are kilobytes).
- The overlay lives outside the document model: exports of the SBOM itself
  are unaffected, and removing the VEX document removes every trace.

The demo cascade ships a synthetic advisory
(`examples/acme-advisories.openvex.json`, fictional CVE ids marked as
demo data) — *Load example* in the SBOM flavor shows the whole overlay in
one click.
