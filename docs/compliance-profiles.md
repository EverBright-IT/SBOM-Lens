# Compliance profiles

SBOM Lens ships the [NTIA minimum elements (2021)](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom) as its default quality
report, and
lets every organization define its **own** minimum elements as a small JSON
file. The active profile drives the Quality section of each document and its
Markdown export; nothing else in the app changes.

Profiles are pure data. There is no code execution, and license checks stay
field-level (presence, patterns): SBOM Lens does not do legal interpretation.

## Format (`sbomlens-profile/v1`, `v2`)

```json
{
  "schema": "sbomlens-profile/v1",
  "name": "ACME SBOM Baseline",
  "description": "Minimum evidence for third-party deliveries.",
  "checks": [
    { "type": "document-field", "field": "creators" },
    { "type": "document-field", "field": "namespace", "pattern": "^https://sbom\\.acme\\.example/" },
    { "type": "document-field", "field": "dataLicense", "values": ["CC0-1.0"] },
    { "type": "created-recency", "maxAgeDays": 180 },
    { "type": "relationships", "minCount": 1 },
    { "type": "package-coverage", "field": "version", "threshold": 100 },
    { "type": "package-coverage", "field": "supplier", "threshold": 95, "pattern": "^Organization: ACME" },
    { "type": "package-coverage", "field": "purpose", "threshold": 100, "values": ["APPLICATION", "CONTAINER"] },
    { "type": "package-coverage", "field": "checksum", "threshold": 100 },
    { "type": "package-coverage", "field": "downloadLocation" }
  ]
}
```

### Check types

| Type | Checks | Fields |
| --- | --- | --- |
| `document-field` | the field is present (and matches the modifiers) | `name`, `namespace`, `created`, `creators`, `dataLicense`, `comment`; v4: `sbomType`, `describes`, `externalDocumentRefs` |
| `relationships` | the document has at least `minCount` (default 1) relationships | - |
| `created-recency` | `created` parses and is at most `maxAgeDays` old (boundary inclusive) | - |
| `package-coverage` | the share of packages satisfying the field (and modifiers) reaches `threshold` % | `version`, `supplier`, `purl`, `uniqueId`, `checksum`, `license`, `downloadLocation`, `purpose`, `copyright`, `originator`; v4: `fileName`, `supportLevel`, `validUntil`, `licenseDeclared`, `licenseConcluded`, `properties` |

### Modifiers and semantics

- **`pattern`**: a regular expression the value must match. `RegExp.test` is
  a substring match: anchor with `^...$` when you mean the full value. No
  flags in v1 (matching is case-sensitive).
- **`values`**: exact-match allow-list. Combined with `pattern` via AND.
- **`creators`** is an array: SOME semantics: at least one creator must
  satisfy the modifiers.
- **`threshold`** on `package-coverage` is optional. Without it the check is
  an informational meter and never fails. Gating is exact
  (cross-multiplication): a displayed 95% can still fail a `95` threshold if
  the true ratio is 94.9%.
- `supplier`, `downloadLocation`, `copyright`, `originator` treat
  `NOASSERTION`/`NONE` as absent. `license` uses the concluded license,
  falling back to declared. `uniqueId` means purl **or** any external ref;
  `pattern`/`values` do not apply to `uniqueId`/`checksum`.
- Documents without packages pass coverage checks vacuously (and the Quality
  section stays hidden, as before).

### Schema v2: checksum algorithms

`sbomlens-profile/v2` adds one modifier: **`algorithms`** on
`package-coverage` with `field: "checksum"`. Only a checksum whose algorithm
is in the list (case and dash insensitive: `"SHA512"` equals `"SHA-512"`)
satisfies the check:

```json
{ "schema": "sbomlens-profile/v2", "name": "hash policy", "checks": [
  { "type": "package-coverage", "field": "checksum", "threshold": 100, "algorithms": ["SHA512"] }
] }
```

A profile using `algorithms` MUST declare `v2`. This is deliberate: engines
released before v2 ignore keys they do not know, so under `v1` they would
evaluate the check as a plain presence check and report a false pass. The
`v2` schema id makes them reject the profile outright instead. Everything
else is unchanged between v1 and v2; v1 profiles keep working as-is.

### Schema v3: format preconditions

`sbomlens-profile/v3` adds one profile-level field: **`requires`**. It
states a hard precondition of the requirement source itself and evaluates
as a leading **gated** check, before any field check:

```json
{ "schema": "sbomlens-profile/v3", "name": "spdx3 policy",
  "requires": { "spec": "spdx-3" },
  "checks": [ { "type": "relationships" } ] }
```

With `{ "spec": "spdx-3" }`, an SPDX 2.x document fails a visible
"Format baseline: SPDX 3.0.1 or later" check instead of rendering an
all-green report for a format the requirement source does not accept.
The same fail-closed reasoning applies as for v2: an older engine would
ignore `requires` and silently under-check, so the field demands the `v3`
schema id. v3 includes everything from v2.

### Schema v4: lifecycle and licensing fields, informational checks

`sbomlens-profile/v4` adds what the 2026 requirement sources ask for and
the earlier fields could not express:

- **Package fields** `fileName` (SPDX packageFileName), `supportLevel`
  (SPDX 3 supportLevel, or a CycloneDX property named `support-level`,
  optionally prefixed `fda:lifecycle:`), `validUntil` (SPDX 2.3
  ValidUntilDate, SPDX 3 validUntilTime, or a CycloneDX property named
  `end-of-support` / `eol` / `eos` / `valid-until`), `licenseDeclared` and
  `licenseConcluded` (the two licence fields separately; `license` remains
  "concluded, else declared"), and `properties` (CycloneDX `properties[]`
  rendered as `name=value` lines so a `pattern` can target one property).
- **Document fields** `sbomType` (SPDX 3 sbomType or the first CycloneDX
  lifecycle phase; absent in SPDX 2.x), `describes` (a primary component
  is declared), `externalDocumentRefs` (other SBOMs are referenced).
- **`informational: true`** on `document-field`, `relationships` and
  `created-recency`: the check reports pass or fail but never counts as a
  gate. Before v4 every boolean check gated by construction; guidance
  documents describe facts worth showing without turning them into a
  verdict. (Coverage checks stay informational by omitting `threshold`.)
- **`licenseIds`** on `license`, `licenseDeclared` and `licenseConcluded`:
  `"known"` requires every identifier in the expression to be on the SPDX
  License List; `"known-or-ref"` also accepts `LicenseRef-...` (the form
  BSI TR-03183-2 prescribes for the ScanCode LicenseDB fallback). The
  exception after `WITH` is not a licence and is not checked. The list is
  generated from `spdx-license-ids` and carries identifiers and their
  deprecation flag, nothing else: whether a licence is acceptable is not a
  question this engine answers. **`allowDeprecated: false`** additionally
  fails identifiers the list marks deprecated (default: they count).

```json
{ "schema": "sbomlens-profile/v4", "name": "licence identifiers",
  "checks": [
    { "type": "package-coverage", "field": "licenseDeclared", "threshold": 100,
      "licenseIds": "known-or-ref" },
    { "type": "document-field", "field": "sbomType", "informational": true } ] }
```

New field tokens are rejected below v4 by the whitelist; the schema id
exists for the two modifiers, which an older engine would otherwise drop
silently. v4 includes everything from v3.

### Validation is fail-closed

An unknown check type or field rejects the **whole** profile with a list of
errors: an older SBOM Lens will never half-evaluate a newer profile and
report a false "pass". Limits: 200 checks, 64 KB per file, patterns ≤ 500
chars (must compile), ids unique, `algorithms` ≤ 8 entries.

## Importing a profile

- **Drop it into the window** (or *Open → Compliance profile...*). Detection is
  content-based (the `schema` field), not by file name. Imported profiles
  persist in the browser/editor and auto-activate.
- **Deployment catalog**: `sbomlens.catalog.json` may list profiles the
  instance rolls out to everyone (never auto-activated):

  ```json
  { "profiles": [{ "name": "ACME minimum elements", "url": "profiles/acme.json" }] }
  ```

- **VS Code**: put `.sbomlens/profile.json` into the workspace; the
  extension pushes it into every SBOM Lens panel automatically. In **OCM
  Lens** the same mechanism reads `.ocmlens/profile.json`: each product
  keeps its own directory so both can live in one workspace with different
  rules.

Switch profiles in the Quality section's dropdown; `×` removes an imported
profile (falls back to the builtin: NTIA minimum elements (2021) in SBOM Lens,
OCM component essentials in OCM Lens); **Export** writes the current report
as Markdown for audits. Up to 16 imported profiles (256 KB total) persist;
anything beyond that stays session-only with a notice.

## Builtin presets

Besides the default (NTIA minimum elements (2021) for SPDX documents, OCM
component essentials for component descriptors), the dropdown offers:

- **[CISA 2026 minimum elements](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom)**: the data fields of the *2026 Minimum
  Elements for a Software Bill of Materials* (CISA, NSA, FBI and 16
  international partners including the BSI, 29 July 2026), which
  **updates and replaces** the 2021 NTIA minimum elements. Nine checks
  cover eleven of the seventeen data fields in the document's Appendix A:
  SBOM author (a Person or Organization creator, not the tool), SBOM
  timestamp, SBOM tool name, and coverage meters for component producer,
  version, identifiers, hash and licence, plus dependency relationships.
  Two mapping decisions are worth knowing. **Component producer is read
  from the SPDX `originator` field, not `supplier`**: the 2026 text
  replaced "Supplier Name" because supplier denotes the distributor, and
  SPDX draws the same line. Mainstream generators populate neither field
  today, so a low meter is a finding about the SBOM rather than about the
  profile. **Hash value and hash algorithm are one check**, because both
  formats carry them as a pair. Unlike the BSI preset there is no format
  baseline: the 2026 elements name SPDX and CycloneDX without a version
  floor. Component name and the two SBOM data-format fields are satisfied
  by construction in any parsed document and are not checked; SBOM author
  signature, generation context, SBOM version and the tool version on its
  own are not readable by this engine and are listed in the profile's own
  description. The six *Practices and Processes* elements describe how an
  organisation handles SBOM data and are out of scope for a document
  check, with one note: the **Coverage** element explicitly accepts
  linking to separate SBOM documents, which is what the workspace
  resolves and reports as a cascade.
- **[BSI TR-03183-2 licence fields (6.1)](https://www.bsi.bund.de/dok/TR-03183)** (schema v4): the
  licence fields section 6.1 of the TR requires per component. The
  distribution licence (SPDX `licenseDeclared`, CycloneDX licences not
  acknowledged as concluded) is **gated at 100 %** and must be an SPDX
  identifier or expression whose identifiers are on the SPDX License List
  or are `LicenseRef-...` (the TR names the ScanCode LicenseDB,
  `LicenseRef-scancode-*`, as the fallback); the effective licence
  (`licenseConcluded`) is a meter under the same identifier rule.
  Deprecated identifiers still count as identifiers; NOASSERTION and NONE
  count as absent; a licence text in place of an identifier is the
  expression grammar lint's finding, not this profile's. The TR format
  baseline (SPDX 3.0.1+ or CycloneDX 1.6+) leads, as in the field-coverage
  preset. The profile says nothing about which licence is acceptable, what
  it obliges, or whether two licences are compatible.
- **[FDA 524B cybersecurity (02/2026)](https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-management-system-considerations-and-content-premarket)** (schema v4): the SBOM content the FDA guidance
  *Cybersecurity in Medical Devices* (final, February 2026) asks for under
  section 524B of the FD&C Act. The NTIA baseline checks reuse the NTIA
  preset's ids, so the two reports compare line by line; on top, **level
  of support** and **end-of-support date** are coverage meters. The
  guidance is nonbinding (the legal lever is refuse-to-accept at
  submission), so nothing gates and a complete report is not a statement
  of acceptability. Exactly three field conventions are read: SPDX 2.3
  `ValidUntilDate` (end of the support period from the supplier), SPDX
  3.0.1 `supportLevel` / `validUntilTime` (the latter means "reassess
  after", close to but not the same as end of support), and CycloneDX
  properties named `support-level` / `end-of-support` (optionally
  prefixed `fda:lifecycle:`), because CycloneDX has no normative field for
  either. An addendum file is not read. Known vulnerabilities are the
  VEX/CSAF overlay's job and are not scored.
- **[OpenChain Automotive SBOM v1.1](https://github.com/OpenChain-Project/Automotive-SBOM)** (schema v4): the
  thirteen mandatory fields of the OpenChain Automotive SBOM Specification
  (CC0-1.0), which maps each onto SPDX and CycloneDX. The requirement is
  contractual (OEMs pass UNECE R155/R156 obligations down the tier chain),
  so package fields are meters and nothing gates. **SBOM type** and
  **external document references** are informational document facts: SPDX
  2.x cannot express a type at all, and a leaf SBOM references nothing.
  File name is SPDX `packageFileName` (CycloneDX has no field), concluded
  licence is `licenseConcluded`, copyright is read where the formats carry
  it, hashes are optional in the specification and shown as a meter, and
  component name is satisfied by construction and not checked. The n-tier
  vehicle SBOM the specification is written for is what the cascade view
  resolves.
- **[BSI TR-03183-2 field coverage (approximation)](https://www.bsi.bund.de/dok/TR-03183)**: the machine-checkable
  field requirements of BSI TR-03183 part 2 v2.1.0, gated at 100%: SBOM
  creator with contact (email or URL, on a Person/Organization creator),
  timestamp, per-component version, creator (via supplier), licence, and a
  **SHA-512** hash (the algorithm is enforced via the v2 `algorithms`
  modifier), plus dependency enumeration; unique IDs (purl/CPE) are reported
  informationally. The TR accepts only SPDX 3.0.1+ or CycloneDX 1.6+ as
  formats, and the profile enforces that baseline as a leading **gated
  check** (via the v3 `requires` precondition, which accepts a list of
  baselines): an SPDX 2.x or CycloneDX 1.5 document visibly fails the
  format-baseline check instead of looking conformant, while its field
  checks still show what data is present. SPDX 3.0.x and CycloneDX 1.6+
  documents pass the baseline.
  It stays labelled an *approximation*: the profile verifies field
  coverage, not the full TR.
  What the engine cannot check (component filenames, the
  executable/archive/structured properties, source URIs, the completeness
  indication) is listed in the profile's own description, which the report
  shows under *What this profile checks* and the Markdown export carries as
  a blockquote, together with a link to the requirement source.

Builtin presets are code, not stored data: they cannot be removed, and the
selection persists per product.

## Norm scores in CI

For scoring SBOMs against the published standards themselves, use
[sbomqs](https://github.com/interlynk-io/sbomqs): it implements BSI
TR-03183-2 (v1.1, v2.0, v2.1), the NTIA minimum elements, FSCT v3, and
OpenChain Telco, reads both SPDX and CycloneDX, and is actively
maintained. As of sbomqs v2.0.12 it carries no scorer for the 2026
minimum elements. SBOM Lens deliberately does not compete on standards breadth;
the BSI preset above stays a viewer-side approximation.

Profiles cover what a standards scorer cannot: checks you define yourself
(field patterns, thresholds, format baselines), evaluation of a resolved
multi-document cascade as one workspace, and one rule set driving the
viewer and the gate alike. The two combine well in a pipeline: sbomqs for
the standard score, your own profile for the acceptance rules.
