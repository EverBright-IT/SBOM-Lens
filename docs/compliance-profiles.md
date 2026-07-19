# Compliance profiles

SBOM Lens ships the NTIA minimum elements as its default quality report, and
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
| `document-field` | the field is present (and matches the modifiers) | `name`, `namespace`, `created`, `creators`, `dataLicense`, `comment` |
| `relationships` | the document has at least `minCount` (default 1) relationships | - |
| `created-recency` | `created` parses and is at most `maxAgeDays` old (boundary inclusive) | - |
| `package-coverage` | the share of packages satisfying the field (and modifiers) reaches `threshold` % | `version`, `supplier`, `purl`, `uniqueId`, `checksum`, `license`, `downloadLocation`, `purpose`, `copyright`, `originator` |

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
profile (falls back to the builtin: NTIA minimum elements in SBOM Lens,
OCM component essentials in OCM Lens); **Export** writes the current report
as Markdown for audits. Up to 16 imported profiles (256 KB total) persist;
anything beyond that stays session-only with a notice.

## Builtin presets

Besides the default (NTIA minimum elements for SPDX documents, OCM component
essentials for component descriptors), the dropdown offers:

- **BSI TR-03183-2 field coverage (approximation)**: the machine-checkable
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
  indication) is listed in the profile's own description, so exported
  reports carry the caveat with them.

Builtin presets are code, not stored data: they cannot be removed, and the
selection persists per product.

## Norm scores in CI

For scoring SBOMs against the published standards themselves, use
[sbomqs](https://github.com/interlynk-io/sbomqs): it implements BSI
TR-03183-2 (v1.1, v2.0, v2.1), the NTIA minimum elements, FSCT v3, and
OpenChain Telco, reads both SPDX and CycloneDX, and is actively
maintained. SBOM Lens deliberately does not compete on standards breadth;
the BSI preset above stays a viewer-side approximation.

Profiles cover what a standards scorer cannot: checks you define yourself
(field patterns, thresholds, format baselines), evaluation of a resolved
multi-document cascade as one workspace, and one rule set driving the
viewer and the gate alike. The two combine well in a pipeline: sbomqs for
the standard score, your own profile for the acceptance rules.
