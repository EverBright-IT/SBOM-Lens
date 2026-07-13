# Compliance profiles

SBOM Lens ships the NTIA minimum elements as its default quality report — and
lets every organization define its **own** minimum elements as a small JSON
file. The active profile drives the Quality section of each document and its
Markdown export; nothing else in the app changes.

Profiles are pure data. There is no code execution, and license checks stay
field-level (presence, patterns) — SBOM Lens does not do legal interpretation.

## Format (`sbomlens-profile/v1`)

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
| `relationships` | the document has at least `minCount` (default 1) relationships | — |
| `created-recency` | `created` parses and is at most `maxAgeDays` old (boundary inclusive) | — |
| `package-coverage` | the share of packages satisfying the field (and modifiers) reaches `threshold` % | `version`, `supplier`, `purl`, `uniqueId`, `checksum`, `license`, `downloadLocation`, `purpose`, `copyright`, `originator` |

### Modifiers and semantics

- **`pattern`** — a regular expression the value must match. `RegExp.test` is
  a substring match: anchor with `^…$` when you mean the full value. No
  flags in v1 (matching is case-sensitive).
- **`values`** — exact-match allow-list. Combined with `pattern` via AND.
- **`creators`** is an array: SOME semantics — at least one creator must
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

### Validation is fail-closed

An unknown check type or field rejects the **whole** profile with a list of
errors — an older SBOM Lens will never half-evaluate a newer profile and
report a false "pass". Limits: 200 checks, 64 KB per file, patterns ≤ 500
chars (must compile), ids unique.

## Importing a profile

- **Drop it into the window** (or *Open → Compliance profile…*). Detection is
  content-based (the `schema` field), not by file name. Imported profiles
  persist in the browser/editor and auto-activate.
- **Deployment catalog** — `sbomlens.catalog.json` may list profiles the
  instance rolls out to everyone (never auto-activated):

  ```json
  { "profiles": [{ "name": "ACME minimum elements", "url": "profiles/acme.json" }] }
  ```

- **VS Code** — put `.sbomlens/profile.json` into the workspace; the
  extension pushes it into every SBOM Lens panel automatically.

Switch profiles in the Quality section's dropdown; `×` removes an imported
profile (falls back to NTIA); **Export** writes the current report as
Markdown for audits. Up to 16 imported profiles (256 KB total) persist;
anything beyond that stays session-only with a notice.
