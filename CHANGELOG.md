# Changelog

All notable changes to SBOM Lens. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org) (0.x: the API surface is the app itself).

## [0.24.1] - 2026-07-23

### Security
- **fast-uri raised to 3.1.4** (GHSA-v2hh-gcrm-f6hx, CVSS 7.5). A build-time
  dependency only, pulled transitively through ajv by vite-plugin-pwa and
  @vscode/vsce; nothing shipped in the app or the extensions was affected.
  The blocking osv-scanner gate stopped the 0.24.0 pipeline before any
  artifact was published, which is what the gate is for. An `overrides`
  entry keeps 3.1.4 as the floor. Feature-identical to 0.24.0.

## [0.24.0] - 2026-07-23

### Added
- **Spec findings: documents are checked against their own specification.**
  Beyond "can I read this?", the viewer now reports what a consumer
  downstream would trip over: a relationship type outside the SPDX
  vocabulary, a digest whose length cannot match its algorithm, a license
  expression that does not parse, an identifier off its grammar, an SPDX 3
  element without creationInfo, a relationship end pointing at an id that
  is neither in the graph nor imported, a duplicate CycloneDX bom-ref.
  28 rules across SPDX 2.x (13), SPDX 3.0.x (7) and CycloneDX 1.x (8),
  next to the 9 OCM descriptor rules that already existed. Every finding
  is a warning: nothing here can stop a document from loading.
- **Spec findings and parser notes are told apart in the UI.** The document
  detail shows them as separate rows, each linking into the diagnostics
  drawer pre-filtered to what it counted. The drawer gains a "Spec
  findings only" toggle and tags spec rows. `isSpecFinding()` is exported
  from the core package.
- **License expressions are checked for grammar** (operators, parentheses,
  `LicenseRef-` shape), deliberately without matching identifiers against
  the SPDX license list: no list is vendored and rating licenses stays a
  non-goal. [docs/spec-findings.md](docs/spec-findings.md) states the
  boundary and points at [spdx/tools-java](https://github.com/spdx/tools-java)
  for authoritative conformance verification.
- **The VS Code extension opens CycloneDX files.** `*.cdx.json` and
  `*.bom.json` join the custom-editor selectors; the core has read
  CycloneDX since 0.23.0, but the manifest never offered it. Description
  and marketplace keywords say so now too.

## [0.23.1] - 2026-07-19

### Fixed
- **BOM-Link fragments now address elements.** bom-refs become element ids
  verbatim (the SPDX 3.x IRI precedent) instead of a sanitized
  `SPDXRef-` form, so a fragment like `#jwt-lib` finds the element it names
  in the linked BOM. Before, the tree silently fell back to the linked
  BOM's root when a fragment pointed at a non-root element - plausible but
  wrong nesting. A test now pins the invariant.
- **BOM-Link URNs match case-insensitively** (namespace and link are both
  lowercased): mixed-case serial numbers no longer silently fail to
  resolve.
- A component `cpe` that is neither a 2.3 formatted string nor a 2.2 URI is
  labelled `cpe` instead of being mislabelled `cpe22Type`; a digit-string
  BOM `version` ("2") is honoured instead of defaulting to 1.

### Changed
- The parser's deliberate readings are now stated in code and docs: the
  AND-join over CycloneDX license lists, CONTAINS as a tree rendering of
  the component inventory, the uncapped breadth, and the tolerant reading
  of YAML-serialized BOMs (README limits).

## [0.23.0] - 2026-07-19

### Added
- **[SBOM Lens] CycloneDX 1.x documents load.** JSON BOMs open next to
  SPDX: components (including nested assemblies) with purl and CPE
  identity, suppliers, hashes, licenses (declared/concluded via
  acknowledgment), dependencies as DEPENDS_ON, and the full component node
  in the source view. **BOM-Links cascade**: a reference of type `bom`
  (`urn:cdx:<serial>/<version>#<bom-ref>`) becomes an external document
  reference and resolves through the same namespace matcher SPDX cascades
  use, with actionable placeholders for unresolved links (BOM-Links carry
  no document hash, so checksum resolution honestly does not apply). The
  CPE lands as a SECURITY reference, so VEX/CSAF statements match CDX
  inventories immediately. Out of scope, stated plainly: services,
  compositions, embedded VEX data, XML. The demo catalog gained a
  CycloneDX pair wired by BOM-Link.
- **BSI profile covers both format lines.** The v3 `requires` precondition
  accepts a list of baselines (`spdx-3`, `cdx-1.6`); the BSI preset now
  passes CycloneDX 1.6+ and fails 1.5, exactly as it already did for SPDX
  3.x versus 2.x. Fail-closed as before: older engines reject the list
  outright instead of under-checking.

## [0.22.0] - 2026-07-19

### Added
- **CPE matching for the VEX overlay, both products.** Statements that
  identify a product by CPE — the common case in BSI-CERT advisories — now
  match the inventory through the SECURITY `cpe22Type`/`cpe23Type` external
  references, alongside purl. CPE 2.3 formatted strings and 2.2 URIs
  normalise onto one key (case-folded, unescaped); the purl version rule
  carries over (exact version or versionless wildcard), and a wildcarded
  vendor/product never matches. CSAF CPE-only products and OpenVEX
  `identifiers.cpe23`/`.cpe22` become matchable; coverage counts CPE-only
  packages as matchable. See [docs/vex.md](docs/vex.md).

### Changed
- **Norm scoring points at sbomqs.** The BSI preset deliberately stays a
  viewer-side approximation; the compliance docs now recommend sbomqs for
  standards scores in CI and position profiles as the custom-rules,
  cascade-aware complement.

## [0.21.1] - 2026-07-18

### Fixed
- **SPDX 3.x cascades no longer show "(missing element)".** An element's
  global id is `documentId#spdxId`, decoded on the last `#` — which broke for
  SPDX 3.x, whose element ids are full IRIs carrying their own `#fragment`.
  The described root of a 3.x document then resolved to nothing and rendered
  as a missing element. Decoding now splits on the first `#` (a document
  namespace never carries a fragment), so 3.x roots resolve correctly.

## [0.21.0] - 2026-07-18

### Added
- **CSAF 2.0 as a second VEX source, both products.** Load a CSAF 2.0
  advisory (the BSI exchange format) next to your SBOMs, alongside OpenVEX.
  The product tree — full product names, a recursive branch tree, and
  relationships — is resolved to package URLs, the four `product_status`
  buckets map onto the VEX statuses, and `flags`/`remediations`/`threats`/
  notes fill justification/action/impact/description. Both formats share one
  overlay and the same time rule; each loaded document is tagged OpenVEX or
  CSAF. Matching stays purl-based for now: CPE-only products are reported,
  not matched. See [docs/vex.md](docs/vex.md).
- **Delivery acceptance: verify delivered files against the SBOM.** *Open →
  Check delivery…* hashes the files you were actually delivered and compares
  them, path by path, to the SBOM's file checksums — match, mismatch
  (tampered or corrupt), missing, or unverifiable, plus extras the SBOM
  never mentioned. Hashing runs in the worker; the delivered bytes never
  reach the UI thread. The SPDX-side counterpart to OCM Lens's blob-digest
  check. See [docs/acceptance.md](docs/acceptance.md).
- **One-click demos for every feature.** The demo catalog gained a delivery
  acceptance run (a file-level SBOM plus a delivery that hits all four
  verdicts), an SPDX 3.0.1 cascade, and — in OCM Lens — a signed component
  descriptor with its public key. A catalog source can now carry an optional
  `delivery` list of files to check against the SBOM it loads.

## [0.18.2] - 2026-07-17

### Added
- **VS Code Marketplace publishing in CI.** `publish-vsce-sbomlens` and
  `publish-vsce-ocmlens` mirror the Open VSX jobs: manual, on a tag, token
  from the masked and protected `VSCE_TOKEN` variable which vsce reads as
  `VSCE_PAT` from the environment, plus a pre-flight `verify-pat` and the
  same tag-versus-manifest guard. No `--skip-duplicate`: a republished
  version fails loudly rather than looking like a success that did nothing.
  The jobs cannot run until the `everbright-it` publisher exists; the manage
  portal's web upload publishes without any token and stays documented as an
  equal option, because an Azure DevOps PAT now requires an organization and
  a new organization requires an active Azure subscription.

## [0.20.1] - 2026-07-17

### Added
- **VEX API, verify-ready.** `vexCoverage()` classifies the package
  inventory as covered / uncovered (matchable purl, no statement) /
  unmatchable (no usable purl) — one shared classification for the UI
  and report consumers. Findings carry `sourceFile` next to `source` as
  an unambiguous join key back to the VEX document, plus
  `supersededCount` for statements the time rule discarded. The
  hand-over order of VEX documents is documented as part of the
  matching contract and pinned by a determinism test.

### Fixed
- **purl matching: unencoded scopes.** A versionless purl with an
  unencoded scope (`pkg:npm/@angular/core`) no longer mis-splits at the
  scope's `@`; the wildcard form now matches, and encoded/unencoded
  spellings of the same package produce the same match key.
- **Faster drops.** The ingest sniff pre-screens VEX candidates with a
  raw byte scan instead of text-decoding every dropped file up to 4 MB
  on the UI thread; ordinary SBOM drops are never decoded just to be
  ruled out.
- **[SBOM Lens] SPDX 3.x import grouping** backfills the defining
  document's checksum when a later import entry carries the hash the
  first one lacked.
- docs/vex.md states plainly that re-loading a VEX document with the
  same `@id` replaces it (and what that means for advisories that
  share an id).

## [0.20.0] - 2026-07-17

### Added
- **[SBOM Lens] SPDX 3.x cascades: imports resolve.** A 3.x document's
  `import` entries (ExternalMap) now become external document
  references, grouped by the defining document's IRI, and relationship
  ends pointing at imported element IRIs become external references.
  The existing cascade resolution takes it from there: load both
  documents and they link up (the IRI before the fragment doubles as
  the target document's namespace), with SHA1 `verifiedUsing` hashes
  feeding the checksum resolver and other hash algorithms displayed as
  the expected value. Unresolved imports appear as the same actionable
  placeholders 2.x references get.
- **[SBOM Lens] Curated SPDX 3.0.1 field tooltips.** 3.x documents no
  longer render without field info: a hand-curated documentation set
  speaks the 3.0.1 vocabulary (packageVersion, suppliedBy,
  verifiedUsing, primaryPurpose, ...) and deep-links every field into
  the 3.0.1 model specification pages. Where the viewer folds 3.x
  structure into a 2.x-shaped field (license relationships, creators),
  the tooltip says so. The 2.3 texts stay exactly as they were for 2.x
  documents.

## [0.19.0] - 2026-07-17

### Added
- **VEX overlay (OpenVEX), both products.** Load an OpenVEX document
  next to your SBOMs (or deliveries) and the viewer shows what the
  supplier communicates about known vulnerabilities. Statements match the inventory by
  package URL (type/namespace case-folded, name and version exact,
  qualifiers ignored; versionless purls cover every version;
  subcomponent matches are labeled). Each matched package gets a
  *Vulnerability communication* section with status, justification,
  impact and action statements; the Inventory grows a VEX column with
  status filter chips, and CSV/JSON exports carry the findings. Several
  VEX documents merge by the OpenVEX time rule (newest statement per
  vulnerability and package wins), re-loading the same `@id` replaces
  it, and the overlay recomputes live as documents come and go. It is
  a communication channel, not a scanner: no CVE-database lookup, no
  version ranges, and malformed statements are skipped with
  diagnostics instead of guessed. The demo cascade ships a synthetic
  advisory so *Load example* shows the whole flow. CSAF 2.0 is a
  planned follow-up. See docs/vex.md.

## [0.18.1] - 2026-07-17

### Fixed
- **Release hygiene.** The v0.18.0 tag never produced release artifacts:
  its commit accidentally included unrelated work-in-progress files that
  failed CI everywhere. This release supersedes it with an identical
  feature set; the dead tag remains without a release.

### Added
- **[OCM Lens] Registry browsing in the VS Code extension.** Pull a
  component version straight from an OCI registry and browse it like a
  local delivery. *OCM Lens: Open component version from registry...*
  asks for registry, component, and version (from the registry's tags);
  unresolved component references gain a *Fetch from registry* button
  prefilled from the descriptor's repository contexts. The extension
  host runs the standard bearer-token flow (anonymous for public
  registries; per-host `user:token` credentials via *OCM Lens: Set
  registry credential*, kept in VS Code secret storage) and packs the
  version's manifest and layers into the same CTF shape `ocm transfer`
  writes, so SBOM extraction, digest verdicts, and signature
  verification work unchanged. Layers over 50 MB (or past a 256 MB
  total) are skipped and reported; the descriptor always arrives.
  Version tags map OCM build metadata both ways (`1.0.0+7` as
  `1.0.0.build-7`).
- **[OCM Lens] Deep link.** External tools can open a delivery in the
  extension via
  `vscode://everbright-it.ocmlens/open?path=/absolute/path/to/delivery.ctf`.

## [0.17.0] - 2026-07-17

### Added
- **[SBOM Lens] Profiles can require a format baseline.** Compliance
  profile schema `sbomlens-profile/v3` adds a profile-level `requires`
  precondition (`{ "spec": "spdx-3" }`) that evaluates as a leading
  **gated** check. The builtin BSI TR-03183-2 preset uses it: the TR
  accepts only SPDX 3.0.1+ (or CycloneDX 1.6+) as formats, and an SPDX
  2.x document now visibly fails "Format baseline: SPDX 3.0.1 or later"
  in the report and the export instead of rendering all-green with the
  caveat buried in the description. Fail-closed like schema v2: an
  older engine rejects a `requires` profile outright rather than
  silently under-checking; v3 includes v2's `algorithms` modifier.

### Fixed
- **[OCM Lens] Streaming walker hardening.** GNU-longname/PAX header
  payloads are capped at 1 MB: their size field is attacker-controlled,
  and the streaming path would have materialized gigabytes for a "file
  name". And near the 2 GiB gunzip cap a failed output allocation now
  reports the honest "repack as plain .tar" error instead of "not a
  valid gzip stream".
- The GitHub link in the app footer and the docs now points at the
  renamed `EverBright-IT` organization.

## [0.16.0] - 2026-07-17

### Added
- **[OCM Lens] Multi-GB deliveries open.** Plain `.tar`/`.ctf` deliveries
  now stream from disk instead of being buffered whole: the walker reads
  the archive through the browser's file handle, materializes only the
  small entries that matter (descriptors, indexes, SBOMs), and indexes
  large artifact blobs by offset. A full release bundle with several
  components and multi-GB images opens in seconds; nested artifact sets
  stream through source windows the same way. Indexed blobs show
  *not inspected* instead of a preview, but their declared
  `genericBlobDigest/v1` sha256 is still verified for real, hashed
  incrementally off the archive in constant memory (per-blob cached;
  gzip-stored blobs keep the either-or rule and never produce a false
  mismatch). SBOM resources past the cap are fetched in full regardless:
  they are the point of this product.

### Fixed
- **[OCM Lens] Large bundles no longer lose components.** The old
  512 MB expanded cap silently dropped every tar entry after the limit,
  and in a multi-component CTF that tail is where the descriptors live.
  The cap is gone (entries were zero-copy views; it saved no memory), and
  the real decompression-bomb guard now sits where bytes actually
  materialize: gzip decompression is capped at 2 GiB with an honest
  "repack as plain .tar" error instead of an unbounded allocation.

## [0.15.0] - 2026-07-16

### Added
- **[SBOM Lens] SPDX 3.0.x documents load.** JSON-LD serializations of
  SPDX 3.0.x (the only SPDX line BSI TR-03183-2 v2.1.0 accepts) now parse
  into the same views as 2.x: packages and files with versions, suppliers,
  purposes, hashes, and external identifiers (purl, CPE); relationships with
  multi-target expansion; `hasDeclaredLicense`/`hasConcludedLicense`
  relationships folded into the license fields they represent; *describes*
  derived from the SpdxDocument's `rootElement`. Compliance profiles
  (NTIA, BSI) evaluate on 3.x documents unchanged. Elements from profiles
  beyond core/software (AI, dataset, build) are counted in a notice instead
  of being dropped silently. SPDX 2.x support is untouched; the 2.3 field
  tooltips stay off on 3.x documents rather than linking into the wrong
  spec.

## [0.14.0] - 2026-07-16

### Added
- **Diff sees content changes, not just version strings.** The Diff view now
  compares checksum fingerprints alongside versions: a package that ships
  the same version with different bytes (a rebuild, repack, or tampering)
  appears as changed with a *digest* chip, and the tooltip carries both
  fingerprints. Judged conservatively: digests are only compared when both
  sides actually declare checksums. Works for SPDX checksums and OCM digests
  alike; the Markdown export annotates "(content changed, same version)".
- **[OCM Lens] Structural lint for component descriptors.** Every descriptor
  is checked against the spec's structural rules, reported as warnings
  (`OCM_SCHEMA_*`): missing provider, names outside the spec pattern,
  non-semver versions, bad relations, typeless access nodes, incomplete
  digest triples, duplicate artifact identities, nameless labels, and
  unparseable timestamps. The document loads regardless; the lint shows what
  a stricter consumer would trip over.

### Fixed
- Same-named OCM artifacts that differ only in `extraIdentity` (e.g. one
  config per platform) no longer merge into one identity in the Conflicts
  and Diff views.

## [0.13.0] - 2026-07-16

### Added
- **[OCM Lens] Signature verification, client-side.** A signed component
  descriptor can now be verified in the browser: paste a public key (PEM) or
  a certificate in the Signatures section, and OCM Lens recomputes the
  descriptor's normalised digest and checks the RSA signature via
  `crypto.subtle`: no server, no upload. Supports `jsonNormalisation`
  v4alpha1/v3/v2, RSASSA-PSS and RSASSA-PKCS1-v1_5, SHA-256/512. It reports
  *valid*, *invalid* (distinguishing a bad signature from a changed
  descriptor), or *unverifiable* with a reason, and never guesses a verdict:
  an unknown normalisation, an unsupported algorithm, a non-canonicalisable
  descriptor, or a key that will not import all yield *unverifiable*.
  Verified end to end against the real `ocm` CLI (v0.9.0), including the
  maximum-salt-length PSS convention the CLI uses. Certificate chains and
  trust policy are out of scope: a certificate is used only for its public
  key, stated plainly in the dialog. See `docs/ocm.md`.

## [0.12.1] - 2026-07-16

Hardening release after an internal review of 0.12.0.

### Fixed
- **[OCM Lens] Digest verdicts are now strictly per resource.** Two
  artifacts pointing at the same blob but declaring different digests got
  the first artifact's verdict, so a tampered declaration next to a correct
  one could show *digest match*. Content inspection still caches per blob;
  the verdict is computed per artifact, proven by a test with one shared
  blob and two contradicting declarations.
- **[OCM Lens] localBlob sources are inspected too**, not only resources.
- **The BSI preset's contact check can no longer be satisfied by a tool
  version.** `Creator: Tool: npm@10.1` matched the email heuristic via its
  "@"; the pattern now requires the contact on a Person or Organization
  creator.
- The profile dropdown no longer renders blank when the active selection
  does not apply to the current document (a BSI selection on a component
  descriptor, a catalog profile not yet loaded): it shows the builtin the
  report actually falls back to.

### Changed
- **[OCM Lens] Compressed blobs accept stored OR uncompressed bytes for
  `genericBlobDigest/v1`** until the exact spelling is pinned against the
  ocm CLI. A sha256 match on either cannot be forged, while a wrong
  *mismatch* verdict would break trust for nothing.
- **[OCM Lens] Large-blob memory behavior in the parse worker**: text
  previews decode only the preview window instead of the whole blob, digest
  hashing no longer copies the bytes, and SBOM blobs are not gunzipped
  twice.

### Added
- **Profile schema `sbomlens-profile/v2`: the `algorithms` modifier.**
  Checksum coverage can now require specific hash algorithms
  (`"algorithms": ["SHA512"]`). A separate schema id on purpose: older
  engines ignore unknown keys and would silently evaluate such a profile as
  a weaker presence check; the v2 id makes them reject it outright. The BSI
  preset now enforces SHA-512 as the TR demands, and the store listing
  finally mentions the digest verification.

## [0.12.0] - 2026-07-16

### Added
- **[OCM Lens] Artifact content: what the delivery physically ships.** Every
  local blob in a loaded CTF or component archive is now inspected inside the
  parse worker, and its resource shows an "Artifact content" section: helm
  charts with their file list and Chart.yaml/values.yaml previews, OCI
  artifact sets with the manifest and a layer table, JSON/YAML/text blobs
  with exportable content, binaries with a hex head. Previews are hard-capped
  (64 KB text, 500 files); the raw bytes never leave the worker.
- **[OCM Lens] Blob digests are checked, not just displayed.** Resources
  declaring `genericBlobDigest/v1` or `ociArtifactDigest/v1` get their digest
  recomputed from the actual bytes: a green *digest match* or a red *digest
  mismatch* chip, plus an `OCM_DIGEST_MISMATCH` warning. Other normalisations
  stay honestly *unchecked* rather than risking a wrong verdict; component
  and reference digests remain display-only until signature verification
  lands. The demo delivery shows all three states.
- **Builtin compliance preset: BSI TR-03183-2 field coverage
  (approximation).** The Quality dropdown now offers the machine-checkable
  field requirements of BSI TR-03183 part 2 v2.1.0 (creator with contact,
  timestamp, per-component version/creator/licence/hash at 100%, dependency
  enumeration; purl/CPE informational). Deliberately labelled an
  approximation: the TR accepts only SPDX 3.0.1+ or CycloneDX 1.6+, so these
  checks measure data completeness on SPDX 2.x, not TR conformance; what the
  engine cannot check rides in the profile description and every exported
  report.

## [0.11.3] - 2026-07-16

### Added
- **Open VSX publishing runs in CI.** Every tag pipeline now offers a manual
  `publish-sbomlens` and `publish-ocmlens` job. Manual is the feature, not a
  shortcut: a published version is immutable, so tagging must never publish
  on its own, and the two products stay independently releasable. Each job
  verifies the token against the namespace first and refuses to publish when
  the tag and the manifest version disagree, because a mislabelled version
  cannot be corrected afterwards. Setup is one masked CI variable
  (`OVSX_TOKEN`), which `ovsx` reads from the environment so it never reaches
  a command line or a job log. See `apps/vscode/DEVELOPMENT.md`.

### Fixed
- The container image builds again, and 0.11.2 was the release that proved
  it: its docker job failed with `Cannot find module '@sbomlens/vscode-shell'`.
  The image ran the root typecheck across every workspace, so it depended on
  the VS Code extensions it does not ship, and a new workspace package was
  missing from the manifests layer. The same class of break cost a release
  before, so the image now typechecks and builds only the web app it serves.
  Linting, typechecking and testing every workspace stays with the `test`
  job, which runs on the same pipeline.

### Changed
- Plain punctuation across every public text: the READMEs, the store
  descriptions of both extensions, the docs, and this changelog. Em-dashes
  read as machine-written, and the store listing is the first thing a user
  sees of either product.

## [0.11.2] - 2026-07-15

### Changed
- **[OCM Lens]** The store listing now matches SBOM Lens': a hero screenshot
  showing what the product actually does (a delivery as one tree, with the
  OCM identity and access spec of a real artifact), the Open VSX version
  badge, an install section, a pointer to the sibling extension, and links to
  the OCM mapping docs and the hosted app. It shipped as text-only: the one
  thing a store page is for is showing the thing.

## [0.11.1] - 2026-07-15

### Fixed
- **Both extensions now ship this changelog**, so the store renders it as its
  own tab. Without it, 0.11.0 would have removed OCM deliveries from SBOM
  Lens through a silent auto-update: the reason was documented everywhere
  except where users would look.
- **[OCM Lens]** The vsix carried its own source (`src/extension.ts`), build
  config (`tsconfig.json`, `esbuild.mjs`), a source map, and the SBOM flavor's
  demo catalog: the extension had no `.vscodeignore`, so nothing was excluded.
  It now ships the same allowlist as SBOM Lens (which in turn stops shipping
  the OCM favicon).
- **[OCM Lens]** Workspace profiles are documented: the extension reads
  `.ocmlens/profile.json` (SBOM Lens keeps `.sbomlens/profile.json`), so both
  products can live in one workspace with different rules. The feature
  existed since 0.11.0 but was mentioned nowhere.

## [0.11.0] - 2026-07-14

### Added
- **[OCM Lens]** The repository now ships a second branded product: OCM Lens,
  a delivery-first viewer for Open Component Model component versions, built
  from the same codebase as a web app (`vite --mode ocm` → `dist-ocm`, own
  PWA manifest/favicon) and a VS Code extension (`apps/vscode-ocm`, editor
  for `component-descriptor.yaml|yml|json` and `.ctf` archives: it takes
  `*.ctf` by default; SBOM Lens keeps it under "Open With..."). Branding,
  copy, pref/secret namespaces (`ocmlens.*`), catalog path
  (`ocmlens.catalog.json`), and the bundled example are flavor-switched in
  `apps/web/src/app/brand.ts`; a CI gate fails any build that leaks the
  sibling product's name. The VS Code shell (bridge, panel lifecycle,
  commands) moved to the shared workspace package
  `@sbomlens/vscode-shell`: both extensions are thin configs around it.
  OCM Lens carries its own accent color (indigo, against SBOM Lens' sky):
  the UI now styles every affordance with a flavor-swappable `accent-*` ramp
  (`src/index.css`) instead of a fixed hue, so the products are told apart at
  a glance. Semantic colors (added/warning/error) and the per-document
  palette are untouched; SBOM Lens renders exactly as before.
- **OCM-native details**: the mapper no longer drops component-descriptor
  data: labels (with `signing` badges), structured repository contexts,
  **signatures** (name, algorithm, digest triple, truncated value),
  access specs, artifact digests (hash / normalisation / value), reference
  digests, and `extraIdentity` all surface in dedicated detail sections;
  the component root's source view now shows the full component node. The
  field info tooltips are model-aware: OCM documents link into the OCM spec
  (hand-curated `OCM_DOCS`), SPDX documents keep their SPDX 2.3 links.
  Quality defaults per model: component descriptors get a new builtin
  **"OCM component essentials"** profile (version coverage gated, digests
  and access locations as informational meters) instead of NTIA framing.

### Changed
- **Separation of concerns: OCM belongs to OCM Lens.** SBOM Lens is an SPDX
  viewer again: no component descriptors, no delivery archives, no `.ctf` in
  its extension. The split is structural rather than cosmetic: the descriptor
  mapper, the tar reader, and the gzip path moved behind a
  `@sbomlens/core/ocm` subpath and are *registered*, not imported (the seam
  `registerYamlParser` already uses), so only OCM Lens wires them in. The SBOM
  Lens bundle carries none of that code, ~20 KB smaller, and a CI gate greps
  the built assets to prove it instead of asserting it. Dropping a descriptor
  into SBOM Lens now yields one honest diagnostic ("this is an OCM component
  descriptor, not an SPDX document"); the classifier stays model-aware, so it
  can say that without any OCM code.
- OCM support is no longer flagged experimental: the `OCM_EXPERIMENTAL`
  diagnostic and the experimental badge on delivery documents is gone (documents now
  carry a "component version" chip); docs and READMEs follow. Digest
  verification stays on the roadmap (`OCM_DIGESTS_NOT_VERIFIED`).

### Removed
- **[SBOM Lens]** OCM deliveries, shipped as an experimental feature since
  0.10.0, are no longer part of SBOM Lens: they moved to OCM Lens (see
  above). Concretely: `.ctf` / `.tar` / `.tgz` and component descriptors no
  longer open, and the extension's custom editor drops its `*.ctf` selector.
  Opening one still explains where it belongs instead of failing silently.
  If you use SBOM Lens for deliveries, install **OCM Lens**: same engine,
  same views, plus the OCM-native detail that SBOM Lens never had.

## [0.10.6] - 2026-07-13

### Added
- The status bar shows the app version (links to the changelog).
- **Sub-component inventory per package**: "Show sub-components in Inventory"
  on any selected package filters the Inventory to that package and everything
  transitively below it: across resolved sub-SBOM boundaries, exactly as the
  tree splices them. A dismissible chip shows the active scope; CSV/JSON
  exports respect it.

### Changed
- The sidebar/detail divider is now visible (grip handle), keyboard-operable
  (arrow keys: Shift for larger steps, Home/End, double-click to reset),
  drag-robust via pointer capture, and allows a wider sidebar (220-800 px).
- GitLab Pages now serves the viewer directly: the Pages root IS the app,
  no landing-repo clone at deploy time (the landing page deploys to
  <https://sbom-lens.everbright-it.de/> from its own repo).

## [0.10.5] - 2026-07-13

### Changed
- **Public home**: the project now lives at
  <https://sbom-lens.everbright-it.de/> (viewer at `/app/`): canonical/OG
  tags, README links, and the package `homepage` follow. The GitLab Pages
  deployment stays available as a secondary host.
- The app declares `<meta name="robots" content="noindex">`: it is a tool,
  not a content page: search traffic belongs to the landing page. Applies to
  every deployment (GitLab Pages `/app/`, self-hosts) without server config.
- The VS Code extension README is now a proper store listing (screenshot,
  install, usage: it renders verbatim on Open VSX); build, F5 checklist,
  and publishing procedures moved to `apps/vscode/DEVELOPMENT.md`.
- The Diff view lays out its three categories side by side: version changes
  (left), added (middle), removed (right), so a large diff no longer buries
  removals below hundreds of added rows. All three columns share one scrollbar
  and stay virtualized. Narrow viewports (e.g. a VS Code split panel) keep the
  stacked list, now ordered version changes first.

## [0.10.4] - 2026-07-12

### Changed
- GitLab Pages now serves the project landing page at `/` (pulled from the
  [sbom-lens-web](https://gitlab.com/everbrightit-group/sbom-lens-web) repo at
  deploy time); the viewer moved to `/app/`. A self-destroying service-worker
  stub at the root scope migrates returning visitors whose browsers still hold
  the old root-scope PWA registration.

### Added
- Production hardening: the bundled nginx config now ships security headers
  by default: a Content-Security-Policy tailored to the viewer (arbitrary
  HTTPS origins stay allowed for "From URL"), `nosniff`, `frame-ancestors
  'none'`, a strict referrer policy, and a minimal permissions policy.
- Deployment guidance: HTTPS is required for cascade resolution
  (`crypto.subtle` only exists in secure contexts), same-origin proxies must
  be access-restricted and use read-only tokens (notes in
  `deploy/nginx.conf` and the README), and the URL dialog now recommends
  read-only token scopes.

## [0.10.3] - 2026-07-11

### Added
- Open-source readiness: `SECURITY.md` (private reporting via
  tech@everbright-it.de, scope, response targets), `CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), GitLab issue/MR templates (the GitHub mirror
  points at the canonical tracker), and a real README screenshot with a
  reproducible generator (`npm run screenshot -w @sbomlens/web`).

### Fixed
- OCM: a registry port without an image tag no longer leaks into the
  generated `pkg:oci` purl version.
- Catalog-shipped compliance profiles no longer toast on every app start.
- `CONTRIBUTING.md` paths updated to the workspace layout.

## [0.10.2] - 2026-07-11

### Changed
- **Official brand assets** adopted from the design handoff (`docs/brand/`):
  the lens-over-cascade mark replaces the provisional logo in the topbar and
  empty state, the favicon is updated, and the VS Code extension ships a
  proper Marketplace icon (`icon.png`, rasterized from the SVG).
- The extension README now documents publishing to the VS Code Marketplace
  and Open VSX step by step (publisher `everbright-it`, PAT scopes, one-line
  publish commands).

## [0.10.1] - 2026-07-11

### Changed
- OCM/SBOD support is now clearly flagged as **experimental**: delivery
  delivery documents show an experimental badge, carry an
  `OCM_EXPERIMENTAL` diagnostic, and the docs/README say so: the mapping
  and archive handling may still change between releases.

## [0.10.0] - 2026-07-11

### Added
- **OCM deliveries (Software Bill of Delivery), experimental**: open OCM component
  descriptors (v2, best-effort v3alpha1) and local CTF / component archives
  (`.tar`/`.tgz`/`.ctf`): the component hierarchy renders as the usual
  cascade, resources/sources become packages (types as purposes, digests as
  checksums, `pkg:oci` purls), `componentReferences` link loaded descriptors
  through synthetic `ocm://` namespaces, and SBOMs stored in the delivery
  are extracted and connected by byte checksum in the same batch. Both CTF
  artifact layouts (flat manifest, nested artifact set) are supported; a
  plain tar of SPDX files works too. Hand-rolled tar/gzip handling (PAX +
  GNU longnames, zip-bomb caps, links never followed): zero new runtime
  dependencies. Read-only: digests are displayed, never verified. See
  `docs/ocm.md`.
- VS Code: explorer multi-select and a new "Open folder with SBOM Lens"
  context entry load several documents into ONE shared panel: the middle
  ground between a single file and the whole-workspace scan. `.ctf`
  deliveries open from the explorer as well.

## [0.9.0] - 2026-07-11

### Added
- **Custom compliance profiles**: define your organization's own minimum
  elements as a small `sbomlens-profile/v1` JSON: document-field presence
  with regex/allow-list modifiers, relationship minimums, created-recency,
  and per-package coverage gates with thresholds. Import per drag&drop
  (content-detected), *Open → Compliance profile...*, a URL, the deployment
  catalog (`profiles` field: rolled out to every user of an instance), or
  `.sbomlens/profile.json` in a VS Code workspace. The Quality section gains
  a profile picker, threshold-aware meters (`>=N%`, amber when failing), and
  a Markdown report export for audits. The built-in NTIA report is now a
  profile in the same engine; validation is fail-closed (an unknown check
  type rejects the profile instead of silently weakening it). Imported
  profiles persist (16 profiles / 256 KB budget).
- CI supply-chain hygiene: osv-scanner gate on every push (GitLab + GitHub),
  GitLab SAST + Secret Detection, Trivy image scan on tags, a per-release
  self-SBOM artifact (`sbomlens-<tag>.spdx.json`: dogfooding), and Renovate
  as a scheduled in-project job. See `docs/ci-security.md`.

## [0.8.1] - 2026-07-11

### Added
- **Per-document accent colors**: cross-document badges in the Explore tree,
  the document column in the Inventory, and the nodes in both maps carry a
  deterministic color per document name: the same document is recognizable
  at a glance everywhere.
- **Theme switch**: a topbar toggle cycles system → light → dark (persisted
  as a preference; "system" keeps following the OS or editor theme live).
- Topbar links to the GitLab repository and the GitHub mirror.

## [0.8.0] - 2026-07-11

### Added
- **VS Code extension MVP** (`apps/vscode`): "Open with SBOM Lens" as a
  custom editor for `*.spdx` / `*.spdx.json` / `*.spdx.yaml`, plus
  "SBOM Lens: Scan workspace for SBOMs" (recursive, >50 MB skipped, one
  shared panel). The webview runs the unchanged web app; URL fetches happen
  in the extension host (no CORS), tokens live in VS Code secret storage,
  exports use the native save dialog. CI builds a `sbomlens.vsix` artifact
  on every tag; parsing stays off-thread via a Blob-instantiated worker.
- **HostAdapter seam** (`apps/web/src/host/`): network, prefs, secrets, file
  export, worker creation, and host-initiated document pushes go through one
  interface with browser and VS Code implementations. ESLint now forbids
  direct web-storage access outside the seam.

### Changed
- The repository is an npm workspace: `packages/core` (`@sbomlens/core`,
  framework-free, source-exported), `apps/web`, `apps/vscode`. Familiar root
  scripts (`dev`/`build`/`test`/`lint`/`typecheck`) delegate; releases bump
  all workspaces in lockstep.

## [0.7.0] - 2026-07-11

### Added
- **Subtree expansion**: Shift+click a chevron (or press `*`) to expand an
  entire subtree at once: across document boundaries, so a component's full
  resolved cascade unfolds in one action (capped at 2000 nodes with a notice).
- **Show cascade in Inventory**: a button in the document detail filters the
  Inventory to the document plus everything reachable through its resolved
  references: the flat, exportable answer to "all sub-elements of X".
- **Tree filter in place**: the funnel toggle next to the search box filters
  the Explore tree directly: matches stay put with their ancestor chain as
  dimmed context, siblings disappear. Expanding a filtered node zooms back out
  to the full tree at that spot; a header bar shows the match count and a
  one-click way back.
- **Spec links**: the field info tooltips now link into the rendered SPDX 2.3
  specification: click to open the exact field section (hand-curated anchors,
  verified against spdx.github.io).

### Changed
- **Map v2**: left-to-right collapsible tree layout replaces the top-down lane
  grid. Wide levels stack vertically instead of producing a 7000px row; nodes
  fold their subtree behind a `+N` badge; workspaces over 24 documents start
  with only the roots expanded; Expand/Collapse-all in the toolbar; search
  force-reveals matching documents. Readable at 70+ documents.

## [0.6.0] - 2026-07-11

### Added
- **Map view**: the document topology as a full-canvas graph with pan, wheel
  zoom-to-cursor and fit-to-view: readable at 77+ documents (compact node
  mode, fan-out edge de-emphasis, barycenter lane ordering). Nodes select
  documents (detail rail), double-click jumps into Explore, the search query
  highlights matching documents, missing references appear as clickable
  stubs. The inline sidebar minimap now hands over to the Map view above 12
  documents.
- **Cascade-aware removal**: removing a document now asks what should happen
  to documents only reachable through it: "Remove all N" or "Keep them as
  roots". A new manage-documents dialog (click the status-bar document count)
  offers multi-select bulk removal with a live orphan summary.
- Extension roadmap (VS Code + Chromium) documented in
  `docs/extension-architecture.md`.

### Fixed
- Removing a document no longer unconditionally clears the selection, and
  stale expansion state is pruned so re-added documents don't self-expand.

## [0.5.0] - 2026-07-11

### Added
- **Fetch all references**: one click in the status bar downloads every
  referenced document *recursively* (fixpoint over newly discovered
  references, 4 parallel fetches, capped): the full cascade for analysis
  without clicking each placeholder. Structural references are always
  attempted; informational ones only when their URL looks like an SPDX
  document.
- Catalog sources support `resolveRefs: true`: list only the root document
  and the whole tree assembles itself after loading.

## [0.4.0] - 2026-07-11

### Added
- **Document map**: a minimap of the cascade topology (documents as nodes,
  resolved references as edges, unresolved structural references as dashed
  stubs) at the bottom of the Explore sidebar; nodes select documents.
- **Deployment catalog**: self-hosted instances can ship
  `sbomlens.catalog.json` with curated SBOM sources (start-screen cards and
  Open-menu entries, optional `loadOnStart`). Documented same-origin
  reverse-proxy pattern for private GitLab registries in `deploy/nginx.conf`.
- **PWA/offline**: the app precaches itself (including the bundled examples
  and catalog) and keeps working without network after the first visit.

### Changed
- Accessibility: tree rows expose `aria-level`.

## [0.3.0] - 2026-07-11

### Added
- **YAML input**: the third official SPDX 2.x serialization; parsed in the
  worker only, so the main bundle stays lean.
- **Spec field docs**: info icon tooltips on detail fields carry the SPDX 2.3
  specification's own property documentation, generated at build time from the
  official JSON schema (`npm run generate:spec-docs`).
- Public repository metadata (gitlab.com canonical, GitHub mirror) and
  CC-BY-3.0 attribution for spec-derived content in `NOTICE`.

## [0.2.0] - 2026-07-11

### Added
- **Analysis views** behind a top-bar switcher:
  - *Inventory*: sortable cross-cascade package table with CSV/JSON export.
  - *Conflicts*: package identities (purl without version) appearing in more
    than one version anywhere in the workspace.
  - *Diff*: two cascades compared package-by-package (added / removed /
    version-changed), copyable as Markdown.
- **Quality report** per document (NTIA minimum elements): document checks,
  per-package coverage meters, dangling/unresolved reference counts.
- Read-only **license facet** in search and inventory.

## [0.1.0] - 2026-07-11

Initial release: SPDX 2.3 viewer (tag-value + JSON) with cascading
`externalDocumentRef` resolution (checksum → namespace → manual, suggestions
for drifted names), lazily derived cross-document tree with placeholders and
cycle guard, worker-based parsing, virtualized UI, ranked search with facets,
diagnostics, file/folder/URL loading with per-host session tokens, bundled
demo cascade, Docker image, GitLab CI (Pages + kaniko) and GitHub Actions.
