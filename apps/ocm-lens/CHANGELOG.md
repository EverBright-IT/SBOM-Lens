# Changelog - OCM Lens

OCM Lens 2.0 versions independently of the monorepo's 0.x line. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.3.1] - pre-release

### Security
- **A valid signature requires the referenced component versions to match
  their recorded digests.** The signature check covered the signed
  descriptor only. The digests a signed root records for its component
  references were never compared with the component versions actually in
  the delivery, so whoever supplied the file could replace a referenced
  component version, descriptor and blobs, under a signed root: Verify
  still read *valid* where `ocm verify` rejects the delivery. Verify now
  recomputes the normalised digest of every referenced component version
  in the delivery, follows matching references on, and calls a
  cryptographically valid signature *valid* only when that closure holds.
  It reads *invalid* when a digest differs and *unverifiable*, with the
  reason, when a referenced version is not part of the delivery, carries
  no digest, or uses a normalisation or hash OCM Lens does not compute. A
  delivery that ships its references elsewhere therefore reads
  *unverifiable* where it read *valid*.
- **"All match" means every declared digest was checked and matches.** For
  blobs that are indexed instead of loaded (over 64 MB, or past the 512 MB
  budget), a differing sha256 read as *unchecked* whenever the stored bytes
  began with the gzip magic, and Verify showed "all match" as soon as no
  mismatch was counted, even when nothing had been checked. A changed large
  blob could pass as intact. A differing digest is now always a *mismatch*,
  and the summary reads "N not checked" (the acceptance report: "NOT ALL
  CHECKED") while a declared digest is unchecked or pending.
- **The registry client keeps a stored credential with its registry (VS
  Code extension).** On a 401 the client sent the credential stored for a
  registry, as Basic auth, to whatever realm the answer named: any host,
  also over http. The realm now only counts over https on the registry's
  own host (any port) or on the token host known for it (Docker Hub,
  gitlab.com), and the token request follows no redirect. A registry whose
  token service lives on another host outside that list, such as a
  self-managed GitLab with a separate registry domain, no longer
  authenticates and answers HTTP 401.
- **Registry requests no longer follow a redirect to any address (VS Code
  extension).** Redirects are followed by hand: only to https, and the
  bearer token stays with the registry's origin. A 401 of a redirect target
  is no longer taken for the registry's challenge, which had sent the
  stored credential to a realm the target named. Blob downloads a registry
  hands on to its store keep working.

### Changed
- **SBOM fact sheets follow the corrected core checks of SBOM Lens 0.29.10.**
  The NTIA dependency relationships row and the BSI "dependencies
  enumerated" row count dependency statements only (CycloneDX
  `dependencies[]` or nested components, SPDX DEPENDS_ON and CONTAINS), so
  a CycloneDX image SBOM without a dependency graph reads one document row
  fewer; "purl or other ID" counts purl, CPE, SWID, SWHID and gitoid, not
  website or vcs links; the BSI TR-03183-2 approximation measures the
  component creator via the originator with a contact, the concluded
  licence, the filename and the SHA-512 hash as the TR's appendix 8.2 maps
  them, and its format gate rejects SPDX 3.0.0.
- **CSAF 2.1 advisories in a delivery are read (SBOM Lens 0.29.11).** The
  shared reader takes the 2.1 metrics for the CVSS row, the disclosure date
  as the statement date and the first_affected, last_affected, first_fixed
  and recommended buckets (affected or fixed); a product with status
  unknown yields no statement and a note; the unreadable reason no longer
  says CSAF 2.0.

## [2.3.0] - pre-release

### Added
- **What does the supplier say about a vulnerability?** A new
  Vulnerabilities tab in the Packages view reads the OpenVEX and CSAF 2.0
  documents a delivery carries (found by resource type, media type or
  content, also in a generic JSON blob) and any the reader adds (a button,
  or drop the file onto an open delivery). Offline only: a document
  declared with an external access is named and never fetched; nothing is
  looked up, nothing is scanned.
- **Statements on the packages that ship.** They are matched to the
  delivery's packages by purl, CPE and file hash, with the OpenVEX time
  rule; a package listed by several SBOMs gets the most cautious statement
  any of them receives. Per vulnerability: the stated status, the packages
  it reaches with the image or component version they ship in, and the
  supplier's action, impact or justification. Statements that name no
  package in the list stay visible, together with the artifacts the list
  does not cover, because the product may ship there. Search by
  vulnerability id or alias; a missing statement is called one, never an
  all-clear.
- The package table gains a VEX column and filter (worst stated status, or
  no statement), the package detail lists the statements, and the CSV and
  JSON exports carry the status and the vulnerabilities when documents are
  loaded.
- **Acceptance report.** A "Vulnerability communication" line and section:
  the documents (read, not read, outside the delivery, unreadable), the
  packages by stated status, the vulnerabilities that affect or are under
  investigation, and the statements without a package; an additive `vex`
  object in the JSON (the schema stays `ocm-lens-acceptance-report/v1`).
  The export reads the delivery's VEX documents first.
- **SBOM demo.** An OpenVEX document for the whole shop, a CSAF advisory
  stored as a generic JSON blob, and one declared outside the delivery.
  Demo identifiers only.

### Changed
- Package lists keep the package checksums, so a CSAF advisory that names
  a product by its file hash reaches it.
- The Licenses tab is virtualized like the package table: real deliveries
  name hundreds of license identifiers (one LicenseRef per unrecognized
  license text).

### Fixed
- The acceptance report keeps every name and note inside its table cell or
  list item: a line break or a pipe in a delivery's names, an SBOM's
  fields or a supplier's note no longer breaks a table or adds lines the
  report never wrote.

## [2.2.0] - pre-release

### Added
- **Packages: what ships, where, and is X in it?** A new Packages view
  lists every package the delivery's SBOMs name, once per identity and
  version, with the place it ships: the image or binary its SBOM is bound
  to (by digest or reference), the component version a release SBOM names,
  or the SBOM alone when it identifies nothing. The binding strength from
  the SBOM evidence travels with every place. An SBOM's subject (the image
  or product it describes) ships too: it is listed, marked and searchable,
  so per SBOM the count matches its fact sheet. Filters by ecosystem (purl
  type), artifact and license; the table stays fast for deliveries with
  tens of thousands of packages. This is the OCM-native successor of the
  1.x Inventory, Conflicts and Licenses views announced with 2.0.
- **Search by name, purl or CPE, with an honest "not found".** A purl
  (`pkg:deb/debian/openssl`, with or without version) or a CPE matches by
  identity, so `pkg:npm/lodash` never finds lodash-es. Every answer says
  where the matches ship and which artifacts that ship software were not
  searched, and why: no SBOM, an SBOM outside the delivery, not analysed
  yet, unreadable. It also names artifacts searched only through an SBOM
  that does not identify them or that states a different digest (it may
  describe a local build), how many packages state no purl or CPE (only a
  name search finds those), and when a filter narrows the search. A search
  for a vulnerable component therefore never reads as an all-clear for an
  image nobody could look into.
- **Licenses.** The license identifiers the packages name (concluded, else
  declared), checked against the SPDX License List and counted, with the
  artifacts they ship in; packages without a license and values that are
  not SPDX expressions are counted separately. What a license obliges is
  not judged.
- **Versions.** Packages that ship in more than one version, those that
  differ between artifacts first (two images carrying different openssl
  releases); several versions inside one artifact on request.
- **Export.** CSV (one line per package and artifact) and JSON
  (`ocm-lens-packages/v1`, with what the list does not cover) of the
  current filter. The CSV follows the formula guard of the SBOM Lens
  exports (0.29.9): a cell that starts with `=`, `+`, `-` or `@`, with a
  tab, CR or LF, or with the full-width form of one of the four gets a
  leading single quote, so a spreadsheet reads it as text. npm scopes such
  as `@types/node` keep their name.
- **Acceptance report.** Key figures in a new "Packages" section (packages,
  ecosystems, license identifiers, versions that differ between artifacts,
  artifacts the list does not cover) and an additive `packages` object in
  the JSON; the schema stays `ocm-lens-acceptance-report/v1`. The export
  reads the package lists first, so the report does not depend on which
  views were open, and it waits while SBOMs are being analysed: a report
  is complete or not exported, with the reason. Its order no longer
  depends on the machine's locale.
- Links into the package list from the SBOM fact sheet and from the SBOM
  evidence of an artifact in the Resources view.

### Changed
- **Package lists reach the UI, documents still do not.** The worker hands
  over each analysed SBOM's packages (identity, version, supplier,
  licenses, CPEs) when the Packages view or the report first needs them;
  files (image scanners list thousands), the raw JSON and the
  relationships stay in the worker. Files are counted, not listed. Every
  package element is kept, also in SBOMs that name all their packages as
  described.

## [2.1.0] - pre-release

### Added
- **SBOM evidence: is the right SBOM with every artifact?** A new SBOMs
  view ties each embedded SBOM to the artifact it describes and grades the
  claim by what matched: by digest (the SBOM names a digest of the
  delivered artifact: manifest, declared or image config digest), by
  reference (same repository and tag but no shared digest, typical for an
  image scanned from a local build before the push), by component (the
  SBOM names the component version, as release and source SBOMs do), or
  not at all. Every artifact that ships software (images, executables,
  packages, extensions) shows whether it is covered, unverified, has an
  SBOM declared but not usable (external, unreadable, deferred), or has
  none.
- **SBOM fact sheets.** Format and spec version, generator, timestamp,
  package count, field coverage (version, supplier, purl or other ID,
  checksum, license), the NTIA minimum elements, and the BSI TR-03183-2
  approximation with its format gate (the TR accepts SPDX 3.0.1+ or
  CycloneDX 1.6+ only). The NTIA reading names both levels: the document
  elements and the package element with the lowest coverage ("document 4
  of 4, supplier 64 %"), so a clean document header no longer reads as a
  complete SBOM.
- **Everywhere it matters.** The dashboard's Evidence card splits into
  Signatures and SBOMs ("3 of 3 artifacts covered"); the Resources table
  shows SBOM evidence per artifact, with an "SBOM gaps" filter and an SBOM
  evidence section in the artifact detail.
- **Acceptance report.** An SBOM evidence line in the verdict summary and
  an "SBOM evidence" section (artifacts, SBOMs, binding, format,
  generator, packages, NTIA, BSI). The JSON report gains an additive
  `sbomEvidence` object; the schema stays `ocm-lens-acceptance-report/v1`.
  The transport verdict is not affected by any of it.
- **SBOM demo.** A second demo delivery next to the ECME platform: one
  shop whose SBOMs show every binding level, an external SBOM and an image
  without any ("SBOM demo" on the start screen).
- Findings `OCM_SBOM_MISSING` (a warning when the delivery carries SBOMs
  but leaves software out, a note when it carries none), `OCM_SBOM_UNBOUND`,
  `OCM_SBOM_AMBIGUOUS`, `OCM_SBOM_EXTERNAL` and
  `OCM_SBOM_ANALYSIS_DEFERRED` (info), one aggregated entry each.

### Changed
- **Embedded SBOMs are read now, not just listed.** 2.0 called them
  "evidence, not documents" and left their contents to SBOM Lens. 2.1
  parses every embedded SBOM in the background worker and keeps a summary;
  the documents never reach the UI. The delivery opens first; up to 64 MB
  of SBOM text is analysed right after, with progress, the rest on "Analyse
  now", like deferred digest checks.
- **Extracted SBOMs keep their real file type.** The format comes from the
  content (a CycloneDX file declared as `application/json` is CycloneDX),
  downloads use the matching media type and extension, an SBOM shipped
  under several component versions is extracted once, and equal resource
  names no longer collide.

### Fixed
- An SBOM that cannot be decoded no longer costs its component version:
  it is reported (`OCM_SBOM_UNREADABLE`) and the rest opens. Unpacking
  failures are reported the same way instead of dropped silently.
- A background worker that dies (for example out of memory on a huge
  SBOM) no longer leaves the app waiting: the open fails with a message,
  and the next action starts a fresh worker.

## [2.0.2] - pre-release

### Fixed
- **Air-gap deliveries written by the current ocm CLI open correctly.**
  When `ocm transfer --copy-resources` (CLI 0.13) stores images and Helm
  charts by value, it tags an OCI index around the component descriptor and
  the stored artifacts' manifests, lists those manifests untagged as well,
  and keeps the descriptor that signing replaced. 2.0.1 called the stored
  images and charts broken (so no such delivery was ever air-gap ready),
  reported every untagged manifest as unreadable, and listed a signed
  component version twice. Now the index resolves to its descriptor, stored
  images and charts count as transported with their layers in the blob
  statistics and their digest checked, and the superseded descriptor is
  skipped. Checked against CTFs the CLI writes in both variants, by
  reference and by value.
- **A stored image counts as transported only when it is complete.** Every
  blob its manifest names must be in the delivery at the declared size;
  otherwise the resource is broken and a finding (`OCM_ARTIFACT_INCOMPLETE`)
  says how many blobs are missing or cut short. That catches a copy that
  did not finish on its way to the air-gapped side.
- **A damaged delivery is called incomplete, not "needs network".** The
  dashboard and the acceptance report had two verdicts, so a delivery with
  broken resources read "needs network to deploy", although no network
  brings back a blob the delivery lost. Broken resources now give a third
  verdict, *incomplete* (report: `INCOMPLETE DELIVERY`), which outranks
  the other two. The JSON report keeps its shape (`airGapReady` plus the
  reasons); the broken reason comes first and now reads "missing from the
  archive or incomplete".

## [2.0.1] - pre-release

### Fixed
- **VS Code: a delivery the editor cannot hand over now says so.** Files
  over 32 MB reach the viewer as webview resources; when that read failed,
  2.0.0 treated the file as empty and reported a misleading parse error.
  Now the file is named with the reason (`HOST_FILE_UNREADABLE`); in a
  multi-file push the readable files still open and the unreadable ones
  are listed as findings.

### Changed
- **Internal: one webview protocol, owned by the extension shell.** The
  messages between VS Code and the viewer moved from the SBOM Lens app into
  the shared shell (`@sbomlens/vscode-shell/protocol`); OCM Lens no longer
  depends on the SBOM Lens app package. No behavior change.
- **Internal: the version lives in package.json only.** The UI reads it
  from there; a release bumps two files instead of three.

## [2.0.0] - pre-release

### Added
- **The OCM-native rebuild.** OCM Lens no longer maps deliveries onto an
  SPDX document model: a CTF opens as what it is - component versions,
  artifacts, references, a content-addressed blob store. Four views answer
  the delivery questions in order: Dashboard (what is this bundle), Components
  (how does it aggregate - roots, diamonds, cycles shown honestly, unlimited
  depth), Resources (what actually ships, with content previews and
  download-on-demand), Verify (do digests and signatures hold).
- **Transport truth.** Every resource is classified transported / external /
  broken / unknown; the air-gap verdict also requires a complete in-bundle
  reference closure, because an unresolved reference is a network dependency
  in disguise.
- **Acceptance report.** One export (Markdown + JSON,
  `ocm-lens-acceptance-report/v1`) documents verdict, components, transport
  gaps, digest integrity, signature results, and SBOM coverage -
  deterministic and golden-tested.
- **Signature verification against the current toolchain.** The demo
  delivery carries a component signed with ocm CLI v0.13.0 (RSASSA-PSS,
  jsonNormalisation/v4alpha1); pinned keys from 1.x keep working (same
  pref key).
- **Bare descriptors open too**: a single component-descriptor file becomes
  a one-CV bundle whose localBlob accesses are honestly `broken` until the
  delivery they belong to is opened.
- **Transfer-medium-sized deliveries open instantly.** Load-time digest
  hashing is budgeted (256 MB); past it, verdicts open as `pending` with a
  visible "unchecked" chip, and "Check now" in Verify (or per artifact)
  runs the deferred checks on demand with progress: identical verdict
  semantics, deferred I/O. Reports state deferred checks explicitly.
- **Entries over 8 GiB parse.** The tar reader understands GNU base-256
  sizes AND Go-style PAX size records (what the ocm CLI writes); such
  resources previously appeared 'broken'.
- **The VS Code extension runs 2.0** (`everbright-it.ocmlens` 2.0.0, published
  on the **pre-release channel**: in VS Code, choose *Switch to Pre-Release
  Version*). Component descriptors and `.ctf` archives open in the custom
  editor; *Open folder* and the workspace scan merge several descriptors
  into one bundle with one reference graph; *Open component version from
  registry* pulls a component straight from an OCI registry into the 2.0
  views; the deep link `vscode://everbright-it.ocmlens/open?path=...` still
  works. Large files stream from disk instead of passing through memory,
  and saves (reports, artifact blobs, SBOMs) go through VS Code's save
  dialog.

### Changed
- **The whole mental model.** 1.x presented a delivery as SPDX documents
  with packages; 2.0 presents it as what the spec says it is. Everything
  you select, filter, and export speaks OCM vocabulary (component version,
  resource, reference, access, transport), not SPDX vocabulary.
- **One delivery at a time.** 1.x kept a multi-document workspace; 2.0
  deliberately holds ONE delivery - the product's job is understanding
  THIS bundle. Opening another delivery replaces the current one.
- **Embedded SBOMs are evidence, not documents.** 1.x parsed embedded
  SPDX/CycloneDX files into the workspace for full analysis; 2.0 lists
  them per resource, shows coverage, and offers extraction/download - deep
  SBOM analysis is SBOM Lens' job, one download away.
- **The version line restarts at 2.x** with this changelog; 1.x history
  stays in the monorepo CHANGELOG under its 0.x releases.

### Removed (vs. the 1.x OCM flavor - deliberate V1 scope, not oversights)
- **Inventory, Conflicts, Licenses, Map, Diff views.** They operated on
  the SPDX mapping; their OCM-native successors are scoped for 2.x
  (delivery-to-delivery diff first). Until then the 1.x flavor remains
  available for these workflows.
- **VEX/CSAF overlay** on deliveries.
- **Compliance profiles and the quality report** (including the "OCM
  component essentials" builtin and `.ocmlens/profile.json`).
- **Open from URL with access tokens.** File open, drag&drop, bare
  descriptors, and (in VS Code) registry access are supported.
- **Spec info tooltips** (the field-level links into the OCM spec).
- **VS Code: comparing two registry versions.** The command returns with
  the 2.x delivery diff; opening a single version from the registry stays.
- **VS Code: workspace compliance profiles** (`.ocmlens/profile.json` is no
  longer read; 2.0 has no profiles yet).

### Migration notes
- **Pinned signature keys carry over automatically** (same origin, same
  pref key `ocmlens.trustedKeys`).
- **VS Code users choose the channel.** 2.0.0 ships as a pre-release: users
  on the release channel stay on 1.x (0.29.6, frozen) until 2.x goes
  stable; *Switch to Pre-Release Version* in the extension page installs
  2.0. Open VSX lists 2.0.0 as its newest version, and not every client
  honors the pre-release flag there, so some Open VSX editors may install
  2.0 directly. Pinned keys from the 1.x extension carry over (same pref
  key in the extension's storage).
- Browser prefs from 1.x other than pinned keys (sidebar width, theme) do
  not apply to the new UI and are simply unused.
- The acceptance report (`ocm-lens-acceptance-report/v1`) is new; the 1.x
  quality-report Markdown export has no 2.0 equivalent until profiles
  return.
