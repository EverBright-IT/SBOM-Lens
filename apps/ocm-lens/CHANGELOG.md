# Changelog - OCM Lens

OCM Lens 2.0 versions independently of the monorepo's 0.x line. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
