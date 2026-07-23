# OCM Lens for VS Code

[![Open VSX Version](https://img.shields.io/open-vsx/v/everbright-it/ocmlens?label=Open%20VSX)](https://open-vsx.org/extension/everbright-it/ocmlens)
[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/everbright-it.ocmlens?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=everbright-it.ocmlens)

View [Open Component Model](https://ocm.software/) component versions and
deliveries right in your editor: component descriptors (YAML/JSON), CTF and
component archives. The component hierarchy renders as one navigable tree,
and SBOMs stored in a delivery are extracted and linked automatically.

![The Explore view: a delivery as one tree with the component, its artifacts, and the SBOM stored inside it; detail pane with OCM identity and access spec](https://ocm-lens.everbright-it.de/assets/hero-explore.png)

## Opening deliveries

- **Open with OCM Lens**: right-click a `component-descriptor.yaml`/`.json`
  or a `.ctf` / `.tar` / `.tgz` archive in the explorer. Multi-select several
  files and they open together in one panel, with component references
  resolved between them.
- **Open folder with OCM Lens**: right-click a folder, and every component
  descriptor and CTF under it loads into one panel.
- **OCM Lens: Scan workspace for component descriptors**: the
  command-palette way to load the whole workspace.
- **OCM Lens: Open component version from registry...**: pull a component
  version straight from an OCI registry (e.g.
  `ghcr.io/open-component-model/ocm`) and browse it like a local delivery,
  SBOMs, digest verdicts and signatures included. Unresolved component
  references offer a *Fetch from registry* button prefilled from the
  descriptor's repository contexts. Private registries: store a `user:token`
  per host via *OCM Lens: Set registry credential*.

## What you get

- **Component hierarchies as one tree.** `componentReferences` resolve across
  everything you load; resources and sources appear with types, digests, and
  `pkg:oci` package URLs. Embedded SPDX SBOMs connect underneath their
  resource automatically.
- **See what the delivery physically ships, and whether it is intact.**
  Every artifact stored in a CTF or component archive shows its actual
  content: helm charts with their file list and Chart.yaml/values.yaml,
  OCI artifact sets with their layer table, configs and texts with an
  exportable preview. Declared blob digests are recomputed from the real
  bytes: a tampered or corrupted artifact shows a red *digest mismatch*
  right on the resource.
- **Verify signatures, in the browser.** Paste a public key or certificate
  and OCM Lens recomputes the descriptor's normalised digest and checks the
  RSA signature client-side: no server, no upload. Verified against the real
  `ocm` CLI, and honest by design: it reports *valid*, *invalid*, or
  *unverifiable* with a reason, never a guessed verdict.
- **Analysis views.** A sortable resource/package inventory (CSV/JSON
  export), version conflicts, version-to-version diffs, and quality reports.
  Component versions are checked against "OCM component essentials" by
  default.
- **Your own rules.** Drop an `.ocmlens/profile.json` into the workspace and
  every panel picks it up as a quality profile: field presence, patterns,
  coverage thresholds. Reports export as Markdown.
- **Spec findings.** Descriptors are checked against the OCM specification:
  component names and versions off their pattern, an access node without a
  type, an incomplete digest triple, duplicate artifact identities. They stay
  warnings and sit next to the descriptor, told apart from parser notes so you
  always know which you are looking at.
- **Private by design.** Everything is parsed locally inside the editor.
  Nothing is uploaded anywhere.
- Field info tooltips carry the OCM specification's own vocabulary and link
  into the exact chapter; the theme follows your editor.

> Working with **SPDX** documents? That is
> [SBOM Lens](https://open-vsx.org/extension/everbright-it/sbomlens), the
> sibling extension built from the same codebase: same views, SPDX-first.

## Limits

- **Read-only.** No signing, no registry writes; registry access is
  pull-only. Documents are parsed locally in the editor; nothing is
  uploaded. Registry fetches skip layers over **50 MB** (256 MB total per
  component version) and say so; the descriptor always arrives.
- **Delivery archives** are capped at **10,000 entries**; blobs over
  **64 MB** are indexed without loading their content (the digest verdict
  still runs). Compressed `.tgz` deliveries are capped at **2 GiB**
  decompressed: repack larger ones as plain `.tar`. ZIP is rejected with a
  repack hint, and links inside tars are never followed. The workspace scan
  skips files over 50 MB.
- **Artifact previews are capped**: 64 KB of text, 500 files listed, a 256-byte
  hex head for binaries. The raw bytes stay in the parse worker.
- **Digest checks** cover `genericBlobDigest/v1` and `ociArtifactDigest/v1`;
  any other normalisation is shown as *unchecked*, never guessed.
- **Signature verification** handles RSASSA-PSS and RSASSA-PKCS1-v1_5 over
  SHA-256/512. Out of scope: signing, certificate-chain and trust-policy
  validation, timestamping, and the deprecated `jsonNormalisation/v1`
  (reported *unverifiable*).
- **Descriptors**: schema v2 fully, v3alpha1 best-effort. Unknown access
  types are listed without a download location. Verification needs HTTPS or
  localhost (`crypto.subtle` runs only in secure contexts).

## Install

- **Open VSX** (VSCodium, Cursor, Gitpod, Theia):
  [`everbright-it.ocmlens`](https://open-vsx.org/extension/everbright-it/ocmlens),
  or search "OCM Lens".
- **VS Code Marketplace**:
  [`everbright-it.ocmlens`](https://marketplace.visualstudio.com/items?itemName=everbright-it.ocmlens),
  or search "OCM Lens" in the Extensions view.

## Links

- [Source & issues](https://gitlab.com/everbrightit-group/sbom-lens)
  (GitLab, canonical: one monorepo for both products, label `ocm-lens`), or
  the [GitHub mirror](https://github.com/EverBright-IT/SBOM-Lens)
- [Changelog](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md)
- [How OCM maps onto the viewer](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/docs/ocm.md):
  the mapping table, supported archive layouts, and the limits
- Use it without VS Code: <https://ocm-lens.everbright-it.de/app/>
- Building, testing, publishing this extension:
  [DEVELOPMENT.md](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/vscode/DEVELOPMENT.md)

Apache-2.0 © [EverBright IT GmbH](https://everbright-it.de) — we help teams
with CRA/SBOM readiness and secure AI adoption.
