# OCM Lens for VS Code

[![Open VSX Version](https://img.shields.io/open-vsx/v/everbright-it/ocmlens?label=Open%20VSX)](https://open-vsx.org/extension/everbright-it/ocmlens)

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

## What you get

- **Component hierarchies as one tree.** `componentReferences` resolve across
  everything you load; resources and sources appear with types, digests, and
  `pkg:oci` package URLs. Embedded SPDX SBOMs connect underneath their
  resource automatically.
- **Analysis views.** A sortable resource/package inventory (CSV/JSON
  export), version conflicts, version-to-version diffs, and quality reports.
  Component versions are checked against "OCM component essentials" by
  default.
- **Your own rules.** Drop an `.ocmlens/profile.json` into the workspace and
  every panel picks it up as a quality profile: field presence, patterns,
  coverage thresholds. Reports export as Markdown.
- **Private by design.** Everything is parsed locally inside the editor.
  Nothing is uploaded anywhere.
- Field info tooltips carry the OCM specification's own vocabulary and link
  into the exact chapter; the theme follows your editor.

> Working with **SPDX** documents? That is
> [SBOM Lens](https://open-vsx.org/extension/everbright-it/sbomlens), the
> sibling extension built from the same codebase: same views, SPDX-first.

## Install

- **Open VSX** (VSCodium, Cursor, Gitpod, Theia):
  [`everbright-it.ocmlens`](https://open-vsx.org/extension/everbright-it/ocmlens),
  or search "OCM Lens".
- **VS Code Marketplace**: listing in progress. Until then, download
  `ocmlens.vsix` from a
  [release pipeline](https://gitlab.com/everbrightit-group/sbom-lens/-/pipelines)
  and use *Extensions*, *Install from VSIX...*.

## Links

- [Source & issues](https://gitlab.com/everbrightit-group/sbom-lens)
  (GitLab, canonical: one monorepo for both products, label `ocm-lens`), or
  the [GitHub mirror](https://github.com/EverBrightIT/SBOM-Lens)
- [Changelog](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md)
- [How OCM maps onto the viewer](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/docs/ocm.md):
  the mapping table, supported archive layouts, and the limits
- Use it without VS Code: <https://ocm-lens.everbright-it.de/app/>
- Building, testing, publishing this extension:
  [DEVELOPMENT.md](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/vscode/DEVELOPMENT.md)

Apache-2.0 © [EverBright IT GmbH](https://everbright-it.de)
