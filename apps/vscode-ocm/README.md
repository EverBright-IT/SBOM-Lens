# OCM Lens for VS Code

View [Open Component Model](https://ocm.software/) component versions and
deliveries right in your editor: component descriptors (YAML/JSON), CTF and
component archives — the component hierarchy renders as one navigable tree,
and SBOMs stored in a delivery are extracted and linked automatically.

## Opening deliveries

- **Open with OCM Lens** — right-click a `component-descriptor.yaml`/`.json`
  or a `.ctf` / `.tar` / `.tgz` archive in the explorer. Multi-select several
  files and they open together in one panel, with component references
  resolved between them.
- **Open folder with OCM Lens** — right-click a folder: every component
  descriptor and CTF under it loads into one panel.
- **OCM Lens: Scan workspace for component descriptors** — the
  command-palette way to load the whole workspace.

## What you get

- **Component hierarchies as one tree.** `componentReferences` resolve across
  everything you load; resources and sources appear with types, digests, and
  `pkg:oci` package URLs. Embedded SPDX SBOMs connect underneath their
  resource automatically.
- **Analysis views.** A sortable resource/package inventory (CSV/JSON
  export), version conflicts, version-to-version diffs, and quality reports.
- **Private by design.** Everything is parsed locally inside the editor —
  nothing is uploaded anywhere.

OCM Lens shares its engine with
[SBOM Lens](https://open-vsx.org/extension/everbright-it/sbomlens) — the
SPDX-first sibling product.

## Links

- [Source & issues](https://gitlab.com/everbrightit-group/sbom-lens)
  (monorepo, label `ocm-lens`) ·
  [GitHub mirror](https://github.com/EverBrightIT/SBOM-Lens)
- [Changelog](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md)

Apache-2.0 © [EverBright IT GmbH](https://everbright-it.de)
