# SBOM Lens for VS Code

[![Open VSX Version](https://img.shields.io/open-vsx/v/everbright-it/sbomlens?label=Open%20VSX)](https://open-vsx.org/extension/everbright-it/sbomlens)

View SPDX SBOMs — including cascading document hierarchies — right in your
editor. The full [SBOM Lens](https://sbom-lens.everbright-it.de/) viewer as a
custom editor: Explore tree, document map, inventory, version conflicts,
release diff, and quality reports.

![The Explore view: a release cascade as one tree, detail pane with relationships, document map](https://sbom-lens.everbright-it.de/assets/hero-explore.png)

## Opening documents

- **Open with SBOM Lens** — right-click a `.spdx`, `.spdx.json`, or
  `.spdx.yaml` file in the explorer (or use *Reopen editor with…*).
  Multi-select several files and they open together in one panel, with
  cross-document references resolved between them.
- **Open folder with SBOM Lens** — right-click a folder: every SPDX document
  under it loads into one panel.
- **SBOM Lens: Scan workspace for SBOMs** — the command-palette way to load
  the whole workspace (files over 50 MB are skipped).
- **From URL** — fetches run in the extension host, so browser CORS limits
  don't apply; access tokens are kept in VS Code's secret storage.

## What you get

- **Cascades as one tree.** `ExternalDocumentRef` links resolve across
  everything you load — by checksum first, then namespace — and render as one
  continuous tree: release → component → sub-SBOM → package. Unresolved
  references become actionable placeholders.
- **Analysis views.** A sortable cross-cascade inventory (CSV/JSON export via
  the native save dialog), version-conflict detection, release-to-release
  diffs, and an NTIA quality report per document.
- **Your own compliance rules.** Drop a `.sbomlens/profile.json` into the
  workspace and every panel picks it up as a quality profile — thresholds,
  field patterns, coverage gates. Reports export as Markdown.
- **Private by design.** Documents are parsed locally inside the editor —
  nothing is uploaded anywhere.
- Field ⓘ tooltips carry the SPDX 2.3 spec docs and link into the exact
  section of the specification; the theme follows your editor.

> Working with **Open Component Model** deliveries (component descriptors,
> CTF / component archives)? That is
> [OCM Lens](https://open-vsx.org/extension/everbright-it/ocmlens), the
> sibling extension built from the same codebase. SBOM Lens stays a focused
> SPDX viewer.

## Install

- **Open VSX** (VSCodium, Cursor, Gitpod, Theia…):
  [`everbright-it.sbomlens`](https://open-vsx.org/extension/everbright-it/sbomlens)
  — or search "SBOM Lens".
- **VS Code Marketplace**: listing in progress. Until then, download
  `sbomlens.vsix` from a
  [release pipeline](https://gitlab.com/everbrightit-group/sbom-lens/-/pipelines)
  and use *Extensions → ⋯ → Install from VSIX…*.

## Links

- [Source & issues](https://gitlab.com/everbrightit-group/sbom-lens)
  (GitLab, canonical) ·
  [GitHub mirror](https://github.com/EverBrightIT/SBOM-Lens)
- [Changelog](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md)
- Use it without VS Code: <https://sbom-lens.everbright-it.de/app/>
- Building, testing, publishing this extension:
  [DEVELOPMENT.md](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/vscode/DEVELOPMENT.md)

Apache-2.0 © [EverBright IT GmbH](https://everbright-it.de)
