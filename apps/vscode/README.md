# SBOM Lens for VS Code

[![Open VSX Version](https://img.shields.io/open-vsx/v/everbright-it/sbomlens?label=Open%20VSX)](https://open-vsx.org/extension/everbright-it/sbomlens)
[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/everbright-it.sbomlens?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=everbright-it.sbomlens)

View SPDX SBOMs, including cascading document hierarchies, right in your
editor. The full [SBOM Lens](https://sbom-lens.everbright-it.de/) viewer as a
custom editor: Explore tree, document map, inventory, version conflicts,
release diff, and quality reports.

![The Explore view: a release cascade as one tree, detail pane with relationships, document map](https://sbom-lens.everbright-it.de/assets/hero-explore.png)

## Opening documents

- **Open with SBOM Lens**: right-click a `.spdx`, `.spdx.json`, or
  `.spdx.yaml` file in the explorer (or use *Reopen editor with...*).
  Multi-select several files and they open together in one panel, with
  cross-document references resolved between them.
- **Open folder with SBOM Lens**: right-click a folder, and every SPDX
  document under it loads into one panel.
- **SBOM Lens: Scan workspace for SBOMs**: the command-palette way to load
  the whole workspace (files over 50 MB are skipped).
- **From URL**: fetches run in the extension host, so browser CORS limits
  don't apply. Access tokens are kept in VS Code's secret storage.

## What you get

- **Cascades as one tree.** `ExternalDocumentRef` links resolve across
  everything you load, by checksum first and then namespace, and render as one
  continuous tree: release, component, sub-SBOM, package. Unresolved
  references become actionable placeholders.
- **Analysis views.** A sortable cross-cascade inventory (CSV/JSON export via
  the native save dialog), version-conflict detection, release-to-release
  diffs, and an NTIA quality report per document.
- **Your own compliance rules.** Drop a `.sbomlens/profile.json` into the
  workspace and every panel picks it up as a quality profile: thresholds,
  field patterns, coverage gates. Reports export as Markdown.
- **VEX overlay.** Open an OpenVEX document next to your SBOMs and see what
  the supplier communicates about known vulnerabilities: per-package
  statements with status and justification, a VEX column and status filter
  in the inventory, findings in the exports. Matched by package URL, newest
  statement wins. A communication channel, not a scanner.
- **Private by design.** Documents are parsed locally inside the editor.
  Nothing is uploaded anywhere.
- Field info tooltips carry the SPDX 2.3 spec docs and link into the exact
  section of the specification; the theme follows your editor.

> Working with **Open Component Model** deliveries (component descriptors,
> CTF / component archives)? That is
> [OCM Lens](https://open-vsx.org/extension/everbright-it/ocmlens), the
> sibling extension built from the same codebase. SBOM Lens stays a focused
> SPDX viewer.

## Limits

- **SPDX 2.x** (tag-value / JSON / YAML) in full; **SPDX 3.0.x** as JSON-LD
  with the core/software profiles mapped. CycloneDX is recognized with a
  conversion hint.
- The **workspace scan skips files over 50 MB** (open those by hand). A
  single large SPDX document has no hard cap; parsing runs off the UI thread.
- Compliance profiles are capped at 64 KB / 200 checks; up to 16 persist.
- No license-compliance judgement and no vulnerability overlays: license and
  quality fields are shown, not interpreted.
- Documents are parsed locally and never uploaded; only preferences and
  imported profiles persist.

## Install

- **Open VSX** (VSCodium, Cursor, Gitpod, Theia):
  [`everbright-it.sbomlens`](https://open-vsx.org/extension/everbright-it/sbomlens),
  or search "SBOM Lens".
- **VS Code Marketplace**:
  [`everbright-it.sbomlens`](https://marketplace.visualstudio.com/items?itemName=everbright-it.sbomlens),
  or search "SBOM Lens" in the Extensions view.

## Links

- [Source & issues](https://gitlab.com/everbrightit-group/sbom-lens)
  (GitLab, canonical), or the
  [GitHub mirror](https://github.com/EverBright-IT/SBOM-Lens)
- [Changelog](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md)
- Use it without VS Code: <https://sbom-lens.everbright-it.de/app/>
- Building, testing, publishing this extension:
  [DEVELOPMENT.md](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/vscode/DEVELOPMENT.md)

Apache-2.0 © [EverBright IT GmbH](https://everbright-it.de) — we help teams
with CRA/SBOM readiness and secure AI adoption.
