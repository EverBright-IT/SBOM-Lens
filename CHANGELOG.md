# Changelog

All notable changes to SBOM Lens. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org) (0.x — the API surface is the app itself).

## [Unreleased]

### Added
- **[OCM Lens]** The repository now ships a second branded product: OCM Lens,
  a delivery-first viewer for Open Component Model component versions, built
  from the same codebase as a web app (`vite --mode ocm` → `dist-ocm`, own
  PWA manifest/favicon) and a VS Code extension (`apps/vscode-ocm`, editor
  for `component-descriptor.yaml|yml|json` and `.ctf` archives — it takes
  `*.ctf` by default; SBOM Lens keeps it under "Open With…"). Branding,
  copy, pref/secret namespaces (`ocmlens.*`), catalog path
  (`ocmlens.catalog.json`), and the bundled example are flavor-switched in
  `apps/web/src/app/brand.ts`; a CI gate fails any build that leaks the
  sibling product's name. The VS Code shell (bridge, panel lifecycle,
  commands) moved to the shared workspace package
  `@sbomlens/vscode-shell` — both extensions are thin configs around it.
  OCM Lens carries its own accent color (indigo, against SBOM Lens' sky):
  the UI now styles every affordance with a flavor-swappable `accent-*` ramp
  (`src/index.css`) instead of a fixed hue, so the products are told apart at
  a glance. Semantic colors (added/warning/error) and the per-document
  palette are untouched; SBOM Lens renders exactly as before.

## [0.10.6] — 2026-07-13

### Added
- The status bar shows the app version (links to the changelog).
- **Sub-component inventory per package**: "Show sub-components in Inventory"
  on any selected package filters the Inventory to that package and everything
  transitively below it — across resolved sub-SBOM boundaries, exactly as the
  tree splices them. A dismissible chip shows the active scope; CSV/JSON
  exports respect it.

### Changed
- The sidebar/detail divider is now visible (grip handle), keyboard-operable
  (arrow keys — Shift for larger steps, Home/End, double-click to reset),
  drag-robust via pointer capture, and allows a wider sidebar (220–800 px).
- GitLab Pages now serves the viewer directly — the Pages root IS the app,
  no landing-repo clone at deploy time (the landing page deploys to
  <https://sbom-lens.everbright-it.de/> from its own repo).

## [0.10.5] — 2026-07-13

### Changed
- **Public home**: the project now lives at
  <https://sbom-lens.everbright-it.de/> (viewer at `/app/`) — canonical/OG
  tags, README links, and the package `homepage` follow. The GitLab Pages
  deployment stays available as a secondary host.
- The app declares `<meta name="robots" content="noindex">`: it is a tool,
  not a content page — search traffic belongs to the landing page. Applies to
  every deployment (GitLab Pages `/app/`, self-hosts) without server config.
- The VS Code extension README is now a proper store listing (screenshot,
  install, usage — it renders verbatim on Open VSX); build, F5 checklist,
  and publishing procedures moved to `apps/vscode/DEVELOPMENT.md`.
- The Diff view lays out its three categories side by side — version changes
  (left), added (middle), removed (right) — so a large diff no longer buries
  removals below hundreds of added rows. All three columns share one scrollbar
  and stay virtualized. Narrow viewports (e.g. a VS Code split panel) keep the
  stacked list, now ordered version changes first.

## [0.10.4] — 2026-07-12

### Changed
- GitLab Pages now serves the project landing page at `/` (pulled from the
  [sbom-lens-web](https://gitlab.com/everbrightit-group/sbom-lens-web) repo at
  deploy time); the viewer moved to `/app/`. A self-destroying service-worker
  stub at the root scope migrates returning visitors whose browsers still hold
  the old root-scope PWA registration.

### Added
- Production hardening: the bundled nginx config now ships security headers
  by default — a Content-Security-Policy tailored to the viewer (arbitrary
  HTTPS origins stay allowed for "From URL"), `nosniff`, `frame-ancestors
  'none'`, a strict referrer policy, and a minimal permissions policy.
- Deployment guidance: HTTPS is required for cascade resolution
  (`crypto.subtle` only exists in secure contexts), same-origin proxies must
  be access-restricted and use read-only tokens (notes in
  `deploy/nginx.conf` and the README), and the URL dialog now recommends
  read-only token scopes.

## [0.10.3] — 2026-07-11

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

## [0.10.2] — 2026-07-11

### Changed
- **Official brand assets** adopted from the design handoff (`docs/brand/`):
  the lens-over-cascade mark replaces the provisional logo in the topbar and
  empty state, the favicon is updated, and the VS Code extension ships a
  proper Marketplace icon (`icon.png`, rasterized from the SVG).
- The extension README now documents publishing to the VS Code Marketplace
  and Open VSX step by step (publisher `everbright-it`, PAT scopes, one-line
  publish commands).

## [0.10.1] — 2026-07-11

### Changed
- OCM/SBOD support is now clearly flagged as **experimental**: delivery
  documents show a "delivery · experimental" badge, carry an
  `OCM_EXPERIMENTAL` diagnostic, and the docs/README say so — the mapping
  and archive handling may still change between releases.

## [0.10.0] — 2026-07-11

### Added
- **OCM deliveries (Software Bill of Delivery), experimental**: open OCM component
  descriptors (v2, best-effort v3alpha1) and local CTF / component archives
  (`.tar`/`.tgz`/`.ctf`) — the component hierarchy renders as the usual
  cascade, resources/sources become packages (types as purposes, digests as
  checksums, `pkg:oci` purls), `componentReferences` link loaded descriptors
  through synthetic `ocm://` namespaces, and SBOMs stored in the delivery
  are extracted and connected by byte checksum in the same batch. Both CTF
  artifact layouts (flat manifest, nested artifact set) are supported; a
  plain tar of SPDX files works too. Hand-rolled tar/gzip handling (PAX +
  GNU longnames, zip-bomb caps, links never followed) — zero new runtime
  dependencies. Read-only: digests are displayed, never verified. See
  `docs/ocm.md`.
- VS Code: explorer multi-select and a new "Open folder with SBOM Lens"
  context entry load several documents into ONE shared panel — the middle
  ground between a single file and the whole-workspace scan. `.ctf`
  deliveries open from the explorer as well.

## [0.9.0] — 2026-07-11

### Added
- **Custom compliance profiles**: define your organization's own minimum
  elements as a small `sbomlens-profile/v1` JSON — document-field presence
  with regex/allow-list modifiers, relationship minimums, created-recency,
  and per-package coverage gates with thresholds. Import per drag&drop
  (content-detected), *Open → Compliance profile…*, a URL, the deployment
  catalog (`profiles` field — rolled out to every user of an instance), or
  `.sbomlens/profile.json` in a VS Code workspace. The Quality section gains
  a profile picker, threshold-aware meters (`≥N%`, amber when failing), and
  a Markdown report export for audits. The built-in NTIA report is now a
  profile in the same engine; validation is fail-closed (an unknown check
  type rejects the profile instead of silently weakening it). Imported
  profiles persist (16 profiles / 256 KB budget).
- CI supply-chain hygiene: osv-scanner gate on every push (GitLab + GitHub),
  GitLab SAST + Secret Detection, Trivy image scan on tags, a per-release
  self-SBOM artifact (`sbomlens-<tag>.spdx.json` — dogfooding), and Renovate
  as a scheduled in-project job. See `docs/ci-security.md`.

## [0.8.1] — 2026-07-11

### Added
- **Per-document accent colors**: cross-document badges in the Explore tree,
  the document column in the Inventory, and the nodes in both maps carry a
  deterministic color per document name — the same document is recognizable
  at a glance everywhere.
- **Theme switch**: a topbar toggle cycles system → light → dark (persisted
  as a preference; "system" keeps following the OS or editor theme live).
- Topbar links to the GitLab repository and the GitHub mirror.

## [0.8.0] — 2026-07-11

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

## [0.7.0] — 2026-07-11

### Added
- **Subtree expansion**: Shift+click a chevron (or press `*`) to expand an
  entire subtree at once — across document boundaries, so a component's full
  resolved cascade unfolds in one action (capped at 2000 nodes with a notice).
- **Show cascade in Inventory**: a button in the document detail filters the
  Inventory to the document plus everything reachable through its resolved
  references — the flat, exportable answer to "all sub-elements of X".
- **Tree filter in place**: the funnel toggle next to the search box filters
  the Explore tree directly — matches stay put with their ancestor chain as
  dimmed context, siblings disappear. Expanding a filtered node zooms back out
  to the full tree at that spot; a header bar shows the match count and a
  one-click way back.
- **Spec links**: the ⓘ field tooltips now link into the rendered SPDX 2.3
  specification — click to open the exact field section (hand-curated anchors,
  verified against spdx.github.io).

### Changed
- **Map v2**: left-to-right collapsible tree layout replaces the top-down lane
  grid. Wide levels stack vertically instead of producing a 7000px row; nodes
  fold their subtree behind a `+N` badge; workspaces over 24 documents start
  with only the roots expanded; Expand/Collapse-all in the toolbar; search
  force-reveals matching documents. Readable at 70+ documents.

## [0.6.0] — 2026-07-11

### Added
- **Map view**: the document topology as a full-canvas graph with pan, wheel
  zoom-to-cursor and fit-to-view — readable at 77+ documents (compact node
  mode, fan-out edge de-emphasis, barycenter lane ordering). Nodes select
  documents (detail rail), double-click jumps into Explore, the search query
  highlights matching documents, missing references appear as clickable
  stubs. The inline sidebar minimap now hands over to the Map view above 12
  documents.
- **Cascade-aware removal**: removing a document now asks what should happen
  to documents only reachable through it — "Remove all N" or "Keep them as
  roots". A new manage-documents dialog (click the status-bar document count)
  offers multi-select bulk removal with a live orphan summary.
- Extension roadmap (VS Code + Chromium) documented in
  `docs/extension-architecture.md`.

### Fixed
- Removing a document no longer unconditionally clears the selection, and
  stale expansion state is pruned so re-added documents don't self-expand.

## [0.5.0] — 2026-07-11

### Added
- **Fetch all references**: one click in the status bar downloads every
  referenced document *recursively* (fixpoint over newly discovered
  references, 4 parallel fetches, capped) — the full cascade for analysis
  without clicking each placeholder. Structural references are always
  attempted; informational ones only when their URL looks like an SPDX
  document.
- Catalog sources support `resolveRefs: true`: list only the root document
  and the whole tree assembles itself after loading.

## [0.4.0] — 2026-07-11

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

## [0.3.0] — 2026-07-11

### Added
- **YAML input** — the third official SPDX 2.x serialization; parsed in the
  worker only, so the main bundle stays lean.
- **Spec field docs**: ⓘ tooltips on detail fields carry the SPDX 2.3
  specification's own property documentation, generated at build time from the
  official JSON schema (`npm run generate:spec-docs`).
- Public repository metadata (gitlab.com canonical, GitHub mirror) and
  CC-BY-3.0 attribution for spec-derived content in `NOTICE`.

## [0.2.0] — 2026-07-11

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

## [0.1.0] — 2026-07-11

Initial release: SPDX 2.3 viewer (tag-value + JSON) with cascading
`externalDocumentRef` resolution (checksum → namespace → manual, suggestions
for drifted names), lazily derived cross-document tree with placeholders and
cycle guard, worker-based parsing, virtualized UI, ranked search with facets,
diagnostics, file/folder/URL loading with per-host session tokens, bundled
demo cascade, Docker image, GitLab CI (Pages + kaniko) and GitHub Actions.
