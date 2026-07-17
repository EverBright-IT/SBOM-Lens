![SBOM Lens: a fast, minimal viewer for SPDX SBOMs](docs/banner.png)

# SBOM Lens

Drop a release-level SPDX document plus its component SBOMs and navigate the whole
supply chain as one tree: release → component → sub-component → container image →
package. Everything runs in your browser; files never leave your machine.

**Try it:** <https://sbom-lens.everbright-it.de/app/>. The project landing
page lives at <https://sbom-lens.everbright-it.de/>. The VS Code extension is
on [Open VSX](https://open-vsx.org/extension/everbright-it/sbomlens).

> **Two products ship from this monorepo.** This page is about **SBOM Lens**,
> the SPDX viewer. Its sibling **OCM Lens** reads Open Component Model
> deliveries (CTF and component archives, signature verification included)
> and has its own product home:
> [repository](https://gitlab.com/everbrightit-group/ocm-lens) ·
> [landing](https://ocm-lens.everbright-it.de/) ·
> [Open VSX](https://open-vsx.org/extension/everbright-it/ocmlens).
> Issues for both products live in this repo's tracker.

![SBOM Lens: the Explore view with the demo cascade loaded, showing the tree with cross-document badges, the detail pane with relationships, and the document map](docs/screenshot.png)

<sub>Regenerate with `npm run screenshot -w @sbomlens/web` (dev server running).</sub>

## Why SBOM Lens

- **Cascading documents are first-class.** SPDX 2.3 links documents via
  `ExternalDocumentRef` and cross-document relationships
  (`DocumentRef-X:SPDXRef-Y`). SBOM Lens resolves those references across every
  file you load, by checksum first and then namespace, and renders one continuous,
  lazily-expanded tree across document boundaries. Unresolved references appear as
  actionable placeholders: fetch them by URL, drop the file, or confirm a
  suggested match.
- **Fast at real-world scale.** Multi-megabyte documents (6,500+ packages) parse
  in a Web Worker; the tree and source views are virtualized; search runs against
  a prebuilt index with ranked results. No pagination, no jank.
- **Private by design.** A static, client-only app. SBOMs are parsed locally and
  never uploaded. URL fetching only happens when you explicitly ask for it.
- **Honest about dirty data.** Real SBOMs have quirks: checksum spacing variants,
  duplicate SPDXIDs, references without relationships, unknown relationship
  types, versions hiding in purls. The parser tolerates all of it and reports
  what it found as per-document diagnostics instead of refusing to load.
- **Answers questions, not just files.** Beyond browsing: an exportable
  cross-cascade inventory, version-conflict detection, release-to-release
  diffs, and a per-document NTIA quality report.

## Quick start

```sh
git clone https://gitlab.com/everbrightit-group/sbom-lens.git
cd sbom-lens
npm ci
npm run dev      # → http://localhost:5173
```

Click **Load example** for a bundled four-document demo cascade, or drop your own
`.spdx` / `.spdx.json` files (multi-select and whole folders work).

## Loading documents

| Method | Notes |
| --- | --- |
| Drag & drop | Anywhere in the window; folders are walked recursively |
| Open ▸ Files / Folder | Standard pickers |
| Open ▸ From URL | Fetches a document over HTTP(S), e.g. from a GitLab generic package registry |
| Placeholder ▸ Fetch | Each unresolved reference offers a one-click fetch of its recorded URL |
| **Fetch all** (status bar) | Downloads every referenced document **recursively** until the cascade is complete. One click for the full tree instead of one per placeholder |

**Access tokens:** for private registries, add a per-host token in the URL dialog
(GitLab `PRIVATE-TOKEN` or `Authorization: Bearer`). Tokens live in
`sessionStorage` only: they die with the tab and are never persisted.

**CORS:** the browser can only fetch URLs whose server allows cross-origin
requests. When it doesn't, SBOM Lens says so plainly. Download the file and drop
it in instead, or self-host the viewer behind the same reverse proxy as your
registry so requests are same-origin.

## How references resolve

For every `ExternalDocumentRef` of every loaded document, in order of precedence:

1. **Checksum**: the reference's SHA-1 matches a loaded file's bytes. The
   strongest signal, and the only one that works when reference URIs are download
   URLs rather than namespaces.
2. **Namespace**: the reference URI equals a loaded document's
   `documentNamespace` (the spec-blessed path).
3. **Manual**: you bind a file to the reference yourself.

Name similarity ("looks like `acme-auth-service`") is only ever shown as a
one-click *suggestion*, never auto-bound, because DocumentRef names drift from
actual file versions in the wild.

References that no relationship points into (scan reports, attestations, release
notes) are classified as *informational*: they're listed under **External
documents** without nagging you to resolve them.

## Analysis views

| View | What it answers |
| --- | --- |
| **Explore** | "What does this release contain?" The cascading tree, detail pane, and raw source. Shift+click a chevron (or press `*`) to expand an entire subtree including resolved sub-SBOMs; the funnel next to the search box filters the tree in place, leaving matches plus their ancestors and hiding everything else |
| **Map** | "How is this cascade wired?" The document topology as a collapsible left-to-right tree: documents as nodes, resolved references as method-styled edges, missing documents as dashed stubs. Nodes fold their subtree behind a `+N` badge (large workspaces start folded), search force-reveals matches, pan/zoom, click selects, double-click jumps into Explore |
| **Inventory** | "Give me the parts list as a file." One sortable table across all documents, filtered by the same search + facet chips (documents, kinds, purposes, licenses), exportable as CSV/JSON |
| **Conflicts** | "Which packages ship in more than one version?" Grouped by purl identity across the whole cascade, each occurrence one click from its place in the tree |
| **Diff** | "What changed between these two releases?" Added, removed and version-changed packages between two cascades (each side is a document plus everything reachable through its resolved references), copyable as Markdown for release notes |

Each document's detail pane additionally shows a **quality report** oriented on
the NTIA minimum elements: author/timestamp/namespace/relationship checks, plus
per-package coverage of versions, suppliers, unique IDs, checksums, and licenses.
Factual numbers, no invented score. Organizations can go further with
**custom compliance profiles**: a small JSON file with your own minimum
elements (field presence, patterns, coverage thresholds, recency) that imports
per drag&drop, via the deployment catalog, or from `.sbomlens/profile.json`
in a VS Code workspace. Reports export as Markdown. See
[docs/compliance-profiles.md](docs/compliance-profiles.md).

Drop an **OpenVEX document** next to your SBOMs and the viewer shows what the
supplier communicates about known vulnerabilities: per-package statements with
status, justification, and action, a VEX column + status filter in the
Inventory, and findings riding the exports. Matched by package URL, newest
statement wins; it is a communication channel, not a scanner. See
[docs/vex.md](docs/vex.md).

## Keyboard

| Key | Action |
| --- | --- |
| `/` | Focus search |
| `↑` `↓` | Move selection in tree / results |
| `→` | Expand node, then first child |
| `←` | Collapse node, then parent |
| `*` | Expand entire subtree (also: Shift+click a chevron) |
| `Enter` | Toggle node / open search result |
| `Esc` | Clear search, close panels |
| `?` | Shortcut help |

## Supported formats

- **SPDX 2.x tag-value** (`.spdx`), **JSON**, and **YAML**: fully supported.
  Detection is content-based, never by file extension.
- **SPDX 3.0.x JSON-LD**: loads. Packages, files, relationships, hashes,
  external identifiers (purl, CPE), and license relationships map onto the
  same views as 2.x; elements from profiles outside core/software (AI,
  dataset, build) are counted in a notice rather than shown. Tag-value has
  no 3.x serialization; other 3.x serializations are not parsed.
- **CycloneDX** and **Trivy-native JSON**: recognized with a pointer to the
  right conversion (`trivy --format spdx-json`, `cyclonedx convert`).

The detail views carry the spec with them: hover the info icon next to a field
to read the SPDX 2.3 specification's own documentation for it, distilled at
build time from the official JSON schema (`npm run generate:spec-docs`). Click
the icon to open that field's section in the rendered specification. SPDX 3.x
documents render without these tooltips for now: the 2.3 texts would be wrong
for 3.0 fields, and curated 3.0.1 texts are a follow-up.

## Limits

Known boundaries, stated plainly so nothing surprises you:

- **Format scope.** SPDX 2.x in full; SPDX 3.0.x as JSON-LD with the
  core/software profiles mapped (other profiles are counted, not rendered,
  and external document maps are not followed). CycloneDX and Trivy-native
  JSON are recognized with a conversion hint, not parsed. Detection is
  content-based.
- **HTTPS or localhost required.** Cascade resolution hashes file bytes with
  `crypto.subtle`, which browsers expose only in secure contexts. Over plain
  HTTP on a non-localhost host, hashing (and therefore checksum-based
  reference resolution) does not run.
- **URL loading needs CORS.** The browser can only fetch a document whose
  server allows cross-origin requests. When it can't, SBOM Lens says so;
  download the file and drop it in, or self-host behind the same origin as
  your registry (see below).
- **Size.** No hard cap on a single SPDX document: multi-megabyte files with
  thousands of packages parse in a Web Worker. In the **VS Code** extension,
  the workspace scan skips individual files over **50 MB** (open those by
  hand). Expanding an entire subtree stops at **2,000 nodes** with a notice,
  and the tree walks to a depth of 64.
- **Compliance profiles.** A profile file is capped at **64 KB** and **200
  checks**; up to **16** imported profiles persist (**256 KB** total), beyond
  which they stay for the session only.
- **Private, and it stays that way.** No upload path, no telemetry. Only
  preferences and imported profiles are persisted (locally); loaded documents
  are not. Deep links therefore need addressable sources (a catalog entry or
  a URL-loaded document), not dropped files.
- **Not in scope by design.** No license-compliance judgement (license fields
  are shown, not interpreted) and no vulnerability or VEX overlays in the
  core model.

## Self-hosting

SBOM Lens builds to a fully static site (`apps/web/dist/`) that any web server
can host.
A minimal nginx image (~25 MB) is included:

```sh
docker build -f deploy/Dockerfile -t sbomlens .
docker run --rm -p 8080:80 sbomlens
# → http://localhost:8080
```

The bundled nginx config ships hardened security headers (CSP,
`nosniff`, `frame-ancestors 'none'`) by default. See
[deploy/nginx.conf](deploy/nginx.conf) for what the CSP allows and why.
Serve the app over **HTTPS** (or localhost): the SHA-1 hashing that drives
cascade resolution uses `crypto.subtle`, which browsers only expose in
secure contexts. When proxying private registries through the same origin,
scope the server-side token read-only and restrict who can reach the proxy
(notes in the config).

The build uses relative asset paths, so it works at any base path, including
GitLab or GitHub Pages subpaths. The app is a PWA: once visited, it keeps
working offline (including the bundled examples).

### Preconfigured SBOM catalog

A self-hosted instance can ship a curated list of SBOMs so users just open the
viewer and analyze, without hunting for files. Place a `sbomlens.catalog.json`
next to `index.html`:

```json
{
  "title": "ACME releases",
  "sources": [
    {
      "label": "Platform 1.0 (current release)",
      "description": "Release SBOM plus component SBOMs",
      "urls": ["sboms/1.0/platform.spdx"],
      "loadOnStart": false,
      "resolveRefs": true
    }
  ]
}
```

Entries appear on the start screen and in the **Open** menu; `loadOnStart`
sources load automatically. With `resolveRefs: true` you only list the root
document. After it loads, every referenced SBOM is fetched recursively, so one
click gives users the complete tree for analysis. The catalog is only ever read
from this fixed same-origin path (never from a URL parameter), and only
http(s)/relative URLs are accepted.

**Reaching private registries (GitLab etc.):** browsers block cross-origin
requests unless the server sends CORS headers, and GitLab's API does not. The
robust pattern is a **same-origin reverse proxy**: the bundled
[deploy/nginx.conf](deploy/nginx.conf) contains a commented sample that proxies
`/sboms/...` to a GitLab generic-package registry and injects a **read-only**
token server-side. Users need no tokens, nothing is cross-origin, and no secret
ever appears in the catalog file. Never put tokens into
`sbomlens.catalog.json`. Direct absolute URLs also work where the server allows
CORS; authentication then uses the per-host session tokens in the URL dialog.

## Development

```sh
npm run dev          # dev server
npm test             # unit tests (Vitest)
npm run lint         # ESLint
npm run typecheck    # tsc --noEmit
npm run build        # typecheck + production build
```

Releases bump every workspace in lockstep:

```sh
npm version 0.X.0 --workspaces --include-workspace-root --no-git-tag-version
git commit -am "release: v0.X.0" && git tag -a v0.X.0 -m "SBOM Lens 0.X.0"
```

The tag pipeline turns the tag into a GitLab release automatically: the
notes are that version's CHANGELOG section, the assets are both vsix files
and the self-SBOM (served from the package registry, so the links do not
expire). Pushing the same tag in the
[OCM Lens product home](https://gitlab.com/everbrightit-group/ocm-lens)
creates the matching release there; push it after this repo's tag pipeline
finished, so its vsix asset link finds the published package.

Supply-chain hygiene: every push runs an osv-scanner CVE gate, SAST, and
secret detection; releases additionally get a Trivy image scan and ship
their own SPDX SBOM (`sbomlens-<tag>.spdx.json`, which opens in SBOM Lens).
Dependency updates arrive as Renovate MRs. Details: [docs/ci-security.md](docs/ci-security.md).

The repository is an npm workspace, layered deliberately:

```
packages/core/        @sbomlens/core, the framework-free domain: parsers
                      (tag-value/JSON/YAML), workspace, reference resolution,
                      graph indexes, tree derivation, search, analysis
                      (inventory/conflicts/diff/quality), generated spec docs.
                      Zero React imports, enforced by ESLint.
apps/web/src/worker/  a thin Web Worker shell around core parsing (hashing +
                      parsing off the UI thread; yaml loads only here).
apps/web/src/app/     zustand store, ingest pipeline (files / folders / URLs),
                      deployment catalog, memoized selectors.
apps/web/src/ui/      React components: virtualized tree + document map,
                      detail pane, analysis views, search, diagnostics.
apps/web/src/host/    HostAdapter seam: browser host (fetch, web storage,
                      module workers) and VS Code webview host (postMessage
                      bridge, blob workers, editor secret storage).
apps/vscode/          the VS Code extension: custom editor + workspace scan
                      around the same webview bundle (see its README).
```

The repository also builds a sibling product from this codebase: **OCM Lens**,
a viewer for Open Component Model component versions and deliveries
([docs/ocm.md](docs/ocm.md); product home
[gitlab.com/everbrightit-group/ocm-lens](https://gitlab.com/everbrightit-group/ocm-lens),
live at [ocm-lens.everbright-it.de](https://ocm-lens.everbright-it.de/)).
It is a separate concern, and the split is
structural, not cosmetic: descriptor mapping, the tar reader, and gzip live
behind `@sbomlens/core/ocm`, only OCM Lens wires them in, and a CI gate fails
the build if a byte of that code reaches the SBOM Lens bundle. SBOM Lens is an
SPDX viewer: it recognizes a component descriptor only well enough to tell
you it isn't an SBOM.

`packages/core/fixtures/` contains synthetic documents reproducing every
real-world quirk the parser supports;
`apps/web/scripts/generate-examples.mjs` regenerates the demo cascade. To
validate against a private SBOM collection without committing it:
`SBOM_CORPUS_DIR=~/my-sboms npm run check-corpus`.

## Roadmap

- **SPDX 3.x, deeper**: curated 3.0.1 field tooltips, external document
  maps, and serializations beyond JSON-LD. Loading 3.0.x JSON works today
  (see [Supported formats](#supported-formats)).
- **Chromium extension** ("Open in SBOM Lens" for raw SBOMs in the browser):
  a thin shell around the same codebase, like the VS Code extension that now
  lives in [apps/vscode](apps/vscode/README.md) ("Open with SBOM Lens",
  workspace scanning; published on
  [Open VSX](https://open-vsx.org/extension/everbright-it/sbomlens)).
  Architecture:
  [docs/extension-architecture.md](docs/extension-architecture.md).
- **CycloneDX** read support via the same adapter seam
- Workspace persistence (File System Access API), shareable deep links
  (deep links require addressable sources: catalog or URL-loaded documents)
- Optional overlays (vulnerabilities), kept out of the core model

## Repository & mirrors

Development happens on EverBright's GitLab; changes are mirrored to the public
repositories:

- GitLab (canonical public repo): <https://gitlab.com/everbrightit-group/sbom-lens>
- GitHub mirror: <https://github.com/EverBright-IT/SBOM-Lens>

Issues and contributions are welcome on either platform; maintainers sync them
into the primary repository.

## License

[Apache-2.0](LICENSE) © EverBright IT GmbH. Maintained by
[EverBright IT GmbH](https://everbright-it.de). Field documentation shown in
the UI is derived from the [SPDX specification](https://spdx.dev) (CC-BY-3.0,
© The Linux Foundation and SPDX contributors).
