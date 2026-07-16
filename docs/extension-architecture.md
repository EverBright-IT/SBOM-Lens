# Extension architecture: VS Code & Chromium

Status: **accepted roadmap design** (v0.7.0-v0.9.0). Nothing in this document
is built yet; it records the architecture so the enabler work lands in the
right shape. Guiding constraints: one reusable codebase, one version, one
release pipeline, and the privacy story (documents are parsed locally) must
survive every host.

## The enabler (v0.7.0): workspace split + host adapter

Two structural changes, no user-visible features:

1. **npm workspaces.**
   - `packages/core`: the React-free core, moved verbatim from `src/core`
     (the ESLint fence was built for this). Publishable as `@sbomlens/core`
     for third-party tooling.
   - `apps/web`: the current application (`src/app`, `src/ui`, `src/worker`).
   - Later: `apps/vscode`, `apps/chrome` as thin shells.
   One root version; CI builds every artifact from the same tag.

2. **`HostAdapter` interface.** The web app touches the host platform in a
   handful of places; everything else (UI, worker, core) is host-agnostic.
   The adapter isolates exactly those touchpoints:

   ```ts
   interface HostAdapter {
     /** Fetch SBOM bytes. Web: fetch + CORS rules. Extensions: privileged
      *  host fetch: CORS does not apply. */
     fetchDocument(url: string): Promise<ArrayBuffer>;
     /** UI preferences (sidebar width, map state). Web: localStorage.
      *  VS Code: Memento. Chrome: storage.local. */
     readPref(key: string): string | null;
     persistPref(key: string, value: string): void;
     /** Registry tokens. Web: sessionStorage (tab-scoped). VS Code:
      *  SecretStorage. Chrome: session storage area. */
     secret(host: string): Promise<string | null>;
     /** Inventory/diff exports. Web: blob download. VS Code: save dialog +
      *  workspace.fs. Chrome: downloads API. */
     exportFile(fileName: string, mime: string, text: string): void;
     openExternal(url: string): void;
     /** Push channel: extension shells inject documents (bytes + name). */
     onIngestMessage(cb: (fileName: string, bytes: ArrayBuffer) => void): void;
   }
   ```

   The web implementation is today's behavior, moved. `Fetch all references`
   automatically becomes CORS-free inside both extensions because it flows
   through `fetchDocument`.

## VS Code extension (v0.8.0, `apps/vscode`)

- **Surface:** `CustomReadonlyEditorProvider` registered for `*.spdx`,
  `*.spdx.json`, `*.spdx.yaml` ("Open with... SBOM Lens"), an explorer context
  menu entry, and a "SBOM Lens: scan workspace for SBOMs" command that feeds
  detected documents into the workspace like a catalog.
- **Webview:** hosts the built web app unchanged: local assets only, strict
  CSP (`default-src 'none'`, explicit `script-src`/`style-src`/`worker-src`
  for the parse worker), `retainContextWhenHidden` so the workspace survives
  tab switches.
- **Data flow:** the extension host reads file bytes via `workspace.fs`
  (transparently correct over Remote-SSH/WSL/Dev Containers) and pushes them
  through the ingest channel. Reference fetching and tokens live in the
  extension host (Node fetch + `SecretStorage`).
- **Release:** `vsce package` in the existing tag pipeline; publish to the
  VS Marketplace and Open VSX with the root package version.

## Chromium extension (v0.9.0, `apps/chrome`, Manifest V3)

- **The app ships inside the extension** as its own page
  (`chrome-extension://.../index.html`): works offline, needs no hosted
  instance. An options setting can instead hand off to a self-hosted
  instance URL for enterprises that prefer their catalog-equipped deployment.
- **Detection:** a content script sniffs raw document tabs (content type
  `text/plain`/`application/json` + body starting with `spdxVersion` /
  `SPDXVersion:`) and shows the page action "Open in SBOM Lens"; a context
  menu entry covers links to SBOM files.
- **Data flow:** the background service worker fetches the bytes using
  `optional_host_permissions` granted on demand (privacy-preserving: no
  blanket host access), opens the bundled viewer tab, and delivers the bytes
  via `chrome.runtime` messaging into the ingest channel. Recursive
  `Fetch all` routes through the background worker: CORS-free.
- **Release:** CI zips the extension on tags; Chrome Web Store / Edge Add-ons
  publishing is asynchronous to tagging (store review takes days).

## Non-goals for now

- No Firefox port until the MV3 surface stabilizes there.
- No monorepo before v0.7.0: the split is its own reviewable, feature-free
  release.
- No shared state between browser tabs / VS Code windows; each host instance
  owns one workspace.
