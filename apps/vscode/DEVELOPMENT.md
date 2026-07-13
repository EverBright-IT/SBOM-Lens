# SBOM Lens for VS Code — development & publishing

Maintainer documentation. The user-facing extension page is
[README.md](README.md) — it is rendered verbatim as the store listing, so
keep build/publish details out of it.

## Development

```sh
npm install                                # repo root
npm run build:vscode -w @sbomlens/web      # webview bundle → apps/web/dist-vscode
npm run compile -w sbomlens                # extension bundle + media copy
```

Then open the repo in VS Code and press **F5** ("Run SBOM Lens extension").

### Manual F5 checklist

- [ ] Open a multi-MB `.spdx` file via "Reopen editor with… → SBOM Lens" —
      parses off-thread (UI stays responsive), tree renders.
- [ ] Drop several files of a cascade into the panel — references resolve,
      document map fills in.
- [ ] Multi-select two cascade files → "Open with SBOM Lens" — ONE shared
      panel with both documents linked.
- [ ] Right-click a folder → "Open folder with SBOM Lens" — only that
      folder's SBOMs load; re-running replaces the shared panel's content.
- [ ] "SBOM Lens: Scan workspace for SBOMs" — singleton panel, progress
      notification, >50 MB files skipped with a warning.
- [ ] From URL with a token — token survives a window reload
      (`context.secrets`), fetch works against a CORS-less server.
- [ ] Inventory → Export CSV — native save dialog, file lands on disk.
- [ ] Field ⓘ links open the SPDX spec in the external browser.
- [ ] A `.sbomlens/profile.json` in the workspace shows up in the Quality
      section's profile dropdown of every panel.
- [ ] Switch editor tabs away and back — panel state is retained
      (`retainContextWhenHidden`).
- [ ] Remote/WSL window, if available: all of the above.

## Packaging

```sh
npm run package -w sbomlens                # → sbomlens.vsix (repo root)
```

The vsix ships zero runtime dependencies (`vsce --no-dependencies`; the
extension is a single esbuild bundle). CI builds the vsix on every tag.
`.vscodeignore` is an allowlist — new files are excluded from the package
unless explicitly added there.

## Publishing

Two registries matter; both are one-time account setups followed by a
one-command publish. The `publisher` in `package.json` is `everbright-it` —
the account ids MUST match it.

### Open VSX (VSCodium, Gitpod, Theia, Cursor…)

Published — the listing lives at
<https://open-vsx.org/extension/everbright-it/sbomlens>.

1. Log in at <https://open-vsx.org> with GitHub, link the Eclipse account,
   and sign the publisher agreement. (Done.)
2. Create an access token (user settings), then once:
   `npx ovsx create-namespace everbright-it -p <TOKEN>`. (Done; the
   namespace *claim* — verified-publisher status — runs separately via an
   EclipseFdn issue + DNS TXT record.)
3. Re-publish a new version: bump the workspace version (lockstep procedure
   in the root README), rebuild, then
   `npx ovsx publish sbomlens.vsix -p <TOKEN>`.

### VS Code Marketplace (status: publisher setup pending)

1. Sign in at <https://marketplace.visualstudio.com/manage> with a Microsoft
   account and **create the publisher `everbright-it`** (display name free).
2. Create an Azure DevOps **Personal Access Token** at
   <https://dev.azure.com> → User settings → Personal access tokens:
   Organization = *All accessible organizations*, Scope = **Marketplace →
   Manage**. Note: brand-new Azure DevOps orgs may require an Azure
   subscription — the web upload in the manage portal bypasses the PAT
   entirely.
3. Build fresh and publish:

   ```sh
   npm run build:vscode -w @sbomlens/web
   npm run compile -w sbomlens
   npm run package -w sbomlens
   cd apps/vscode && npx @vscode/vsce publish --no-dependencies --packagePath ../../sbomlens.vsix -p <PAT>
   ```

   Alternatively upload `sbomlens.vsix` by hand in the manage portal — no
   token handling in the terminal.

### Notes

- The store pages render `README.md`; the icon comes from `icon.png`
  (rasterized from `docs/brand/vscode-icon.svg`). Images/links in the README
  must be absolute URLs — relative paths break on the registry pages.
- Versions are immutable per registry — bump before re-publishing.
- Store the PATs outside the repo. For CI publishing later: masked CI
  variables and a manual tag job (`vsce publish` + `ovsx publish`) —
  deliberately not wired up until both accounts exist.
