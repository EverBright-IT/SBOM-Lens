# SBOM Lens for VS Code: development & publishing

Maintainer documentation. The user-facing extension page is
[README.md](README.md): it is rendered verbatim as the store listing, so
keep build/publish details out of it.

## Development

```sh
npm install                                # repo root
npm run build:vscode -w @sbomlens/web      # webview bundle → apps/web/dist-vscode
npm run compile -w sbomlens                # extension bundle + media copy
```

Then open the repo in VS Code and press **F5** ("Run SBOM Lens extension").

### Manual F5 checklist

- [ ] Open a multi-MB `.spdx` file via "Reopen editor with... → SBOM Lens" -
      parses off-thread (UI stays responsive), tree renders.
- [ ] Drop several files of a cascade into the panel: references resolve,
      document map fills in.
- [ ] Multi-select two cascade files → "Open with SBOM Lens": ONE shared
      panel with both documents linked.
- [ ] Right-click a folder → "Open folder with SBOM Lens": only that
      folder's SBOMs load; re-running replaces the shared panel's content.
- [ ] "SBOM Lens: Scan workspace for SBOMs": singleton panel, progress
      notification, >50 MB files skipped with a warning.
- [ ] From URL with a token: token survives a window reload
      (`context.secrets`), fetch works against a CORS-less server.
- [ ] Inventory → Export CSV: native save dialog, file lands on disk.
- [ ] Field info icon links open the SPDX spec in the external browser.
- [ ] A `.sbomlens/profile.json` in the workspace shows up in the Quality
      section's profile dropdown of every panel.
- [ ] Switch editor tabs away and back: panel state is retained
      (`retainContextWhenHidden`).
- [ ] Remote/WSL window, if available: all of the above.

OCM Lens on top ("Run OCM Lens extension" launch config):

- [ ] "OCM Lens: Open component version from registry..." against
      `ghcr.io/open-component-model/ocm` / `ocm.software/ocmcli`: tags list,
      version opens as a delivery, SBOM linked underneath.
- [ ] Load a descriptor with an unresolved `componentReferences` entry:
      the placeholder detail offers *Fetch from registry* prefilled from
      the repository context; fetching resolves and reveals the reference.
- [ ] "OCM Lens: Set registry credential..." stores/clears a `user:token`
      (verify a private registry, or at least that the flow round-trips).
- [ ] Deep link: `open 'vscode://everbright-it.ocmlens/open?path=...'`
      with an absolute `.ctf` path opens the delivery after the consent
      prompt.
- [ ] Drop a large (hundreds of MB) `.ctf` into the panel: loads without
      freezing the extension host.

## Packaging

```sh
npm run package -w sbomlens                # → sbomlens.vsix (repo root)
```

The vsix ships zero runtime dependencies (`vsce --no-dependencies`; the
extension is a single esbuild bundle). CI builds the vsix on every tag.
`.vscodeignore` is an allowlist: new files are excluded from the package
unless explicitly added there.

## Publishing

Two registries matter; both are one-time account setups followed by a
one-command publish. The `publisher` in `package.json` is `everbright-it` -
the account ids MUST match it.

### Open VSX (VSCodium, Gitpod, Theia, Cursor...)

Published: the listing lives at
<https://open-vsx.org/extension/everbright-it/sbomlens>. OCM Lens publishes
to the same namespace as `everbright-it.ocmlens`.

**CI does this.** Every tag pipeline builds both vsix and offers a manual
`publish-sbomlens` / `publish-ocmlens` job in the `publish` stage. They are
manual on purpose: an Open VSX version is immutable, so nobody can take back
an accidental publish. Each job verifies the token, then refuses to run if
the tag and the manifest version disagree.

One-time setup:

1. Log in at <https://open-vsx.org> with GitHub, link the Eclipse account,
   and sign the publisher agreement. (Done.)
2. Create an access token (user settings), then once:
   `npx ovsx create-namespace everbright-it -p <TOKEN>`. (Done; the
   namespace *claim*, i.e. verified-publisher status, runs separately via an
   EclipseFdn issue + DNS TXT record.)
3. Add that token as **`OVSX_TOKEN`**, a *masked* and *protected* CI variable.
   `ovsx` reads it from the environment as `OVSX_PAT`, so it never reaches a
   command line or a job log.
4. **Protect the release tags** so the protected variable actually reaches the
   publish job: *Settings → Repository → Protected tags* → protect `v*`. A
   protected variable is passed *only* to pipelines on protected branches or
   protected tags; without this the job sees an empty token and stops with
   "OVSX_TOKEN is not set". If a tag pipeline was created before you protected
   the pattern, push a fresh tag rather than retrying the old job.

Publishing by hand still works, e.g. before the variable exists:

```sh
npx ovsx publish sbomlens.vsix -p <TOKEN>
npx ovsx publish ocmlens.vsix -p <TOKEN>
```

### VS Code Marketplace (status: publisher setup pending)

1. Sign in at <https://marketplace.visualstudio.com/manage> with a Microsoft
   account and **create the publisher `everbright-it`** (display name free).
2. Create an Azure DevOps **Personal Access Token** at
   <https://dev.azure.com> → User settings → Personal access tokens:
   Organization = *All accessible organizations*, Scope = **Marketplace →
   Manage**. Note: brand-new Azure DevOps orgs may require an Azure
   subscription: the web upload in the manage portal bypasses the PAT
   entirely.
3. Build fresh and publish:

   ```sh
   npm run build:vscode -w @sbomlens/web
   npm run compile -w sbomlens
   npm run package -w sbomlens
   cd apps/vscode && npx @vscode/vsce publish --no-dependencies --packagePath ../../sbomlens.vsix -p <PAT>
   ```

   Alternatively upload `sbomlens.vsix` by hand in the manage portal: no
   token handling in the terminal.

### Notes

- The store pages render `README.md`; the icon comes from `icon.png`
  (rasterized from `docs/brand/vscode-icon.svg`). Images/links in the README
  must be absolute URLs: relative paths break on the registry pages.
- Versions are immutable per registry: bump before re-publishing. Publishing
  the same version twice fails loudly rather than silently doing nothing,
  which is the point: a no-op that looks like success is worse than an error.
- Store the PATs outside the repo. Open VSX publishing runs in CI (see
  above); the Marketplace stays manual until its publisher exists, then it
  can extend the same job shape with `vsce publish`.
