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

OCM Lens 2.x on top ("Run OCM Lens extension" launch config; its
pre-launch task runs `npm run build:vscode -w @sbomlens/ocm-lens` and
`npm run compile -w ocmlens`):

- [ ] Open a `.ctf` (custom editor): the 2.0 dashboard shows the delivery;
      Components, Resources, and Verify work.
- [ ] Right-click a folder with several `component-descriptor.yaml` files
      -> "Open folder with OCM Lens": ONE bundle, references resolved
      across the files.
- [ ] "OCM Lens: Open component version from registry..." against
      `ghcr.io/open-component-model/ocm` / `ocm.software/ocmcli`: tags list,
      the version opens in the 2.0 views.
- [ ] "OCM Lens: Set registry credential..." stores/clears a `user:token`.
- [ ] Deep link: `open 'vscode://everbright-it.ocmlens/open?path=...'`
      with an absolute `.ctf` path opens the delivery after the consent
      prompt.
- [ ] A `.ctf` over 32 MB opens without freezing the extension host
      (pushed as a resource URI, streamed from disk).
- [ ] A key pinned in the 1.x extension verifies the ECME demo signature
      without pasting it again.
- [ ] Export the acceptance report and download an artifact blob: both
      open VS Code's save dialog and write the file.
- [ ] Light and dark theme both render correctly.

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

**CI does this.** A `v*` tag builds SBOM Lens and offers the manual
`publish-sbomlens` job; an `ocm-lens-v*` tag builds OCM Lens 2.x (packaged
for the **pre-release** channel while 2.x is in beta) and offers the manual
`publish-ocmlens` job. They are manual on purpose: an Open VSX version is
immutable, so nobody can take back an accidental publish. Each job verifies
the token, then refuses to run if the tag and the manifest version
disagree.

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
   publish job: *Settings → Repository → Protected tags* → protect `v*` AND
   `ocm-lens-v*` (OCM Lens 2.x has its own tag namespace). A
   protected variable is passed *only* to pipelines on protected branches or
   protected tags; without this the job sees an empty token and stops with
   "OVSX_TOKEN is not set". If a tag pipeline was created before you protected
   the pattern, push a fresh tag rather than retrying the old job.

Publishing by hand still works, e.g. before the variable exists:

```sh
npx ovsx publish sbomlens.vsix -p <TOKEN>
npx ovsx publish ocmlens.vsix --pre-release -p <TOKEN>
```

OCM Lens 2.x stays on the pre-release channel until it goes stable; the
packaged vsix carries the pre-release flag itself, so the Marketplace web
upload below needs no extra step. Open VSX resolves `latest` to the highest
version even when it is a pre-release: its listing and version badge show
2.x as soon as it is published, and clients that ignore the flag install it.

### VS Code Marketplace

1. Sign in at <https://marketplace.visualstudio.com/manage> with a Microsoft
   account and **create the publisher `everbright-it`** (display name free).
   (Done.)
2. Publish. Two ways, and the second is not a consolation prize: for a fresh
   Microsoft account it is often the only one that works at all.

   - **Web upload**: *New extension → Visual Studio Code* in the manage
     portal, hand it `sbomlens.vsix` / `ocmlens.vsix`; for an extension that
     is already listed, use its *... → Update* instead. No token anywhere.
   - **CI**: the manual `publish-vsce-sbomlens` / `publish-vsce-ocmlens` jobs
     on a tag. They need `VSCE_TOKEN` as a masked, protected variable: an
     Azure DevOps **Personal Access Token** from <https://dev.azure.com> →
     User settings → Personal access tokens, Organization = *All accessible
     organizations*, Scope = **Marketplace → Manage** (`Show all scopes`
     first, or Marketplace is not offered).

   The PAT is not always obtainable, and the failure is structural rather
   than a mistake to debug: a PAT needs an Azure DevOps organization, and
   creating a *new* organization now requires an active Azure subscription.
   Without an organization <https://dev.azure.com/_usersSettings/tokens> is a
   plain 404: there is no token page to find. The Azure *portal*
   (portal.azure.com) is a different product and never has one. This
   project has the token: `VSCE_TOKEN` is set, and the manual CI jobs
   publish both extensions from their tag pipelines. The web upload stays
   the fallback for when the PAT expires or the jobs cannot run.

3. Build fresh, then publish:

   ```sh
   npm run build:vscode -w @sbomlens/web
   npm run compile -w sbomlens
   npm run package -w sbomlens
   npx @vscode/vsce publish --packagePath sbomlens.vsix
   ```

   `--packagePath` reads the manifest out of the vsix, so this runs from the
   repo root and needs no `cd`. Leave `-p` off: vsce takes the token from
   `VSCE_PAT` in the environment, which keeps it out of the shell history.

### Notes

- The store pages render `README.md`; the icon comes from `icon.png`
  (rasterized from `docs/brand/vscode-icon.svg`). Images/links in the README
  must be absolute URLs: relative paths break on the registry pages.
- Versions are immutable per registry: bump before re-publishing. Publishing
  the same version twice fails loudly rather than silently doing nothing,
  which is the point: a no-op that looks like success is worse than an error.
- Store the PATs outside the repo. Both registries publish from manual CI
  jobs on a tag; both read their token from the environment rather than a
  command line.
