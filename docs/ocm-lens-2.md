# OCM Lens 2.0 - the OCM-native delivery explorer

> **This is the 2.0 rebuild** (`apps/ocm-lens`): a standalone app that models
> OCM in the spec's own vocabulary. The 1.x flavor (OCM mapped onto the SPDX
> document model inside `apps/web`) is frozen and will be removed once the
> VS Code extension has moved over. Code home is this monorepo; OCM Lens 2.0
> versions independently (2.x, own changelog in `apps/ocm-lens/`).

Open a delivery - a CTF (`.ctf`/`.tar`/`.tgz`), a component archive, or a
bare component descriptor - and see it as one picture: which component
versions it aggregates, what actually ships, whether the bytes match the
descriptor, and whether the signatures hold. Everything parses client-side
in a worker; files never leave the machine.

## The model (packages/core, framework-free)

`readOcmBundle` walks the archive once (`walkOcmDelivery`, shared with the
1.x path) and builds `OcmBundle`:

- **Component versions** (`OcmCv`): identity, provider, labels, repository
  contexts, signatures, resources/sources (`OcmArtifact`), references
  (`OcmRef`), plus the verbatim parsed descriptor root - the exact bytes-shape
  signature verification normalizes.
- **The reference graph**, reconstructed from the flat archive: aggregation
  is by identity with unbounded depth (the spec sets no limit). Roots are
  CVs nothing points at; a CV referenced twice is `shared` (diamond); a
  cycle-closing edge (the spec is silent on cycles) is marked `cyclic`,
  excluded from incoming-edge counting - which provably leaves every
  strongly connected subgraph with a natural entry point - and shown broken
  in the UI.
- **Transport classification** per artifact: `transported` (localBlob with
  bytes in the archive), `external` (ociArtifact, github, s3, ...),
  `broken` (declared localBlob, bytes missing), `none`, `unknown`.
  Versioned access spellings from the current CLI (`LocalBlob/v1`) classify
  like their base type. An image or Helm chart stored by value (what
  `ocm transfer --copy-resources` and `input: helm` write) is a localBlob
  whose bytes are an OCI manifest: it counts as `transported` only when
  every blob the manifest names is in the archive at the declared size,
  otherwise it is `broken` with `OCM_ARTIFACT_INCOMPLETE`.
- **CLI archive layout** (ocm CLI 0.13): a component version with stored
  artifacts is tagged as an OCI index around its descriptor manifest and
  the artifacts' manifests, and those manifests are listed untagged as
  well; signing leaves the previous descriptor untagged next to the new
  one. The walk reads tagged artifacts first, resolves an index to its
  descriptor manifest, never reads an image or chart manifest as a
  component version, and skips an untagged descriptor for a component
  version a tag already delivered.
- **Completeness**: resources only (sources are provenance, not deployment
  need). `airGapReady` additionally requires a complete in-bundle reference
  closure - an unresolved reference is a network dependency in disguise.
- **Blob statistics** over the content-addressed store: unique blobs,
  sharing, dedup savings.

A bare descriptor opens as a single-CV bundle (`bundleFromDescriptor`);
its localBlob accesses are honestly `broken` until the real delivery is
opened.

## The views (apps/ocm-lens)

- **Dashboard**: the delivery at a glance - CV/root counts, archive size and
  dedup, transported vs external vs broken, reference closure, signatures
  and SBOM coverage, findings. Every card jumps into the view that explains
  it.
- **Components**: the reference graph as navigation (roots first, diamonds
  badged, cycles broken visibly), with the CV detail in spec vocabulary and
  the verbatim descriptor source.
- **Resources**: every artifact of the bundle in one filterable table;
  artifact detail with access spec, digest verdict, content previews
  (helm/OCI/text/hex from the load-time inspection), SBOM download, and
  blob download-on-demand (`extractDeliveryBlob` re-reads the archive; the
  viewer never hoards blob bytes).
- **Verify**: digests aggregated (checked at load time, mismatches linked),
  signature verification against pinned keys (pref key shared with 1.x) or
  a pasted PEM key/certificate (chain NOT validated - the certificate is
  used only for its key), and the acceptance-report export.

## The acceptance report

`acceptanceReport` renders the delivery acceptance protocol as Markdown and
schema-stable JSON (`ocm-lens-acceptance-report/v1`): verdict with reasons,
component table, transport gaps, digest integrity, signature results, SBOM
coverage, findings. Deterministic by construction (timestamp and tool
version are injected), golden-tested. The verdict is one of three:
self-contained; needs network to deploy (external access, references
outside the bundle, unknown access types); or incomplete delivery (a
localBlob missing or cut short), which outranks the other two because no
network brings such a blob back. The JSON keeps `airGapReady` plus the
reasons, broken ones first.

## The demo delivery

`ecme-delivery.ctf.tar` (synthetic vendor "ECME Corp") exhibits every
verdict the product can give: three aggregation levels
(platform → observability → base), a diamond (base referenced twice), one
external `ociArtifact`, a deliberate digest mismatch (`obs-config`), two
embedded SPDX SBOMs - and `ecme.org/webstack`, signed with the **current
ocm CLI (v0.13.0, RSASSA-PSS, jsonNormalisation/v4alpha1)** against the
committed test keypair. Paste or pin `examples/ecme-public-key.pem` in the
Verify view and the signature turns green; the original July verification
engine handles the new toolchain's output unchanged. Fixture facts are
pinned by `bundle.demo.test.ts`; the generator guards the signed blobs'
bytes by hash.

## The VS Code extension (apps/vscode-ocm)

Since 2.0.0 the extension `everbright-it.ocmlens` bundles this app: `npm
run build:vscode -w @sbomlens/ocm-lens` builds the webview variant into
`apps/ocm-lens/dist-vscode`, and the extension's `compile` copies it into
`media/`. The shared shell (`packages/vscode-shell`) owns the custom
editor, folder open, workspace scan, registry fetch, and deep link; the
app talks to it through a small host layer (`apps/ocm-lens/src/host/`):

- **Files in:** the shell pushes small files as bytes (`ingestFiles`) and
  files over 32 MB as webview-resource URIs (`ingestUris`), which the app
  fetches into disk-backed Blobs. One file opens as itself; several
  descriptors become one bundle (`bundleFromDescriptors`); with archives
  among them, the first archive opens and the rest is named. A file the
  shell cannot hand over (the resource fetch fails) is reported by name and
  reason (`HOST_FILE_UNREADABLE`) instead of being parsed as an empty file.
- **Protocol:** the messages live in the shell
  (`packages/vscode-shell/src/protocol.ts`, subpath export
  `@sbomlens/vscode-shell/protocol`), shared by both Lens webviews; neither
  webview depends on the other's app package.
- **Worker:** the webview CSP allows `worker-src blob:` only, so the bundle
  worker is a single file (`inlineDynamicImports`) instantiated from a Blob.
- **Prefs:** the shell snapshots `ocmlens.*` keys from the extension's
  storage into the page and persists writes, so pinned keys carry over
  from the 1.x extension.
- **Saves:** webviews cannot download; reports, SBOMs, and artifact blobs
  go to the host as `exportBytes` and through VS Code's save dialog.

## Release procedure (2.x version line)

OCM Lens 2.x versions independently: `apps/ocm-lens/package.json` and
`apps/vscode-ocm/package.json` carry the same 2.x number (the UI reads it
from package.json; `apps/ocm-lens/src/version.test.ts` enforces the 2.x
line and the match) while the monorepo stays on its 0.x lockstep. The
lockstep command `npm version <v> --workspaces` bumps every workspace,
these included; the same test fails the suite when that happens and names
the one-line fix.

To release: bump both package.json files plus `apps/ocm-lens/CHANGELOG.md`
(then `npm install --package-lock-only`), and tag `ocm-lens-v<version>`.
That tag namespace runs `vsix-ocm` (packaged with `--pre-release` while
2.x is in beta), the manual publish jobs for Open VSX and the Marketplace
(both `--pre-release`; `vsce` refuses a package that was not packed as
one), and the release jobs. The mirrored tag also runs `release-ocm` in
the GitHub release workflow, which marks the GitHub release as a
pre-release. The plain `v*` tags no longer build or publish OCM Lens. When
2.x goes stable, switch `vsix-ocm` and `release-ocm` to `npm run package`,
drop `--pre-release` from the publish jobs, and replace `--prerelease`
with `--latest=false` on GitHub; the stable version must be higher than
the last pre-release.

## Size behavior (air-gap scale)

- **Plain `.tar`/`.ctf` has no size limit.** The walk reads 512-byte
  headers and skips blob data by offset; memory stays constant regardless
  of archive size. Entries larger than **8 GiB** are supported in both
  spellings real tools write (GNU base-256 and Go's PAX `size` records;
  the ocm CLI is Go).
- **Digest checking is budgeted.** The one full-byte read the walk performs
  (hashing declared localBlobs for their verdict) stops at **256 MB** per
  open; beyond it, verdicts open as `pending` and the dashboard says so.
  "Check now" in the Verify view (or per artifact in the drawer) runs the
  deferred checks with progress: same semantics, just when you ask.
  Reports state deferred checks explicitly instead of implying a verdict.
- **`.tgz` is capped at 2 GiB decompressed** (`DecompressionStream` has no
  random access); the app answers with a repack hint. Air-gap bundles
  should be plain tar anyway.
- Dev/QA hook: `?open=<same-origin path>` loads a delivery on start;
  `&budget=<bytes>` and `&mat=<bytes>` override the eager-hash budget and
  the materialization cap (e.g. `?open=examples/ecme-delivery.ctf.tar&budget=0`).
  Large local QA deliveries go in `apps/ocm-lens/qa/` (gitignored, outside
  `public/`): the dev server serves them at `?open=qa/<file>`, and no build
  ever copies them.

## Limits (deliberate, v2.0)

- Read-only; no signing, no registry writes. Registry browsing returns with
  the extension move (stage H).
- Signature verification: RSASSA-PSS and PKCS#1 v1.5 over
  `jsonNormalisation/v2|v3|v4alpha1`; certificate chains and trust policies
  are not validated (key pinning is the honest alternative).
- Deep SBOM analysis stays in SBOM Lens; OCM Lens lists, extracts, and
  hands off.
- Stored images are checked for completeness (every layer present, at the
  declared size), not hashed layer by layer: the resource digest covers
  the manifest, which pins each layer by digest, and a registry verifies
  layer digests when the delivery is imported.
- Archive limits are inherited from the shared walker (see
  [docs/ocm.md](ocm.md)): entry caps, preview caps.
- One delivery at a time; delivery-to-delivery diff is on the 2.x roadmap.
