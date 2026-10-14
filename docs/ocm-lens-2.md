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
  like their base type.
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
version are injected), golden-tested.

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

## Release procedure (2.x version line)

OCM Lens 2.0 versions independently: `apps/ocm-lens/package.json` and
`src/version.ts` carry 2.x while the monorepo stays on its 0.x lockstep.
The lockstep command `npm version <v> --workspaces` bumps every
workspace, this one included; `apps/ocm-lens/src/version.test.ts` fails
the test suite when that happens and names the one-line fix. Bump
`apps/ocm-lens` explicitly (package.json + `src/version.ts` + its
CHANGELOG) when OCM Lens itself releases.

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
- Archive limits are inherited from the shared walker (see
  [docs/ocm.md](ocm.md)): entry caps, preview caps.
- One delivery at a time; delivery-to-delivery diff is on the 2.x roadmap.
