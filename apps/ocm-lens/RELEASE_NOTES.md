# OCM Lens 2.0 - release notes (draft)

> Draft for the v2.0.0 announcement. Sources: this file + CHANGELOG.md.
> Audiences and where each block goes: GitLab/GitHub release description
> (all of it), Open VSX / Marketplace CHANGES tab (from the CHANGELOG),
> landing page news blurb (the first two sections).
> Status: 2.0.0 on the VS Code pre-release channel; the hosted web app is
> still 1.x.

## What this is

OCM Lens 2.0 is a ground-up rebuild: a delivery explorer that models the
[Open Component Model](https://ocm.software) in its own vocabulary instead
of mapping it onto an SPDX document viewer. Open a CTF, a component
archive, or a bare component descriptor and get the delivery as one
picture:

- **Dashboard** - what is this bundle: component versions and roots,
  archive size and dedup, transported vs external vs broken resources,
  reference closure, signatures, SBOM coverage, findings.
- **Components** - how it aggregates: the reference graph as navigation,
  roots first, diamonds marked, cycles shown but never followed, unlimited
  depth, with the component detail in spec vocabulary.
- **Resources** - what actually ships: every artifact in one filterable
  table, with access spec, digest verdict, content previews (helm, OCI,
  text), SBOM download, and blob download-on-demand.
- **Verify** - does it hold: blob digests aggregated, signature
  verification against pinned or pasted keys, and an exportable
  **delivery acceptance report** (Markdown + JSON,
  `ocm-lens-acceptance-report/v1`).

Everything runs client-side, in your browser or in VS Code. Files never
leave your machine.

**In VS Code**, 2.0.0 is on the pre-release channel of
`everbright-it.ocmlens`: open the extension page and choose *Switch to
Pre-Release Version*. Descriptors and `.ctf` archives open in the custom
editor, folders and workspace scans merge their descriptors into one
bundle, and *Open component version from registry* pulls a component
straight from an OCI registry.

## Highlights

- **Air-gap honesty.** The verdict "self-contained - air-gap ready"
  requires every resource transported AND a complete in-bundle reference
  closure - an unresolved reference is a network dependency in disguise.
  Transport gaps are listed by name in the acceptance report.
- **Built for transfer-medium sizes.** Plain `.tar`/`.ctf` has no size
  limit: opening reads headers and descriptors only (constant memory),
  entries over 8 GiB parse (GNU base-256 and Go/ocm-CLI PAX records), and
  digest hashing beyond a 256 MB budget defers to an explicit "Check now"
  run with progress instead of blocking the open. Deferred checks are
  stated in the report rather than implied as verdicts.
- **Verified against the current toolchain.** The bundled demo delivery
  contains a component signed with ocm CLI v0.13.0 (RSASSA-PSS,
  jsonNormalisation/v4alpha1). Pin the demo public key and watch it turn
  green - the verification engine is proven byte-exact against real CLI
  output, old toolchain and new.

## Breaking changes

2.0 replaces the 1.x OCM Lens UI entirely. If you used 1.x:

- The SPDX-shaped views are gone: **Inventory, Conflicts, Licenses, Map,
  and Diff** do not exist in 2.0 V1. Their OCM-native successors are on
  the 2.x roadmap (delivery-to-delivery diff first).
- **VEX/CSAF overlay, compliance profiles, the quality report, spec info
  tooltips, and Open-from-URL (with tokens)** are not part of 2.0 V1.
- **One delivery at a time** replaces the multi-document workspace.
- **Embedded SBOMs are listed and extractable, not deep-analyzed** - open
  the downloaded SBOM in SBOM Lens for cascades, licenses, VEX.
- **VS Code: comparing two registry versions** is gone until the 2.x
  delivery diff; **workspace compliance profiles** (`.ocmlens/profile.json`)
  are no longer read.

What does NOT break:

- **Pinned signature keys carry over automatically** (same pref key).
- **VS Code users are not moved to 2.0 without asking.** On the VS Code
  Marketplace the release channel stays on 1.x (0.29.6) until 2.x goes
  stable; only users who switch to the pre-release get 2.0. Open VSX lists
  2.0.0 as its newest version, and not every client honors the pre-release
  flag there, so some Open VSX editors may install 2.0 directly.
- The 1.x flavor remains buildable from the monorepo until the switch is
  complete.

## Versioning

OCM Lens now versions independently as 2.x (this changelog lives in
`apps/ocm-lens/`). The 0.x history remains in the monorepo CHANGELOG.
The VS Code Marketplace accepts only plain `major.minor.patch` versions,
so the beta lives in the pre-release channel rather than in the version
string: 2.0.0 is a pre-release, and the first stable 2.x will carry the
next number. 2.x releases are tagged `ocm-lens-v<version>` in the
monorepo.
