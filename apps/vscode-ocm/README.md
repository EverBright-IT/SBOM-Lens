# OCM Lens for VS Code

[![Open VSX Version](https://img.shields.io/open-vsx/v/everbright-it/ocmlens?label=Open%20VSX)](https://open-vsx.org/extension/everbright-it/ocmlens)

> **OCM Lens 2.0 is on the pre-release channel.** In the Extensions view,
> open OCM Lens and choose **Switch to Pre-Release Version**. Editors that
> support pre-releases keep the release channel on OCM Lens 1.x until 2.x
> goes stable.

Understand an [Open Component Model](https://ocm.software/) delivery right
in your editor. Open a CTF, a component archive, or a component descriptor
and see what the delivery is: which component versions it aggregates, what
actually ships, whether it can be deployed without network access, and
whether digests and signatures hold.

![OCM Lens 2.0: the delivery dashboard with component versions, transport status, reference closure, signatures, and embedded SBOMs](https://gitlab.com/everbrightit-group/sbom-lens/-/raw/main/docs/ocm-lens-2-hero.png)

## Opening deliveries

- **Open with OCM Lens**: open a `component-descriptor.yaml`/`.json` or a
  `.ctf` archive (it opens in OCM Lens by default), or right-click a
  `.tar` / `.tgz` delivery in the explorer.
- **Open folder with OCM Lens** and **OCM Lens: Scan workspace for component
  descriptors**: several descriptors become one delivery, with references
  resolved across the files.
- **OCM Lens: Open component version from registry...**: pull a component
  version straight from an OCI registry (for example
  `ghcr.io/open-component-model/ocm`) into the same views. Private
  registries: store a `user:token` per host via *OCM Lens: Set registry
  credential*.
- **Deep link** for other tools:
  `vscode://everbright-it.ocmlens/open?path=/absolute/path/delivery.ctf`.

## What you get

- **Dashboard.** The delivery at a glance: component versions and roots,
  archive size, transported vs external vs broken resources, reference
  closure, signatures, embedded SBOMs, and an honest verdict:
  *self-contained*, *needs network to deploy*, or *incomplete* when stored
  content is missing or cut short, with the reasons.
- **Components.** The reference graph as navigation: roots first, any
  depth, components referenced twice marked as shared, cycles shown but
  never followed. Each component version in the spec's own vocabulary,
  with its verbatim descriptor.
- **Resources.** Every artifact of the delivery in one filterable table:
  access type, transport status, digest verdict, and content previews
  (Helm charts, OCI artifact sets, text). Download any transported blob or
  embedded SBOM through VS Code's save dialog.
- **SBOMs.** Every embedded SBOM tied to the artifact it describes (by
  digest, by reference, by component), every image or binary without one
  named, and a fact sheet per SBOM: format, generator, packages, field
  coverage, NTIA minimum elements and BSI TR-03183 checks.
- **Packages.** Every package the SBOMs list, with the image or binary it
  ships in. Ask whether a package is in the delivery by name, purl or CPE,
  and the answer also names what could not be searched (an image without
  an SBOM, say). License identifiers counted, versions that differ between
  artifacts, export as CSV or JSON.
- **Vulnerabilities.** What the supplier states about known
  vulnerabilities in the shipped packages, from OpenVEX and CSAF 2.0
  documents in the delivery or added by you, read offline: status per
  package and image, the supplier's action or justification, and the
  statements that name nothing in the package list. OCM Lens does not scan;
  a package without a statement is not cleared.
- **Verify.** Declared blob digests are recomputed from the delivered
  bytes; signatures (RSASSA-PSS and PKCS1-v1_5 over
  `jsonNormalisation/v4alpha1`, v3, v2) verify against a pinned or pasted
  public key, byte-exact with the real `ocm` CLI. Export a **delivery
  acceptance report** as Markdown or JSON.
- **Built for transfer-medium sizes.** Large deliveries stream from disk;
  entries over 8 GiB parse; digest checks beyond 256 MB run on demand
  instead of blocking the open.
- **Private by design.** Everything is parsed locally inside the editor.
  Nothing is uploaded anywhere.

> Working with **SPDX** documents? That is
> [SBOM Lens](https://open-vsx.org/extension/everbright-it/sbomlens), the
> sibling extension: cascades, licenses, VEX, compliance profiles.

## Coming from 1.x

2.0 is a rebuild around the OCM model, and V1 deliberately leaves some 1.x
features out: the Inventory, Conflicts, Licenses, Map, and Diff views,
comparing two registry versions, the VEX/CSAF overlay, compliance profiles
(`.ocmlens/profile.json`), and spec info tooltips. 2.1 brought SBOM
evidence, 2.2 the Packages view, which takes over from Inventory,
Conflicts and Licenses for a delivery, and 2.3 the VEX/CSAF overlay; the
delivery diff comes next. One delivery is open at a time. Keys you pinned
in 1.x carry over. The full list is in the
[changelog](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/ocm-lens/CHANGELOG.md).

## Limits

- **Read-only.** No signing, no registry writes; registry access is
  pull-only and skips layers over 50 MB (256 MB per component version).
- **Signatures:** certificate chains, trust policies, timestamping, and the
  deprecated `jsonNormalisation/v1` are out of scope and reported as
  unverifiable rather than guessed. A certificate is used only for its key.
- **Archives:** up to 10,000 entries; compressed `.tgz` up to 2 GiB
  decompressed (repack larger ones as plain `.tar`); links inside tars are
  never followed. Content previews are capped (64 KB of text, 500 files).

## Install

- **Open VSX** (VSCodium, Cursor, Gitpod, Theia):
  [`everbright-it.ocmlens`](https://open-vsx.org/extension/everbright-it/ocmlens).
- **VS Code Marketplace**:
  [`everbright-it.ocmlens`](https://marketplace.visualstudio.com/items?itemName=everbright-it.ocmlens).

Then switch to the pre-release version to get 2.0.

## Links

- [OCM Lens home](https://gitlab.com/everbrightit-group/ocm-lens):
  what the product is, where to get it
- [Source](https://gitlab.com/everbrightit-group/sbom-lens) (one monorepo
  for both Lens products), or the
  [GitHub mirror](https://github.com/EverBright-IT/SBOM-Lens)
- [Report a bug](https://github.com/EverBright-IT/OCM-Lens/issues)
- [Changelog (2.x)](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/ocm-lens/CHANGELOG.md)
- [Design notes](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/docs/ocm-lens-2.md):
  the model, the views, size behavior, limits
- Building, testing, publishing this extension:
  [DEVELOPMENT.md](https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/apps/vscode/DEVELOPMENT.md)

Apache-2.0 © [EverBright IT GmbH](https://everbright-it.de). We help teams
with CRA/SBOM readiness and secure AI adoption.
