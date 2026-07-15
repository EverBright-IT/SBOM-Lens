# OCM deliveries (Software Bill of Delivery)

> **Read-only.** Deliveries are displayed, never modified. Signatures and
> digests are shown as recorded; cryptographic verification is on the
> roadmap (`OCM_DIGESTS_NOT_VERIFIED` keeps that honest until then). OCM
> support is also the engine of **OCM Lens**, the delivery-first product
> flavor built from this repository.

SBOM Lens opens [OCM](https://ocm.software) component descriptors and local
delivery archives and shows the whole delivery as its usual cascade — the
component hierarchy becomes the tree/map, and SBOMs contained in the delivery
are loaded as normal SPDX documents, linked automatically.

## What you can open

| Input | How |
| --- | --- |
| Component descriptor (`component-descriptor.yaml` / `.json`, schema v2; v3alpha1 best-effort) | drop / picker / URL — content-detected like every other format |
| CTF archive (`.tar` / `.tgz` / `.ctf`) | drop / picker; both artifact layouts are supported (flat OCI manifest and nested artifact-set) |
| Component archive (tar with `component-descriptor.yaml` + `blobs/`) | drop / picker |
| Plain tar of SPDX files | works too — every SPDX member is loaded |

Remote OCI-registry access is out of scope for now (roadmap: via the VS Code
extension host, which fetches without CORS limits).

## How OCM maps onto the viewer

- A component version becomes a document with the synthetic namespace
  `ocm://<name>/<version>` and one root package (the component itself).
- `resources` and `sources` become packages: the resource type shows up as
  the package purpose (`ociImage`, `helmChart`, `sbom`, …), digests appear as
  checksums, `ociArtifact` image references become download locations and
  best-effort `pkg:oci` purls.
- `componentReferences` become external document references pointing at the
  referenced component's `ocm://` namespace — load both descriptors (or one
  CTF containing them) and they link up exactly like SPDX cascades.
- SBOM resources stored as local blobs are extracted from the archive and
  ingested in the same batch; the descriptor's reference carries the blob's
  byte SHA-1, so the checksum resolver connects them immediately. The SBOM's
  packages appear underneath the resource in the tree (`DESCRIBED_BY`).

## Limits (deliberate)

- **Read-only**: no signing, no verification — OCM digests are displayed,
  never checked (`OCM_DIGESTS_NOT_VERIFIED` reminds you).
- Unknown access types (`s3`, `npm`, …) are listed without download location
  and reported as diagnostics.
- ZIP is rejected with a repack hint; archives are capped at 10k entries /
  512 MB expanded (zip-bomb guard). Links inside tars are never followed.
- CycloneDX SBOMs inside a delivery are reported, not loaded (same conversion
  hint as standalone files).

Fixtures for all of this are generated deterministically
(`npm run generate:ocm-fixtures -w @sbomlens/core`) and pinned byte-for-byte
by tests. Real `ocm` CLI output can be smoke-tested by dropping any CTF —
if a layout variant misbehaves, the archive falls back to a content sweep
and reports diagnostics instead of failing.
