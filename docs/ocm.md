# OCM deliveries (Software Bill of Delivery)

> **This is OCM Lens.** Component descriptors and delivery archives belong to
> the OCM flavor of this codebase: SBOM Lens is an SPDX viewer and ships
> none of this code (`@sbomlens/core/ocm` + `HAS_DELIVERIES`, proven by a CI
> gate). Build it with `npm run build:ocm`, or install the *OCM Lens*
> extension.
>
> **Read-only.** Deliveries are displayed, never modified. Blob digests of
> artifacts inside a loaded delivery are checked against the actual bytes,
> and signatures can be verified against a public key you paste in
> (client-side, no upload). Signing is out of scope.

OCM Lens opens [OCM](https://ocm.software) component descriptors and local
delivery archives and shows the whole delivery as one navigable tree: the
component hierarchy becomes the tree/map, and SBOMs contained in the delivery
are loaded as normal SPDX documents, linked automatically.

## What you can open

| Input | How |
| --- | --- |
| Component descriptor (`component-descriptor.yaml` / `.json`, schema v2; v3alpha1 best-effort) | drop / picker / URL: content-detected like every other format |
| CTF archive (`.tar` / `.tgz` / `.ctf`) | drop / picker; both artifact layouts are supported (flat OCI manifest and nested artifact-set) |
| Component archive (tar with `component-descriptor.yaml` + `blobs/`) | drop / picker |
| Plain tar of SPDX files | works too: every SPDX member is loaded |

In the VS Code extension, component versions can also be pulled straight
from an OCI registry (next section). The browser build stays local-only:
registries do not answer cross-origin requests.

## Fetching from a registry (VS Code extension)

The OCM Lens extension pulls component versions straight from an OCI
registry: the extension host fetches (no CORS), packs the version's OCI
manifest and layers into an in-memory CTF, and the normal delivery pipeline
does the rest, so descriptor mapping, SBOM extraction, digest verdicts, and
signature verification work exactly as for a local file.

- **Command**: *OCM Lens: Open component version from registry...* asks for
  the registry (e.g. `ghcr.io/open-component-model/ocm`), the component name
  (e.g. `ocm.software/ocmcli`), and the version, picked from the registry's
  tags. Registries you use often go into the `ocmlens.registries` setting.
- **Unresolved references**: when a loaded descriptor references a component
  version that is not part of the delivery, the reference's detail pane
  offers *Fetch from registry*, prefilled from the descriptor's repository
  contexts. The fetched version links up like any loaded descriptor.
- **Credentials**: public registries work anonymously (standard bearer-token
  flow). For private ones, run *OCM Lens: Set registry credential...* and
  store a `user:token` value for the host; it is kept in VS Code secret
  storage and sent only to that registry's token endpoint.
- **Caps**: layers over **50 MB** (or past a **256 MB** total per fetch) are
  not downloaded; their resources show without content, and OCM Lens says how
  many were skipped. The component descriptor itself is always fetched.
- **Version mapping**: OCI tags cannot contain `+`, so build metadata appears
  as `.build-` in tags (`1.0.0+7` ⇄ `1.0.0.build-7`); OCM Lens maps both ways
  automatically.

Handy recipe the other way around: `ocm transfer componentversion
ghcr.io/acme/ocm//acme.org/app:1.0.0 ./delivery.ctf` writes a transport
archive you can drop into OCM Lens (web or extension). External tools can
also deep-link the extension:
`vscode://everbright-it.ocmlens/open?path=/absolute/path/to/delivery.ctf`
(VS Code asks before the link reaches the extension).

## How OCM maps onto the viewer

- A component version becomes a document with the synthetic namespace
  `ocm://<name>/<version>` and one root package (the component itself).
- `resources` and `sources` become packages: the resource type shows up as
  the package purpose (`ociImage`, `helmChart`, `sbom`, ...), digests appear as
  checksums, `ociArtifact` image references become download locations and
  best-effort `pkg:oci` purls.
- `componentReferences` become external document references pointing at the
  referenced component's `ocm://` namespace: load both descriptors (or one
  CTF containing them) and they link up exactly like SPDX cascades.
- SBOM resources stored as local blobs are extracted from the archive and
  ingested in the same batch; the descriptor's reference carries the blob's
  byte SHA-1, so the checksum resolver connects them immediately. The SBOM's
  packages appear underneath the resource in the tree (`DESCRIBED_BY`).

## Artifact content: what the delivery physically ships

Every local blob a delivery carries is inspected inside the parse worker,
and its resource shows an **Artifact content** section:

- **Kind and preview**: helm charts show their file list plus `Chart.yaml`
  and `values.yaml`; OCI artifact sets show the manifest and a layer table;
  JSON/YAML/text blobs show their content (exportable); anything binary
  shows a hex head. Previews are capped (64 KB text, 500 files); the raw
  bytes never leave the worker.
- **Digest check**: when the resource declares a digest with
  `genericBlobDigest/v1` (hash of the stored blob bytes) or
  `ociArtifactDigest/v1` (hash of the artifact set's manifest), OCM Lens
  recomputes it and shows *digest match* or *digest mismatch*; a mismatch
  additionally raises an `OCM_DIGEST_MISMATCH` warning. Any other
  normalisation stays *unchecked*: the check never guesses, so it can never
  produce a wrong verdict. Resources that are only referenced
  (`ociArtifact` and friends) carry no blob and no check.

## Structural lint

Beyond loading tolerantly, OCM Lens lints every descriptor against the spec's
structural rules and reports findings as warnings (`OCM_SCHEMA_*`) in the
diagnostics drawer: missing provider, component names outside the spec
pattern, non-semver versions, relations other than local/external, access
nodes without a type, incomplete digest triples, duplicate artifact
identities (name + extraIdentity + version), nameless labels, and unparseable
timestamps. The document always loads; the lint tells you what a stricter
consumer would trip over.

## Signature verification

A signed component descriptor carries `signatures[]`; each is a digest over a
canonical form of the descriptor plus an RSA signature over that digest. In
the **Signatures** section, paste a public key (PEM) or a certificate and OCM
Lens verifies it entirely in your browser via `crypto.subtle`: no server, no
upload.

- **Normalisation**: `jsonNormalisation/v4alpha1` (the current `ocm` CLI
  default), `/v3`, and `/v2`. OCM Lens recomputes the normalised digest and
  reports whether it matches the one the signature records.
- **Signature**: RSASSA-PSS (`application/vnd.ocm.signature.rsa.pss`) and
  RSASSA-PKCS1-v1_5 (`application/vnd.ocm.signature.rsa`), SHA-256/512. The
  PSS check accepts both the maximum-salt convention the CLI uses and the
  hash-length convention, so signatures from either signer verify.
- **Verdicts**: *valid*, *invalid* (with "signature does not verify" vs.
  "descriptor does not match the signed digest"), or *unverifiable* with a
  reason (an unknown normalisation or algorithm, a key that will not import,
  or a descriptor that cannot be canonicalised). It never guesses a verdict.

Verified end to end against the real `ocm` CLI (v0.9.0): our normalisation
reproduces the CLI's recorded digest byte-for-byte.

**Out of scope**: signing; certificate-chain and trust-policy validation (a
certificate is used only for its public key, stated in the dialog);
timestamping; and `jsonNormalisation/v1` (deprecated), which stays
*unverifiable*.

## Limits (deliberate)

- **Read-only**: no signing, no registry writes. Registry access (VS Code
  extension) is pull-only. Blob digests inside a loaded delivery are checked
  against the actual bytes, and signatures are verifiable against a public
  key you supply (above). Component/reference digests without a signature are
  displayed as recorded.
- **Sizes.** Plain `.tar`/`.ctf` deliveries stream from disk: a multi-GB
  release bundle opens without ever being held in memory. Blobs over
  **64 MB** (or past a **512 MB** total budget) are indexed instead of
  loaded: no content preview, but their `genericBlobDigest/v1` sha256
  verdict is still real, hashed incrementally off the archive. Compressed
  `.tgz` deliveries must fit in memory and are capped at **2 GiB**
  decompressed (decompression is where a zip bomb would detonate); past
  that, repack as plain `.tar`. Archives are capped at **10,000 entries**;
  ZIP is rejected with a repack hint, and links inside tars are never
  followed. Artifact-content previews are capped at **64 KB of text**,
  **500 files** listed, and a **256-byte** hex head for binaries; the raw
  blob bytes are inspected in the worker and then dropped. Registry fetches
  cap layers at **50 MB** and **256 MB** per component version (skipped
  layers are reported). The VS Code extension buffers locally opened
  deliveries in memory for now (a chunked webview bridge is on the roadmap);
  its workspace scan skips files over **50 MB**.
- **Verification needs a secure context**: `crypto.subtle` drives both the
  cascade checksums and signature verification, so HTTPS or localhost is
  required (plain HTTP on a remote host disables them).
- Component descriptors: schema v2 fully, v3alpha1 best-effort. Unknown access
  types (`s3`, `npm`, ...) are listed without download location and reported
  as diagnostics.
- CycloneDX SBOMs inside a delivery are reported, not loaded (same conversion
  hint as standalone files).

Fixtures for all of this are generated deterministically
(`npm run generate:ocm-fixtures -w @sbomlens/core`) and pinned byte-for-byte
by tests. Real `ocm` CLI output can be smoke-tested by dropping any CTF -
if a layout variant misbehaves, the archive falls back to a content sweep
and reports diagnostics instead of failing.
