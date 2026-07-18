# Delivery acceptance: did we receive what the SBOM describes?

> **A verifier, not a guess.** An SBOM lists files with checksums. Delivery
> acceptance recomputes the digests of the files you were actually delivered
> and compares them, path by path, to the SBOM — so a tampered, corrupt,
> missing, or unexpected file shows up before you trust the delivery. It is
> the SPDX-side counterpart to the digest check OCM Lens runs on delivery
> blobs.

Load an SPDX SBOM that describes **files** with checksums (SPDX `FileName` +
`FileChecksum`). Then *Open → Check delivery…* and pick the delivered files
or folder. Everything is hashed **locally, in a worker** — the delivered
bytes never leave your machine and never reach the UI thread; only the
digests do.

> **Try it in one click:** *Open → ACME web delivery — acceptance check* in
> the demo catalog loads a file-level SBOM and a bundled delivery that
> exercises all four verdicts (one match, one tampered, one missing, one
> extra).

## Verdicts

Per file, matched by relative path:

- **match** (emerald) — the delivered bytes hash to the checksum the SBOM
  declares.
- **mismatch** (red) — a file is present but its digest differs: tampered or
  corrupt. The detail pane shows declared vs. actual.
- **missing** (amber) — the SBOM describes the file, but it was not
  delivered.
- **unverifiable** (slate) — the SBOM file has no checksum, or none in an
  algorithm the check could recompute (see limits).

Delivered files the SBOM never mentions are listed as **extra** — the
counterpart to *missing*, and often the more interesting one (a stray
credential, a leftover build artifact).

The per-file verdict appears on each file element; the document detail pane
carries the workspace-level report with the counts and the full lists of
mismatches, missing, and extras.

## How paths are matched

SBOM file names are relative and usually carry a leading `./`; the check
strips that. When you pick a **folder**, the browser prefixes every path
with the chosen folder's name — that single shared root segment is stripped
so the paths line up with the SBOM. Files whose paths do not line up show as
*missing* (SBOM side) and *extra* (delivery side) rather than silently
matching.

## Limits (deliberate)

- **Digests are recomputed with SHA-1, SHA-256, SHA-384, SHA-512.** A file
  whose only SBOM checksum is MD5 or a SHA-3 variant reads *unverifiable*
  rather than risking a wrong verdict. Only the algorithms the SBOM actually
  declares are computed.
- **Path-based matching.** A file delivered under a different name than the
  SBOM records shows as *missing* + *extra*, not as a rename.
- **The report is a snapshot** of one check. It does not recompute when the
  SBOM set changes (the delivered bytes are already gone); clear it or run
  the check again.
- Like every overlay, it lives outside the document model: SBOM exports are
  unaffected, and clearing the report removes every trace.
