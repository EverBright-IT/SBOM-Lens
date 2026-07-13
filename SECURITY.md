# Security Policy

SBOM Lens is a client-only viewer: documents are parsed locally in the
browser (or the VS Code webview) and never uploaded. Even so, a viewer for
untrusted supply-chain documents is security-relevant software — we treat
parser robustness, archive handling, and the deployment story as part of the
attack surface and want to hear about anything you find.

## Reporting a vulnerability

Please email **tech@everbright-it.de** with:

- a description of the issue and its impact,
- reproduction steps or a proof-of-concept file (crafted SBOMs/archives are
  welcome as attachments),
- the version (`git tag` / vsix version) you tested.

Please **do not** open a public issue for security reports. You will get an
acknowledgement within **3 business days** and our assessment within **14
days**. We will credit you in the release notes unless you prefer otherwise.

## Scope

In scope:

- Parsing of SPDX documents (tag-value/JSON/YAML), compliance profiles, and
  OCM deliveries (tar/gzip handling, zip-bomb and path-traversal resistance —
  archive entry names are never used as filesystem paths and links are never
  followed).
- The web app and its PWA/service-worker behavior, the deployment catalog
  (`sbomlens.catalog.json`) and its URL restrictions, token handling
  (sessionStorage / VS Code secret storage).
- The VS Code extension: webview CSP, the extension-host bridge
  (fetch/secrets/prefs/export), and the vsix build.
- The published container image and the CI supply chain of this repository.

Out of scope:

- Vulnerabilities in third-party SBOM *generators*.
- Issues that require a compromised host or browser.
- The content of SBOMs themselves (we display them; we do not vouch for them
  — OCM digests are explicitly displayed, not verified).

## Supported versions

The latest tagged release receives fixes. There are no long-term support
branches during 0.x.

## Our own supply chain

Every push runs an osv-scanner gate, SAST, and secret detection; releases add
a Trivy image scan and ship their own SPDX SBOM (`sbomlens-<tag>.spdx.json`).
Details: [docs/ci-security.md](docs/ci-security.md).
