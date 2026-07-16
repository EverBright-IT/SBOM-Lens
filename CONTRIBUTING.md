# Contributing to SBOM Lens

Thanks for helping! The bar for this codebase is *minimal and deliberate*: every
dependency, feature, and abstraction has to earn its place.

## Setup

```sh
npm ci
npm run dev
```

Before opening a merge request:

```sh
npm run lint && npm run typecheck && npm test && npm run build
```

## Ground rules

- **`packages/core/` stays framework-free.** No React, no state libraries, no
  DOM globals: ESLint enforces this. Core logic must be testable in plain
  Vitest without a browser. The web app talks to its host environment only
  through the adapter in `apps/web/src/host/` (ESLint blocks direct
  localStorage/sessionStorage elsewhere).
- **Parsers never throw on bad input.** Real-world SBOMs are dirty; anomalies
  become diagnostics (`{severity, code, message, line?}`) and parsing continues.
  If you find a document that breaks this rule, that document is a test fixture
  waiting to happen.
- **Fixtures are synthetic.** Never commit real customer/internal SBOMs. Distill
  the quirk into an invented fixture under `packages/core/fixtures/` and cover
  it with a test. You can validate against private data locally with
  `SBOM_CORPUS_DIR=... npm run check-corpus`.
- **Fixture and example bytes are load-bearing.** Cascade resolution matches
  SHA-1 checksums, so formatters must not touch `packages/core/fixtures/` or
  `apps/web/public/examples/` (see `.prettierignore` / `.gitattributes`).
  Regenerate the examples with `npm run generate:examples`; the binary OCM
  fixtures come from `npm run generate:ocm-fixtures -w @sbomlens/core` and are
  pinned byte-for-byte by tests.
- **Keep the UI lean.** System fonts, slate + one accent color, no component
  libraries. Large lists must be virtualized.

## Commit style

Conventional-ish: `feat(core): ...`, `fix(ui): ...`, `docs: ...`. Keep subjects under
~70 characters; explain the *why* in the body when it isn't obvious.
