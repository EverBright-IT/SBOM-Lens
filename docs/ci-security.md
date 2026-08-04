# CI security & supply-chain hygiene

What runs, when, and what it blocks. GitLab (`.gitlab-ci.yml`) is the primary
pipeline; the GitHub workflow mirrors the quality gates and the osv scan.

| Job | Pipeline | When | Blocking | What it does |
| --- | --- | --- | --- | --- |
| `test` | GitLab + GitHub | every push/MR | yes | lint, typecheck, unit tests |
| `osv-scan` | GitLab + GitHub | every push/MR | yes | known CVEs in `package-lock.json` via [osv-scanner](https://google.github.io/osv-scanner/) |
| `semgrep-sast` | GitLab (template) | every push/MR | findings reported as artifacts | static analysis of the TS/JS sources |
| `secret_detection` | GitLab (template) | every push/MR | findings reported as artifacts | committed-credential scan |
| `renovate` | GitLab | **scheduled pipeline only** | - | opens dependency-update MRs |
| `image-scan` | GitLab | tags | yes | Trivy scan of the released container image (HIGH/CRITICAL, fixable) |
| `self-sbom` | GitLab | tags | no | syft generates `sbomlens-<tag>.spdx.json`: every release ships its own SBOM (open it in SBOM Lens) |

Build outputs, fixtures, and bundled examples are excluded from SAST via
`SAST_EXCLUDED_PATHS`: the fixtures deliberately contain odd-looking data.

## Renovate setup (one-time, GitLab UI)

Renovate runs inside this project as a scheduled pipeline; nothing runs until
both steps below are done.

1. **Bot token**: create a project (or group) access token with the `api` and
   `write_repository` scopes and the Developer role. Store it under
   *Settings → CI/CD → Variables* as `RENOVATE_TOKEN` (masked; protected only
   if the schedule runs on a protected branch).
2. **Schedule**: *Build → Pipeline schedules → New*: cron e.g.
   `0 6 * * 1` (Mondays 06:00), target branch `main`, and add the variable
   `RENOVATE_RUN = true`. That variable is what routes the pipeline to the
   `renovate` job: every other job skips itself when it is set.

Renovate behavior lives in [`renovate.json`](../renovate.json): non-major
devDependency bumps are grouped into one MR, runtime dependencies get
individual MRs, lockfile maintenance runs monthly.

**GitHub mirror:** Dependabot stays off on purpose. The mirror is read-only -
update PRs must originate on the internal GitLab so history never diverges.

## Suppressing findings

- **osv-scanner**: add an `osv-scanner.toml` at the repo root with
  `[[IgnoredVulns]]` entries (`id`, `reason`, ideally an expiry note). Keep
  every ignore reviewed: the file is diffed like code.
- **Trivy**: add a `.trivyignore` file (one CVE id per line, with a comment
  why). `--ignore-unfixed` is already set, so only fixable findings block.
- **SAST/Secret Detection**: prefer fixing; for true false positives use the
  vendored `// nosemgrep` comment with a justification.

## Forcing a transitive fix (`overrides`)

Sometimes the fix for an advisory sits behind a range a dependency cannot
reach: the vulnerable package is four levels down and its parent declares
`^2.0.1` while the fix lands in 5.0.8. Bumping the direct dependency does not
help, and ignoring the finding leaves the vulnerable code in the tree. For
those cases the root `package.json` carries an `overrides` entry.

`overrides` is a blunt instrument. It applies to every transitive occurrence,
silently, forever, and nothing warns when it goes stale — so each entry needs a
reason and an exit condition:

| Override | Why | When it can go |
|---|---|---|
| `fast-uri: ^3.1.4` | GHSA-v2hh-gcrm-f6hx (7.5); the declared ranges (`^3.0.1`) allowed the fix but npm would not re-resolve on its own | once every consumer (ajv, via vite-plugin-pwa and @vscode/vsce) requires 3.1.4 or newer on its own |
| `brace-expansion: ^5.0.8` | GHSA-mh99-v99m-4gvg (7.5); the fix is a major version and the deep `minimatch@5` chain declares `^2.0.1` | once the chain (vite-plugin-pwa → workbox-build → … → minimatch) ships a minimatch that depends on 5.x |

Two practical notes, both learned the hard way:

- **Adding the entry is not enough.** `npm install` keeps an already-resolved
  version; the lockfile only moves after an explicit `npm update <package>`.
  Always re-run the scanner afterwards to prove the override took.
- **A major jump has to be exercised, not assumed.** These packages sit in the
  build toolchain, so "tests pass" proves little. Run the consumers: the PWA
  build (workbox requires brace-expansion through minimatch) and eslint (same
  chain), plus `npm ci --dry-run` for lockfile consistency.

Renovate treats `overrides` as its own dependency type, so a stale entry
surfaces as its own merge request (see the `overrides` rule in
`renovate.json`) instead of hiding inside a grouped devDependency bump.

**Why the lockfile refreshes weekly.** Three releases in a row failed the
osv-scanner gate on advisories published between refreshes: the fixes were
already inside the declared ranges, but a lockfile only moves when something
moves it. Monthly maintenance left a window in which every release tripped over
a fix it could already have had. `lockFileMaintenance` now runs weekly, and
`vulnerabilityAlerts` is unscheduled so a security fix never waits for a group
slot. That trades a few more merge requests for a gate that fires on genuinely
new problems instead of on a stale lockfile.

## Verifying after a push

The jobs above only prove themselves in a real pipeline run (the local
sandbox has no Docker/GitLab). After the next push: check that `osv-scan`,
`semgrep-sast`, and `secret_detection` appear and pass on the branch
pipeline, and that a tag pipeline additionally runs `image-scan` and
`self-sbom` (grab the SPDX artifact and drop it into SBOM Lens).
