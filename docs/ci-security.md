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

## Verifying after a push

The jobs above only prove themselves in a real pipeline run (the local
sandbox has no Docker/GitLab). After the next push: check that `osv-scan`,
`semgrep-sast`, and `secret_detection` appear and pass on the branch
pipeline, and that a tag pipeline additionally runs `image-scan` and
`self-sbom` (grab the SPDX artifact and drop it into SBOM Lens).
