# Deploying OpenBoxes

Releases are built and published automatically by GitHub Actions.  There is no longer
a Bamboo or Travis CI dependency — GitHub Actions is the single source of CI truth.

## Automated release process

1. **Tag the commit** you want to release using the `vX.Y.Z` format:

   ```bash
   git tag v0.9.5
   git push origin v0.9.5
   ```

2. **GitHub Actions triggers automatically.**  Pushing a tag matching
   `v[0-9]+.[0-9]+.[0-9]+**` starts two parallel workflows:

   | Workflow | File | What it does |
   |---|---|---|
   | Create GitHub Release With Artifacts | `do-github-release.yml` | Builds the WAR with `./grailsw war`, creates a **draft** GitHub Release, and attaches `openboxes.war` as a release asset. |
   | Docker | `docker-image.yml` | Builds the Docker image with `./gradlew prepareDocker` and pushes it to `ghcr.io/openboxes/openboxes:<tag>`. |

3. **Review the draft release** at
   `https://github.com/openboxes/openboxes/releases` and publish it once
   the artifacts look correct.

## Branch-protection required-status-check notes

> **Migration note (WO-001):** The dependency-review workflow file was renamed
> from `dependecy-review.yml` (misspelling) to `dependency-review.yml`.
> The required status check name in branch protection rules was
> **"dependency-review / dependency-review"** and remains the same after
> the rename because the workflow `name:` field and job name are unchanged.
> Confirm any branch-protection rules still match after this change.

## Monitoring build status

- **Main-branch health** — the _On Change_ workflow (`on-change.yml`) runs
  backend and frontend tests on every push to `master`, `develop`, and
  `release/**`.  Failures trigger a Slack notification via `slack-notifier.yml`.

- **Pull-request gating** — the _Test Pull Request_ workflow
  (`test-pull-request.yml`) runs the same test suite on every PR.

- **Workflow hygiene** — the _Workflow Lint_ workflow (`workflow-lint.yml`)
  runs `actionlint` over all workflow files and is a required check.

## Local WAR build (manual)

```bash
./grailsw war --info
```

The resulting artifact is written to `build/libs/openboxes.war`.
