# Contributing

## Branching workflow

**Do not commit directly to `main`.** All changes go through a short-lived branch and a
pull request, so CI runs before anything lands on `main`.

```bash
git switch -c <type>/<short-description>     # e.g. feat/add-adas-assets, fix/can-link-auth
# ...make changes, commit...
git push -u origin <branch>
gh pr create --fill --base main              # open the PR
# CI runs on the PR; once green:
gh pr merge --squash --delete-branch         # merge to main and clean up
git switch main && git pull                  # sync local main
```

Suggested branch prefixes: `feat/`, `fix/`, `chore/`, `docs/`, `research/`.

### Why no direct pushes to `main`
We want every change validated by CI (model validation, analyzer regression, ruff,
Threagile run) before it reaches `main`.

GitHub **branch protection** is the proper enforcement, but it requires the repo to be
**public** (or the owner to be on GitHub Pro/Team for a private repo). Until then we
enforce the rule **locally** with a committed `pre-push` hook.

### Enable the local guard (one-time per clone)
The hook lives in `.githooks/` (version-controlled). Point git at it:

```bash
git config core.hooksPath .githooks
```

After that, `git push` to `main` is rejected with a reminder to use a branch + PR.
Emergency override (avoid): `git push --no-verify`.

### When the repo goes public
Turn on branch protection for `main` (require PR + passing CI status checks) and the
local hook becomes a convenience rather than the primary guard.

## CI

`.github/workflows/ci.yml` runs on PRs to `main` and on pushes to `main`:

- **Validate** — `scripts/validate-model.sh` (model parses) plus the attack-path
  analyzer regression test (Jeep demo diffed against the committed expected output).
- **Ruff** — lints `scripts/`.
- **Threagile** — runs `threagile analyze` in Docker and uploads the report + diagrams
  as a build artifact.
- **Custom risk rules** — runs Threagile's `cmd/script` harness (pinned source + Go) over
  each rule in `model/custom-risk-rules/` against the committed parsed-format fixture,
  asserting each fires on its intended asset and skips its negative control.

Run the fast checks locally before pushing:

```bash
./scripts/validate-model.sh
python3 scripts/attack_path_analyzer.py scripts/examples/jeep-demo.threagile.yaml --out /tmp/demo.yaml
```

To run the custom-rule checks locally you need Go and the Threagile source:

```bash
git clone https://github.com/Threagile/threagile.git /tmp/threagile-src
./scripts/test-risk-rules.sh /tmp/threagile-src
```
