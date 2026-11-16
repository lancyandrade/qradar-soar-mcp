# Runbook: cutting a release (REL-04)

**Status (2026-11-16): the workflow exists on its branch; no release has been cut with it.**
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) has not yet run on
GitHub. The first tag push is its first run. Tagging is the owner's action, and so is
publishing the draft the workflow creates.

Building a release does not make it releasable. The `v0.2.0` verdict is **NO-GO** until
the lab gate is evidenced ([release-readiness §13.3](../release-readiness.md)), and
whether `v0.2.0` carries the CI-built archives at all is open (D25 (e)). Until the
owner decides, **`v0.2.0` is source-only** and the publication checklist (§3) removes the
CI-built assets from its draft.

**No tag is created, no release is published and no lab gate is waived by this runbook
or by merging REL-04.** The first owner-authorised tag push is a separate acceptance
milestone (§6).

## 1. What the workflow does

A push of a tag matching `v*` runs three jobs, each only after the previous one passes:

| Job | Permissions | What it checks or does |
|---|---|---|
| `verify` | `contents: read`, `actions: read` | the tag is `vX.Y.Z`; the tagged commit is an ancestor of `main`; the `ci` workflow **succeeded on that exact commit as a push to `main`** (so gitleaks over the full history, the four-cell test matrix and pip-audit all passed); the `release` environment exists, has at least one required reviewer, uses custom deployment policies and allows exactly `tag:v*` (§2); then it runs the gates again: `uv sync --locked`, ruff, format, mypy, the offline suite with both coverage floors, `check_no_secrets.py`, `check_artifact_hygiene.py`, pip-audit over the locked set |
| `build` | `contents: read`, `id-token: write`, `attestations: write` | a fresh checkout with no credentials kept; fails if `git status` shows any untracked or modified file; `uv build --no-build-isolation`, so the backend is the hatchling pinned in `uv.lock` and not one fetched for the build. uv builds the wheel from the sdist; `SOURCE_DATE_EPOCH` is the commit time. Then `scripts/check_release_dist.py` checks the archives (§3), writes `SHA256SUMS`, and the build provenance of both archives is attested |
| `release` | `contents: write`; environment `release` | **waits for a required reviewer to approve the deployment**; no checkout and no repository code; downloads this run's three files, fails unless there are exactly three and `sha256sum --check --strict` passes, then `gh release create --draft --prerelease --verify-tag` with the archives and `SHA256SUMS` attached |

Not done, by design:

- **Nothing is uploaded to PyPI** or any other index. There is no publish step, and
  `tests/test_release_workflow.py` fails if one is added.
- **Nothing is published.** The release is a draft, which only users with write access
  can see. A human reads it and publishes it.
- **Nothing is overwritten or duplicated.** Before creating anything, `release` lists
  the repository's releases, drafts included, and fails if one already has the tag
  (`gh release create --draft` skips its own check, so it is not relied on). The
  workflow never uploads to, edits or replaces an existing release.

## 2. One-time setup: the protected `release` environment (owner)

**Status (2026-11-16): prepared, not applied.** The PR #27 review asked for the release
job to run in a protected environment, subject to the owner confirming D25 (d). The
workflow names it; nothing in this repository creates it. While it is missing, `verify`
fails every tag run before anything is built, so the workflow cannot release
unprotected. (GitHub would otherwise create a missing environment, unprotected, when a
job first names it.)

Settings → Environments → **New environment** `release`:

- **Required reviewers:** the owner. Leave *Prevent self-review* off: with one
  maintainer it would block every release. The approval is still a second, deliberate
  step after the tag push, so a tag pushed by an automation or a leaked token cannot
  reach `contents: write` on its own.
- **Deployment branches and tags:** *Selected branches and tags*, with exactly one rule:
  tag `v*`.
- No environment secrets or variables: the job uses only the run's `GITHUB_TOKEN`.

Or with the API (owner; each call writes a repository setting):

```bash
gh api -X PUT repos/lancyandrade/qradar-soar-mcp/environments/release --input - <<EOF
{"reviewers":[{"type":"User","id":$(gh api user --jq .id)}],"prevent_self_review":false,
 "deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
EOF
```

```bash
gh api -X POST repos/lancyandrade/qradar-soar-mcp/environments/release/deployment-branch-policies -f name='v*' -f type=tag
```

Verify (read-only; this is what `verify` checks):

```bash
gh api repos/lancyandrade/qradar-soar-mcp/environments/release --jq '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers | length] | add // 0'
```

```bash
gh api repos/lancyandrade/qradar-soar-mcp/environments/release/deployment-branch-policies --jq '.branch_policies[] | "\(.type):\(.name)"'
```

The first must print `1` or more, the second exactly `tag:v*`.

## 3. Cutting a release

1. Merge the release commit to `main` through a pull request, and wait for the `ci`
   push run on the merge commit to go green. Tag **that** commit. A commit that was
   never the head of a push to `main` (for example a commit inside a merged branch)
   has no `ci` push run, and `verify` refuses it.
2. Check that the version agrees in `pyproject.toml` and
   `src/qradar_soar_mcp/__init__.py`, and that `CHANGELOG.md` and `docs/releases/`
   describe the release.
3. Tag and push (owner):

   ```bash
   git tag -a v0.2.0 -m "v0.2.0" <merge-commit-sha>
   ```

   ```bash
   git push origin v0.2.0
   ```

4. Watch the `release` run. When `verify` and `build` pass, the `release` job waits
   for approval: review the run (the commit, the `build` log, the checker's output)
   before approving the deployment. If any job fails or the approval is rejected, no
   draft is created. Fix the cause on
   `main`, then delete the tag (`git push --delete origin v0.2.0`) and tag again. To
   rebuild after a draft exists, delete the draft first; the workflow never replaces
   one.
5. Work through the publication checklist below, then publish the draft.

### Publication checklist (every item before *Publish release*)

- [ ] The release gate for this version is met, or the owner has recorded a decision
      that it need not be (for `v0.2.0`: release-readiness §13.3 is still **NO-GO**; no
      lab gate is waived by this runbook).
- [ ] The draft's tag, title and target commit are the ones you approved.
- [ ] The generated notes are replaced by the release notes (`docs/releases/`).
- [ ] **Assets — source-only releases (`v0.2.0`, until D25 (e) says otherwise):
      delete all three assets** (the sdist, the wheel and `SHA256SUMS`) from the
      draft. Afterwards the only downloads are GitHub's generated source archives.
- [ ] Assets — releases that ship archives: exactly three assets; download them and
      run `sha256sum --check --strict SHA256SUMS` and `gh attestation verify` (§5).
- [ ] *Set as a pre-release* is ticked for every `0.x` release (D25 (b)).

## 4. What `check_release_dist.py` refuses

`scripts/check_release_dist.py --dist DIR --tag TAG --write-sums` exits 1, and writes
no `SHA256SUMS`, if:

- the tag is not `v<major>.<minor>.<patch>` or differs from the `pyproject.toml`
  version, or `__version__` differs from it;
- `DIR` holds anything but the sdist, the `py3-none-any` wheel and the `.gitignore`
  uv writes into its output directory, or either archive is missing;
- an sdist member is not a regular file or directory, lies outside
  `<dist>-<version>/`, or is not in `pyproject.toml`, `README.md`, `LICENSE`,
  `PKG-INFO`, `.gitignore` or the git-tracked package files; or a tracked package file
  is missing;
- a wheel member is a symlink, or is not a tracked package file or one of the five
  `dist-info` files;
- any member path is absolute, contains `..` or a backslash, or has a forbidden
  component (`.claude`, `.git`, `.github`, `tests`, `docs`, `scripts`, …) or suffix
  (`.log`, `.pem`, `.key`, `.pyc`, `.jsonl`, `.env`, `.png`).

The allow-list is the REL-06 manifest; `tests/test_release_workflow.py` keeps the
script's constants equal to those in `tests/test_packaging.py`, and
`tests/test_packaging.py` runs the checker over the real archives it builds.

## 5. Verifying a published release (anyone)

```bash
sha256sum --check --strict SHA256SUMS
```

```bash
gh attestation verify qradar_soar_mcp-0.2.0-py3-none-any.whl --repo lancyandrade/qradar-soar-mcp
```

The attestation says which workflow run, commit and tag built the file. It does not
say the release is fit for any purpose.

## 6. What has not been verified

- The workflow has **not completed a real tag-triggered run**. The YAML is checked by
  tests, the `ci` run query was tried against `main` (`bd6115b`: one successful push
  run; an unknown SHA: zero), the environment `jq` expressions were tried against
  public repositories' environments, and `uv build --no-build-isolation` plus the
  checker were run locally (Windows 11, uv 0.11.14). The tag trigger, reading the
  `release` environment with the run's token, the approval wait, the attestation step
  and `gh release create` are exercised only by the first owner-authorised tag push,
  which is a separate acceptance milestone after REL-04 merges.
- Whether two builds of one commit are byte-identical has not been checked.
