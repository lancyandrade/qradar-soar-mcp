# Runbook: cutting a release (REL-04)

**Status (2026-11-16): the workflow exists on its branch; no release has been cut with it.**
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) has not yet run on
GitHub. The first tag push is its first run. Tagging is the owner's action, and so is
publishing the draft the workflow creates.

Building a release does not make it releasable. The `v0.2.0` verdict is **NO-GO** until
the lab gate is evidenced ([release-readiness §13.3](../release-readiness.md)), and
whether `v0.2.0` carries the CI-built archives at all is open (D25 (e)).

## 1. What the workflow does

A push of a tag matching `v*` runs three jobs, each only after the previous one passes:

| Job | Permissions | What it checks or does |
|---|---|---|
| `verify` | `contents: read`, `actions: read` | the tag is `vX.Y.Z`; the tagged commit is an ancestor of `main`; the `ci` workflow **succeeded on that exact commit as a push to `main`** (so gitleaks over the full history, the four-cell test matrix and pip-audit all passed); then it runs the gates again: `uv sync --locked`, ruff, format, mypy, the offline suite with both coverage floors, `check_no_secrets.py`, `check_artifact_hygiene.py`, pip-audit over the locked set |
| `build` | `contents: read`, `id-token: write`, `attestations: write` | a fresh checkout with no credentials kept; fails if `git status` shows any untracked or modified file; `uv build --no-build-isolation`, so the backend is the hatchling pinned in `uv.lock` and not one fetched for the build. uv builds the wheel from the sdist; `SOURCE_DATE_EPOCH` is the commit time. Then `scripts/check_release_dist.py` checks the archives (§3), writes `SHA256SUMS`, and the build provenance of both archives is attested |
| `release` | `contents: write` | no checkout and no repository code; downloads this run's three files, fails unless there are exactly three and `sha256sum --check --strict` passes, then `gh release create --draft --prerelease --verify-tag` with the archives and `SHA256SUMS` attached |

Not done, by design:

- **Nothing is uploaded to PyPI** or any other index. There is no publish step, and
  `tests/test_release_workflow.py` fails if one is added.
- **Nothing is published.** The release is a draft, which only users with write access
  can see. A human reads it and publishes it.
- **Nothing is overwritten or duplicated.** Before creating anything, `release` lists
  the repository's releases, drafts included, and fails if one already has the tag
  (`gh release create --draft` skips its own check, so it is not relied on). The
  workflow never uploads to, edits or replaces an existing release.

## 2. Cutting a release

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

4. Watch the `release` run. If any job fails, no draft is created. Fix the cause on
   `main`, then delete the tag (`git push --delete origin v0.2.0`) and tag again. To
   rebuild after a draft exists, delete the draft first; the workflow never replaces
   one.
5. Review the draft: the title, the notes (replace the generated text with the
   release notes), the three assets, and the pre-release flag. If this release is
   meant to be **source-only** (the current `v0.2.0` plan), delete the three assets
   from the draft before you publish it.
6. Publish the draft.

## 3. What `check_release_dist.py` refuses

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

## 4. Verifying a published release (anyone)

```bash
sha256sum --check --strict SHA256SUMS
```

```bash
gh attestation verify qradar_soar_mcp-0.2.0-py3-none-any.whl --repo lancyandrade/qradar-soar-mcp
```

The attestation says which workflow run, commit and tag built the file. It does not
say the release is fit for any purpose.

## 5. What has not been verified

- The workflow has **not run on GitHub**. The YAML is checked by tests, the `ci` run
  query was tried against `main` (`bd6115b`: one successful push run; an unknown SHA:
  zero), and `uv build --no-build-isolation` plus the checker were run locally
  (Windows 11, uv 0.11.14). The tag trigger, the attestation step and
  `gh release create` are exercised only by the first real tag push.
- Whether two builds of one commit are byte-identical has not been checked.
