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
milestone (§7).

## 1. What the workflow does

A push of a tag matching `v*` runs three jobs, each only after the previous one passes:

| Job | Permissions | What it checks or does |
|---|---|---|
| `verify` | `contents: read`, `actions: read` | the tag is `vX.Y.Z`; the tagged commit is an ancestor of `main`; the `ci` workflow **succeeded on that exact commit as a push to `main`** (so gitleaks over the full history, the four-cell test matrix and pip-audit all passed); the `release` environment exists, has at least one required reviewer, uses custom deployment policies and allows exactly `tag:v*` (§2); then it runs the gates again: `uv sync --locked`, ruff, format, mypy, the offline suite with both coverage floors, `check_no_secrets.py`, `check_artifact_hygiene.py`, pip-audit over the locked set |
| `build` | `contents: read`, `id-token: write`, `attestations: write` | a fresh checkout with no credentials kept; fails if `git status` shows any untracked or modified file; `uv build --no-build-isolation`, so the backend is the hatchling pinned in `uv.lock` and not one fetched for the build. uv builds the wheel from the sdist; `SOURCE_DATE_EPOCH` is the commit time. Then `scripts/check_release_dist.py` checks the archives (§4: member paths and structure, and content against the tagged commit), writes `SHA256SUMS`, and the build provenance of both archives is attested |
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

## 4. What `check_release_dist.py` checks, and what it does not

`scripts/check_release_dist.py --dist DIR --tag TAG --ref REF --write-sums` exits 1, and
writes no `SHA256SUMS`, on any failure below. `--ref` defaults to `HEAD`; the workflow
passes the tagged commit (`$GITHUB_SHA`).

**Versions and the directory.** The tag must be `v<major>.<minor>.<patch>` and equal to
the `pyproject.toml` version at `REF`, which must equal `__version__` at `REF`. `DIR`
must hold only the sdist, the `py3-none-any` wheel and the `.gitignore` uv writes into
its output directory.

**Paths and structure (the REL-06 allow-list).**

- An sdist member must be a regular file or directory under `<dist>-<version>/`, and
  the set of files must be exactly `pyproject.toml`, `README.md`, `LICENSE`, `PKG-INFO`,
  `.gitignore` and the package files git tracks at `REF`.
- A wheel member must not be a symlink, and the set must be exactly the tracked package
  files plus the five `dist-info` files.
- No member path may be absolute, contain `..` or a backslash, or have a forbidden
  component (`.claude`, `.git`, `.github`, `tests`, `docs`, `scripts`, …) or suffix
  (`.log`, `.pem`, `.key`, `.pyc`, `.jsonl`, `.env`, `.png`).

**Content (added after the PR #27 review).** A path check alone would pass an archive
whose `server.py` had been altered. So:

- every sdist member except `PKG-INFO`, and every wheel package file and
  `dist-info/licenses/LICENSE`, must be **byte-for-byte the blob git holds at `REF`**
  (read with `git cat-file`, not from the working tree);
- `PKG-INFO` and `METADATA` must carry exactly one `Name` and one `Version`, the
  project's;
- `entry_points.txt` must hold only `[console_scripts]`, equal to `[project.scripts]` at
  `REF`, so no extra command can be installed;
- `RECORD` must list every other wheel member exactly once with the right SHA-256 and
  size, and itself without a hash.

**Not checked.** The rest of the generated metadata (the dependency list and classifiers
in `PKG-INFO`/`METADATA`, the `WHEEL` file) is not compared field by field; hatchling
derives it from the `pyproject.toml` that *is* compared. Build reproducibility (two
builds of one commit giving identical archives) is not checked.

`LICENSE` and `py.typed` are pinned to LF in `.gitattributes`, because a Windows
checkout with `text=auto` wrote `LICENSE` with CRLF and a local build then failed the
content check (correctly: that archive did not match the commit). In CI (Linux) the
checkout is LF.

The allow-list constants equal those in `tests/test_packaging.py` (a test keeps them
equal), and `tests/test_packaging.py` runs the checker, content checks included, over
the real archives it builds.

## 5. Verifying a published release (anyone)

```bash
sha256sum --check --strict SHA256SUMS
```

```bash
gh attestation verify qradar_soar_mcp-0.2.0-py3-none-any.whl --repo lancyandrade/qradar-soar-mcp
```

The attestation says which workflow run, commit and tag built the file. It does not
say the release is fit for any purpose.

## 6. Token permissions, verified on GitHub (2026-11-17)

The `verify` job reads the `release` environment and its deployment branch policies
with its own `GITHUB_TOKEN` (`contents: read`, `actions: read`; no administration
access). GitHub's per-permission table lists these three reads under **Actions: read**
for installation tokens; creating or changing an environment or a policy needs
**Administration: write**, which no job here has.

A throwaway probe was run with real tokens: branch `probe/rel-04-env-permissions`
(commit `5445603`, one read-only workflow, not part of this PR, never to be merged),
run `44057891024`. It printed HTTP status codes and counts only:

| Call | job with `actions: read` | job with `contents: read` only |
|---|---|---|
| `GET` this repository's environments | 200 | 200 |
| `GET` this repository's `release` environment | 404 (not created) | 404 |
| `GET` its deployment branch policies | 404 (not created) | 404 |
| `GET` a protected environment of a public repository (`astral-sh/uv` `release-gate`) | 200; `reviewers: 1`, `custom: true` | same |
| `GET` that environment's deployment branch policies | 200; `["branch:main"]` | same |

So the token can read an environment's reviewer rules and policies without any
administration permission. On this public repository even `contents: read` sufficed;
`actions: read` is kept because it is the documented permission (and what a private
repository would need) and because `verify` needs it for the `ci` run query. A missing
environment reads as 404, which `verify` turns into a failure. Not yet observed: a read
of **this** repository's `release` environment once it exists (step A.3 and B.2 below).

## 7. First tag-triggered run: acceptance procedure

The first run is an acceptance milestone of its own, after REL-04 merges. Nothing in
this section creates a tag in this repository, publishes a release or waives a release
gate; each step is the owner's.

### A. Rehearsal in a disposable repository (recommended; touches nothing here)

1. Create a new **public** scratch repository (public, because build-provenance
   attestation on a private user repository is not available) and push this
   repository's `main` to it. Enable Actions and wait for its `ci` push run on `main`
   to go green.
2. **Negative check, no environment:** push the tag `v<version>` to the scratch
   repository. Expect `verify` to fail at "The release environment needs a reviewer
   and allows only v* tags" with the "missing or unreadable" message, and no `build`
   or `release` job to run. Delete the tag there.
3. Create the `release` environment in the scratch repository as in §2, and run the
   two read-only verify commands of §2 against it.
4. **Positive run:** push the tag again. Expect `verify` and `build` green, the
   checker's `ok` line in the `build` log, an attestation, and `release` waiting for
   approval. Approve it.
5. Check the draft: exactly three assets; download them, run
   `sha256sum --check --strict SHA256SUMS` and
   `gh attestation verify <wheel> --repo <scratch repository>`; confirm the draft is a
   pre-release and is not published.
6. **Negative check, existing draft:** re-run the `release` job of that run. Expect it
   to fail with "a release for … already exists" and no second draft.
7. Delete the scratch repository. Record the run URLs and outcomes in
   release-readiness §12.4.

### B. The first real run (only when the owner authorises a release)

1. Every prerequisite of §3 and the release gate for that version are met, or the owner
   has recorded a decision; for `v0.2.0` the verdict is **NO-GO** until the lab gate is
   evidenced.
2. Create the `release` environment here (§2) and run its verify commands.
3. Follow §3. Before approving the `release` job, read the `verify` and `build` logs:
   the tagged commit, the green `ci` run it found, the environment check, the checker's
   `ok` line.
4. Do not publish until the §3 checklist is complete (for `v0.2.0`: delete the three
   assets, D25 (e)).

**Accepted when:** `verify` found the `ci` run and the protected environment; the
checker passed against the tagged commit; the attestation exists; the job waited for
approval; exactly one draft was created; the sums and the attestation verify.
**Rejected if** any of that is not seen: reject the deployment (or delete the draft),
delete the tag, fix on `main` and start again. Record the evidence in
release-readiness §12.4.

## 8. What has not been verified

- The workflow has **not completed a real tag-triggered run**, here or in a rehearsal
  repository. Verified: the YAML, by tests; the `ci` run query against `main`
  (`bd6115b`: one successful push run; an unknown SHA: zero); the environment reads
  with real workflow tokens (§6); `uv build --no-build-isolation` plus the checker,
  content checks included, locally (Windows 11, uv 0.11.14) against `HEAD`. Not yet
  exercised: the tag trigger, a read of this repository's `release` environment once
  created, the approval wait, the attestation step and `gh release create`. §7 is how
  they get exercised.
- Whether two builds of one commit are byte-identical has not been checked.
