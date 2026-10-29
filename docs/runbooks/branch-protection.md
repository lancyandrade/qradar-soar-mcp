# Runbook: `main` branch protection (REL-03)

**Status (2026-10-29): prepared for review, not applied.** The owner approved protecting
`main` in principle (08 §32, D17) and asked for the configuration to be reviewed
first. Nothing in this repository applies it. Every command under "Apply" is for the
owner to run; every command under "Verify" only reads.

Observed on 2026-10-29 (read-only API calls):

- `GET /repos/lancyandrade/qradar-soar-mcp/branches/main/protection` → `404 Branch not protected`.
- `GET /repos/lancyandrade/qradar-soar-mcp/rulesets` → `[]`.
- No Actions environments and no repository variables, so the review-loop and its
  merge gate are **not configured** (`REVIEW_LOOP_ENABLED`, `REVIEW_LOOP_GATE_ENABLED`
  unset; see [`review-loop.md`](review-loop.md) §3).
- One collaborator, the owner (`admin`). The repository is user-owned and public;
  merge, squash and rebase merging are all allowed; auto-merge is off.

## 1. Required status checks

The check names are the `name:` of each `ci.yml` job, expanded over its matrix. All
are check runs published by **GitHub Actions** (`app_id` `15368`), confirmed on the
check runs of `b643f5d` and `0f17ebc`.

| Check | Workflow / job | Why required |
|---|---|---|
| `secret scan (gitleaks, full history)` | `ci.yml` / `secrets` | `07 §7.5`, P1-12 |
| `test (ubuntu-latest, 3.12)` | `ci.yml` / `test` | ruff, format, mypy, the offline suite incl. the permission matrix (P1-13), coverage floors, tree scanner |
| `test (ubuntu-latest, 3.13)` | `ci.yml` / `test` | same |
| `test (windows-latest, 3.12)` | `ci.yml` / `test` | same |
| `test (windows-latest, 3.13)` | `ci.yml` / `test` | same |
| `dependency audit (pip-audit)` | `ci.yml` / `audit` | P1-12 |
| `review-loop/merge-gate` | published by the **review-loop App**, not by Actions | **phase 2 only**, after the App exists (§3) |

Not required: the `review-gate` jobs `gate` and `fanout` and the `review-loop` jobs
(`triage`, `claim`, `fix`, `verify`, `push`, `report`). They are skipped on every PR while
the loop is off, and `gate` is only the job that *publishes* the merge gate; the
required context is the App's `review-loop/merge-gate` check, never the job.

`ci.yml` has no `paths` filter, so every PR reports all six checks; none can stay
"expected" forever. `tests/test_branch_protection_config.py` fails if a job is renamed,
the matrix changes, or the proposal drifts from `ci.yml`.

## 2. Proposed rulesets

Rulesets rather than classic branch protection: they can pin each check to its source
app and they are listed by the API. Three JSON bodies, ready for
`POST /repos/{owner}/{repo}/rulesets`:

| File | Target | Apply when |
|---|---|---|
| [`rulesets/main-phase1.json`](rulesets/main-phase1.json) | `main` (`~DEFAULT_BRANCH`) | now, after review |
| [`rulesets/main-phase2-merge-gate.json`](rulesets/main-phase2-merge-gate.json) | `main` | **replaces** phase 1 once the review-loop App exists and has published `review-loop/merge-gate` on a PR (review-loop §3.7); fill in the App id first: the placeholder is a string, so the API rejects the file until it is replaced |
| [`rulesets/release-tags.json`](rulesets/release-tags.json) | tags `v*` | before the first release tag; makes a published tag impossible to move or delete |

Phase 1 rules on `main`:

- **No deletion, no force push** (`deletion`, `non_fast_forward`).
- **Pull request required**, 0 approvals (a solo maintainer cannot approve their own
  PR; raise to 1 when there is a second maintainer), stale approvals dismissed on push,
  **every review thread resolved** before merge.
- **Merge commits only** (`allowed_merge_methods: ["merge"]`). The reviewed commits
  land unchanged; squash and rebase would rewrite them. Linear history is therefore
  *not* required (it would forbid merge commits).
- **The six CI checks required, each pinned to GitHub Actions (`integration_id`
  15368)**, and the branch must be up to date with `main` before merging (`strict`).
- **Bypass list empty**: nobody, including the owner and every automation account,
  bypasses the rules in normal operation.

## 3. Administrators and automation accounts

| Actor | Access today | In the bypass list? | Notes |
|---|---|---|---|
| Owner (`admin`) | full | **no** | Keeps the ability to edit the ruleset, which is the recovery path (§5). Merging past a red check is never a normal operation. |
| `github-actions[bot]` (`GITHUB_TOKEN`) | per-workflow permissions; `ci.yml` is `contents: read` | **no** | Never pushes to `main`. `review-gate.yml`'s `fanout` uses `actions: write` only to dispatch runs. |
| review-loop GitHub App (not created yet) | will hold `contents: write`, `checks: write`, no `workflows` | **no** | Pushes fix commits to **PR branches** only, fast-forward, never to `main` (review-loop §4.1). The ruleset targets `main` only, so it does not affect those pushes. Its check is the phase-2 gate. |
| Codex (`chatgpt-codex-connector[bot]`, id `199175422`) | reviews and comments | **no** | Never pushes or merges. |

Add an actor to the bypass list only for a recorded emergency, and remove it again.

## 4. Conflicts with the review-loop automation

1. **The merge gate is not configured.** `review-loop.md` §3.7 already proposes a
   ruleset that requires `review-loop/merge-gate`. Applied today, that check never
   appears (no App, gate disabled), so **every merge would be blocked**. Hence phase 1
   without it, and phase 2 only after review-loop §8.1 has been run.
2. **Pinning the gate's source.** In phase 2 the gate must be pinned to the review-loop
   App's id. Pinned to GitHub Actions or left on "any source", any workflow could publish
   a passing check with that name.
3. **Fix commits and `strict`.** A review-loop push makes the PR head new, which
   re-runs CI; `strict` also requires the PR to be up to date with `main`. Updating a PR
   branch with a merge from `main` is allowed (it is a PR branch, not `main`).
4. **Stale approvals.** `dismiss_stale_reviews_on_push` dismisses approvals after a
   review-loop push. With 0 required approvals this has no effect today.
5. **Review threads.** `required_review_thread_resolution` makes Codex findings block
   the merge until resolved. That is intended, and matches review-loop §3.7.

Residual risk, not solved by a ruleset: a pull request can edit `ci.yml` itself, and its
`pull_request` run uses the PR's version, so a malicious PR could make the six checks
pass trivially. The checks show that the PR's own CI passed, not that CI was unchanged.
Mitigation: the human reads every change under `.github/` before merging (07 §7.5's
"human read of the diff" applies), and in phase 2 the review-loop gate re-reads from
the default branch.

## 5. Recovery procedure

If the ruleset blocks a merge that must happen (CI outage, a check renamed, the App
broken):

1. Prefer fixing the cause: re-run the failed job, or fix the check name in the ruleset
   (§6 shows the current names).
2. If a merge cannot wait: as the owner, set the ruleset's `enforcement` to `disabled`
   (Settings → Rules → Rulesets → the ruleset → Enforcement status, or the `PUT` in §6),
   merge, then set it back to `active` straight away.
3. Record in the PR: what was bypassed, why, and when enforcement was restored.
4. Verify (§6) that the ruleset is `active` again and unchanged.

Never delete the ruleset to get past it, and never force-push `main`. A lost admin
account is recovered through GitHub account recovery; no second admin exists, which
is a single point of failure the owner should note.

## 6. Commands

### Verify (read-only; safe at any time)

```bash
gh api repos/lancyandrade/qradar-soar-mcp/rulesets --jq '.[] | {id, name, target, enforcement}'
```

```bash
gh api repos/lancyandrade/qradar-soar-mcp/rules/branches/main --jq '.[] | .type'
```

```bash
gh api repos/lancyandrade/qradar-soar-mcp/commits/main/check-runs --jq '.check_runs[] | {name, conclusion, app_id: .app.id}'
```

```bash
uv run pytest -q tests/test_branch_protection_config.py
```

Expected after phase 1: one active branch ruleset; rules `deletion`,
`non_fast_forward`, `pull_request`, `required_status_checks` on `main`.

### Apply (owner only, after review; **not run by this change**)

```bash
gh api -X POST repos/lancyandrade/qradar-soar-mcp/rulesets --input docs/runbooks/rulesets/main-phase1.json
```

```bash
gh api -X POST repos/lancyandrade/qradar-soar-mcp/rulesets --input docs/runbooks/rulesets/release-tags.json
```

Then test it on a throw-away PR: a direct `git push` to `main` must be refused; a PR
must show the six required checks; a PR with an unresolved review thread must not be
mergeable.

### Emergency (owner only; §5)

```bash
gh api -X PUT repos/lancyandrade/qradar-soar-mcp/rulesets/RULESET_ID -f enforcement=disabled
```

```bash
gh api -X PUT repos/lancyandrade/qradar-soar-mcp/rulesets/RULESET_ID -f enforcement=active
```
