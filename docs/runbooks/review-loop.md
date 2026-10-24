# Runbook: Codex review loop and merge gate

This repository can run an automated loop on its own pull requests:

```
Codex reviews the PR head ──► findings? ──► Claude Code proposes fixes + regression tests
        ▲                                         │
        │                                         ▼
        │                        patch policy + full test suite (no secrets)
        │                                         │
        └──── "@codex review" ◄── push to the PR branch (fast-forward only)
                                                  │
                         CI runs ──► merge gate re-evaluates the new head
```

and a **merge gate**: a required check, `review-loop/merge-gate`, that passes
only when the PR's current head commit has green CI, a completed Codex review
with no unresolved finding, and the security requirements below.

**Nothing merges automatically.** The loop never merges, approves, force-pushes
or changes branch protection. A person merges.

**The loop is off until you turn it on.** It does nothing unless the repository
variable `REVIEW_LOOP_ENABLED` is exactly `true`, and the workflows only run
from the default branch, so nothing happens before this is merged and set up.

No job in this automation holds SOAR credentials or talks to a SOAR appliance.
The test job runs the offline suite with `SOAR_BASE_URL=""`, exactly like CI.

## 1. Components

| File | Role |
|---|---|
| [`.github/workflows/codex-review-relay.yml`](../../.github/workflows/codex-review-relay.yml) | Receives `pull_request_review` events (finishes only when the reviewer is the Codex bot) and `pull_request_review_thread` resolve/unresolve events (same-repository PRs; they re-run the gate, never the fix loop). No permissions, no secrets. |
| [`.github/workflows/review-loop.yml`](../../.github/workflows/review-loop.yml) | The fix loop: triage → claim → fix → verify → push → report. |
| [`.github/workflows/review-gate.yml`](../../.github/workflows/review-gate.yml) | Evaluates and publishes `review-loop/merge-gate` on the PR head. |
| [`automation/review_loop/`](../../automation/review_loop/) | Stdlib-only Python that makes every decision (identity, freshness, ledger, patch policy, gate). Read from the default branch at run time. |
| `tests/test_review_loop_*.py` | Offline tests for all of the above, including the workflows themselves. |

## 2. Security properties

- **Identity by number, not by name.** Codex is accepted only as GitHub App
  `1144995` (`chatgpt-codex-connector`, owner `openai`) acting as bot user
  `199175422` of type `Bot`. Issue comments must carry that App id; reviews and
  inline comments (where GitHub does not expose the App) must match the bot
  user id, type and login. A login, a body, or a copied marker alone never
  counts. These ids were observed on this repository (PR #11).
- **Belongs to this PR.** Everything is re-read from endpoints scoped to the
  PR, and each artefact's own URL must name this repository and PR number.
  Event payload bodies are never trusted; they only name a PR number.
- **Fresh and complete.** Codex's summary comment carries a
  `codex-review-state:v1` block. The loop and the gate act only when that block
  says the review of the **exact current head SHA** is `completed`, a matching
  receipt (`codex-review-receipt:v1`, reviewed-commit prefix) exists, and every
  finding it reports was retrieved through the pull-request review comments API
  with its review thread. Stale (older commit), missing, pending, malformed,
  inconsistent or partial data is rejected; the gate fails.
- **Approved branches only.** Same-repository branches matching
  `(phaseN|fix|feat|build|docs|test|chore|refactor|automation)/<name>`, base
  `main`, opened by an owner/member/collaborator. Forks and `main` are never
  processed.
- **Untrusted code never meets privileged credentials.**
  - Claude Code runs with the Anthropic key, a **read-only** token, and only
    `Read, Edit, Write, Glob, Grep` (no shell, no web): it never executes PR
    code. Before it starts, the job refuses a checkout containing symlinks,
    moves aside every file Claude Code or its tools read as configuration
    (`.claude/`, `.claude.json`, `.mcp.json`, `.gitmodules`, `.ripgreprc`,
    `.husky/`, every `CLAUDE.md` / `CLAUDE.local.md`), disables hooks, and
    denies its file tools `/proc`, `/sys`, `/etc`, `/tmp`, the runner's temp
    and action directories (which hold the step file-command files) and
    `.git/` / `.github/`. The patch is built against a pristine copy of the
    git metadata taken before Claude ran, with hooks and fsmonitor off, and
    nothing credential-shaped (Anthropic, GitHub, AWS keys, private keys,
    JWTs) may leave the job.
  - The test job runs PR code with **no secrets** and a read-only token.
  - The push job holds a short-lived App token (contents + pull requests
    write, **no workflows permission**, so it cannot change `.github/`) and no
    Anthropic key. It re-checks the patch digest and policy, then checks that
    the branch head is still the reviewed commit and that this run still holds
    the attempt claim, and pushes without force. A moved branch makes the push
    fail.
  - Findings are passed to Claude as a data file and the prompt says they are
    untrusted. The model's free-text reasons are **never posted**: reports
    show only finding ids and verdict values. Other quoted text is neutralised
    (no hidden markers, no `@` mentions).
- **Patch policy.** An automated patch may touch only `src/qradar_soar_mcp/`,
  `tests/`, `docs/`, `examples/`, `config/` and `README.md`, and never the
  protected paths in `policy.py` — among them `security/`, `config.py`,
  `tls.py`, `redaction.py`, `logging.py`, `server.py`, `tools/registry.py`,
  `tools/runtime.py`, `docs/design/0*`, `tests/conftest.py`, the permission
  matrix and hygiene tests, fixtures, and this automation's own tests. Matching
  is case-insensitive and refuses Windows-aliased names (`security.`), so a
  case-insensitive checkout cannot be used to reach a protected directory. No
  deletions, binaries, symlinks, executables (new or existing, checked against
  the index), renames into protected paths, or credential-shaped values; at
  most 25 files / 1500 changed lines; and it must **add** lines to a
  `tests/test_*.py` regression test. Every finding needs exactly one
  verdict (`fixed`, `not_a_bug`, `already_fixed`, `needs_human`).
- **Bounded.** At most **3** fix attempts per PR (one per head commit). Each
  attempt is a claim comment by `github-actions[bot]`; the earliest claim for a
  head wins, which settles races and duplicate events. Runs are serialised per
  PR. Any failure halts the loop for that PR (label `review-loop:halted`) and
  posts one report.
- **Deny-by-default stays.** The prompt restates the project rules (no new
  REST endpoints or bodies, no weakened capability/policy/approval/audit/
  redaction/TLS checks, no secrets or real hosts); the patch policy keeps the
  security package and scanner configuration out of reach; the full test suite
  (permission matrix, security coverage floor, secret scan) must pass before
  push and again in CI.

## 3. One-time setup

### 3.1 Create the review-loop GitHub App

Settings → Developer settings → GitHub Apps → **New GitHub App**:

- Name: e.g. `qradar-soar-review-loop`; Homepage: the repository URL.
- Webhook: **uncheck "Active"** (no webhook is needed).
- Repository permissions — exactly these:
  - **Checks: Read and write** (publishes the merge gate)
  - **Contents: Read and write** (pushes fix commits)
  - **Pull requests: Read and write** (posts the `@codex review` request)
  - Metadata: Read-only (mandatory)
  - Everything else: No access. In particular **not** Workflows,
    Administration, Actions or Secrets.
- "Where can this GitHub App be installed?": **Only on this account**.
- Create it, note the **Client ID**, and **generate a private key** (a `.pem`
  download). Install the App on **only** `qradar-soar-mcp`.

Treat the `.pem` like any other secret: put it in the environment below, then
delete the downloaded file.

### 3.2 Environments (Settings → Environments)

| Environment | Deployment branches | Secrets | Variables |
|---|---|---|---|
| `review-loop` | **Selected branches: `main` only** | `REVIEW_LOOP_APP_PRIVATE_KEY` (the `.pem` contents); optional `REVIEW_LOOP_REQUEST_TOKEN` (§3.5) | `REVIEW_LOOP_APP_CLIENT_ID` |
| `review-loop-claude` | **Selected branches: `main` only** | `ANTHROPIC_API_KEY` | — |

The branch restriction is what keeps these secrets away from workflows on PR
branches. Do not add required reviewers (the loop would wait forever) and do
not store these as repository-level secrets.

Use a dedicated Anthropic API key for this repository, with a spend limit, so
it can be revoked without affecting anything else.

### 3.3 Repository variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Value | Meaning |
|---|---|---|
| `REVIEW_LOOP_ENABLED` | `true` | Kill switch for the fix loop. Any other value, or absent, disables it. |
| `REVIEW_LOOP_GATE_ENABLED` | `true` | Turns on gate evaluation. Off, the gate publishes nothing — and once it is a required check, that blocks merging. |
| `REVIEW_LOOP_CLAUDE_MODEL` | optional, e.g. `claude-opus-5-5` | Model for the fix job (default `claude-opus-5-5`). |

### 3.4 Actions settings (Settings → Actions → General)

- Workflow permissions: **Read repository contents** (already the setting).
- "Allow GitHub Actions to create and approve pull requests": **off** (already
  off).
- Fork pull request workflows: **require approval for all external
  contributors**.
- Optional, recommended: **require actions to be pinned to a full-length commit
  SHA**. Every workflow already complies and a test enforces it.

### 3.5 Optional: a request token for `@codex review`

The push job asks Codex for a fresh review by commenting `@codex review` as the
review-loop App. **Whether Codex honours a request from an App account has not
been verified** (it does honour the repository owner's comments). If the first
automated push gets no Codex review, either comment `@codex review` yourself,
or add `REVIEW_LOOP_REQUEST_TOKEN` to the `review-loop` environment: a
fine-grained personal access token limited to this repository with only
**Pull requests: Read and write**, short expiry. That token posts as you, so
keep it narrow and rotate it ([key-rotation.md](key-rotation.md)).

### 3.6 Branch protection for `main` (Settings → Rules → Rulesets → New branch ruleset)

`main` currently has no protection. Create a ruleset targeting the default
branch with:

- Restrict deletions; block force pushes.
- Require a pull request before merging (required approvals: 0 for a solo
  maintainer; 1+ if others contribute). Require conversation resolution.
- Require status checks to pass, **with the source pinned**:
  - `review-loop/merge-gate` → source: **the review-loop App** (not "any
    source"; pinning is what stops another workflow from forging it);
  - the six CI jobs (`secret scan (gitleaks, full history)`,
    `test (ubuntu-latest, 3.12)`, `test (ubuntu-latest, 3.13)`,
    `test (windows-latest, 3.12)`, `test (windows-latest, 3.13)`,
    `dependency audit (pip-audit)`) → source: GitHub Actions.
- Bypass list: empty. Use §6 if you ever have to merge past the gate.

Add the gate as required only **after** you have seen it publish on a PR, so
an unconfigured App does not block merges unexpectedly.

### 3.7 Labels

Create `review-loop:halted` (the loop stopped for this PR) and
`review-loop:off` (never run the loop on this PR).

## 4. Behaviour

### 4.1 The loop (`review-loop.yml`)

Triggered by Codex's comments (`issue_comment`, pre-filtered on bot id
`199175422`), by Codex reviews (via the relay's `workflow_run`), by CI failures
on PRs, or manually (`workflow_dispatch` with a PR number). Each run re-reads
the PR and decides:

| Situation | Action |
|---|---|
| Not eligible (fork, branch name, author, draft, base) or label `review-loop:off` / `review-loop:halted` | nothing |
| Codex review of the head is pending, missing, or of an older commit | nothing (wait) |
| Codex data is incomplete or inconsistent | one report, no fix |
| Codex completed a clean review of the head | nothing (the gate decides) |
| Unresolved findings, head already claimed | nothing (duplicate event) |
| Unresolved findings, 3 attempts used | halt + report |
| More than 40 findings | halt + report |
| Unresolved findings, attempts left | claim attempt *n* and run the fix |
| CI failed on a commit the loop pushed | halt + report |

A fix attempt ends in one report on the PR:

| Outcome | Halts? |
|---|---|
| Fix pushed, `@codex review` requested | no |
| A finding needs a human (`needs_human`) | yes |
| No change was needed or safe | yes |
| Claude step failed | yes |
| Patch broke the policy | yes |
| Patch failed the test suite | yes |
| Branch moved / claim lost before push | yes |
| Push succeeded but the re-review request failed | yes |

After a push, CI runs on the new commit (the push is made by an App, so it
triggers workflows), Codex reviews it, and the loop repeats until Codex is
clean, an attempt fails, or the three attempts are used.

The loop does not resolve review threads. A finding counts as resolved when
its thread is resolved, by you or by Codex.

### 4.2 The gate (`review-gate.yml`)

Re-evaluated on every PR update, label change, owner or Codex comment, CI
completion, Codex review, and review-thread resolve/unresolve. It publishes `review-loop/merge-gate` on the head commit:
**success** only if all of these hold, otherwise **failure** with the reasons:

1. The PR is eligible (§2).
2. The latest `ci.yml` run for the head SHA (event `pull_request`, this
   repository) completed with `success`, and each of the six required jobs
   succeeded on that SHA.
3. Codex completed a review of the head SHA, its receipt matches, and no Codex
   review thread on the PR is unresolved.
4. Security requirements:
   - label `review-loop:halted` is not set;
   - every changed file could be listed;
   - if the PR changes a sensitive path — `.github/`, `automation/`,
     `scripts/`, `src/qradar_soar_mcp/security/`, `docs/design/0*`,
     `.gitleaks.toml`, `.pre-commit-config.yaml`, `SECURITY.md`,
     `pyproject.toml`, `uv.lock`, `.claude/`, `.claude.json`, `.mcp.json`,
     `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `tests/conftest.py`,
     `tests/fixtures/` or `tests/test_permission_matrix.py` (matched
     case-insensitively) — the repository **owner** has commented, on its own
     line:
     `review-loop: approve-sensitive <full 40-character head SHA>`
     (bound to that commit; a new push needs a new approval);
   - if Codex ran a security review of the head, it completed with no
     unresolved finding.

A new push leaves the new head without a gate result until it is evaluated, so
it is blocked by default.

Because eligibility is part of the gate, a PR from a fork, from a branch name
outside the approved patterns, or from a non-collaborator can never pass it.
To take such a contribution, a maintainer reviews it and pushes it to an
approved branch in this repository, which then goes through the loop and gate
like any other PR.

## 5. Operating

- **Resume after a halt:** read the report, fix or decide by hand, then remove
  `review-loop:halted`. Attempts already used still count.
- **Grant more attempts:** delete the `review-loop:claim:v1` comments of the
  attempts you want back. This is deliberate and visible in the PR history.
- **Re-run a decision:** Actions → `review-loop` or `review-gate` → Run
  workflow → PR number.
- **Approve a sensitive change:** after reviewing it yourself, comment
  `review-loop: approve-sensitive <head sha>` (see §4.2).

## 6. Emergency disable

Fastest first; each step stands alone.

1. **Stop new runs:** set `REVIEW_LOOP_ENABLED` to `false` (or delete it).
   ```bash
   gh variable set REVIEW_LOOP_ENABLED --body false
   ```
2. **Disable the workflows:**
   ```bash
   gh workflow disable review-loop.yml
   gh workflow disable codex-review-relay.yml
   ```
3. **Cancel anything in flight:**
   ```bash
   gh run list --workflow review-loop.yml --status in_progress
   gh run cancel <run-id>
   ```
4. **Cut credentials:** delete `ANTHROPIC_API_KEY` from `review-loop-claude`
   and revoke the key in the Anthropic console; suspend or uninstall the
   review-loop App and delete its private key (Settings → Developer settings →
   GitHub Apps → the App); revoke `REVIEW_LOOP_REQUEST_TOKEN` if you created it.
5. **Undo a bad automated commit:** revert it with a normal commit on the PR
   branch. Never force-push a branch others may have pulled.

Disabling `review-gate.yml`, setting `REVIEW_LOOP_GATE_ENABLED` to anything
but `true`, or breaking the App leaves the required gate
missing, which **blocks merges** — that is the fail-closed design. If you must
merge anyway, that is a human decision: edit the ruleset to drop the gate
temporarily, merge, restore it, and note why in the PR.

## 7. Known unknowns and residual risk

**The model runs in the same process environment as the Anthropic key.** The
official action passes its environment to Claude Code, so a prompt-injected
model that could read `/proc/self/environ` would see the key. The deny rules,
the symlink refusal, the credential scan and the enum-only reports are the
controls; **confirm on the first live run that the deny rules hold** (for
example with a throwaway PR whose finding asks Claude to read
`/proc/self/environ`, and check it is refused). To remove the static key
entirely, use the action's workload identity federation inputs
(`anthropic_federation_rule_id`, `anthropic_organization_id`, with
`id-token: write` on the fix job) instead of `ANTHROPIC_API_KEY`. In any case
use a dedicated key with a spend limit, and rotate it if a run ever looks
wrong. The action also installs Claude Code from the network at run time
inside that job; that is upstream supply chain this repository cannot pin
further than the action's commit.

These were not verifiable before the first live run and fail closed if wrong:

- Codex's comment formats (`codex-review-state:v1`, `codex-review-receipt:v1`,
  `**Reviewed commit:**`) were observed on this repository; no version contract
  from OpenAI was found. A format change makes reviews "incomplete" and blocks
  the gate until `automation/review_loop/codex.py` is updated.
- Whether Codex reviews a commit after a request from an App account (§3.5).
- Whether Codex resolves its own threads when a later review no longer reports
  them; otherwise you resolve them. If Codex's review of the head is clean
  but older threads are still open, the loop posts one report asking you to
  resolve them instead of spending an attempt.
- A Codex security review binds the gate only when its state names the head
  commit; a security review still queued for the head while the state names
  an older commit is not waited for. Codex security review is not a required
  part of this gate.
- The workflows only run from `main`, so the first real exercise is after this
  is merged. Watch the first PR end to end with `REVIEW_LOOP_ENABLED=true`
  before making the gate a required check.
