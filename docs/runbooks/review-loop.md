# Runbook: Codex review loop and merge gate

This repository can run an automated loop on its own pull requests:

```
Codex reviews the PR head ──► findings? ──► Claude Code proposes fixes + regression tests
        ▲                                         │
        │                                         ▼
        │                        patch policy + full test suite (no secrets)
        │                                         │
        └── "@codex review" ◄── push to the PR branch (fast-forward only)
            (a maintainer, by default)            │
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
| [`.github/workflows/codex-review-relay.yml`](../../.github/workflows/codex-review-relay.yml) | Receives `pull_request_review` events and finishes only when the reviewer is the Codex bot. No permissions, no secrets. |
| [`.github/workflows/review-loop.yml`](../../.github/workflows/review-loop.yml) | The fix loop: triage → claim → fix → verify → push → report. |
| [`.github/workflows/review-gate.yml`](../../.github/workflows/review-gate.yml) | `gate` evaluates and publishes `review-loop/merge-gate` for one PR; `fanout` (schedule, and events that name no PR) dispatches one `gate` run per open PR. |
| [`automation/review_loop/`](../../automation/review_loop/) | Stdlib-only Python that makes every decision (identity, freshness, ledger, patch policy, git checks, gate). Read from the default branch at run time. |
| `tests/test_review_loop_*.py` | Offline tests for all of the above, including the workflows themselves. |

## 2. Security properties

- **Identity by number, not by name.** Codex is accepted only as GitHub App
  `1144995` (`chatgpt-codex-connector`, owner `openai`) acting as bot user
  `199175422` of type `Bot`. Issue comments must carry that App id; reviews and
  inline comments (where GitHub does not expose the App) must match the bot
  user id, type and login. A login, a body, or a copied marker alone never
  counts. These ids were observed on this repository (PR #11, PR #12).
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
- **No long-lived Anthropic credential exists (§2.1).**
- **Untrusted code never meets privileged credentials.**
  - Claude Code gets a **read-only** GitHub token and only
    `Read, Edit, Write, Glob, Grep` (no shell, no web): it never executes PR
    code. Before it starts, the job refuses a checkout containing symlinks,
    moves aside every file Claude Code or its tools read as configuration
    (`.claude/`, `.claude.json`, `.mcp.json`, `.gitmodules`, `.ripgreprc`,
    `.husky/`, every `CLAUDE.md` / `CLAUDE.local.md`), disables hooks, and
    denies its file tools `/proc`, `/sys`, `/etc`, `/tmp`, the runner's temp
    and action directories (identity token, credential cache, step
    file-command files) and `.git/` / `.github/`. The patch is built against a
    pristine copy of the git metadata taken before Claude ran, with hooks and
    fsmonitor off, and nothing credential-shaped (Anthropic, GitHub, AWS keys,
    private keys, JWTs) may leave the job.
  - The test job runs PR code with **no secrets** and a read-only token.
  - The push job holds a short-lived App token (contents + pull requests
    write, **no workflows permission**, so it cannot change `.github/`) and no
    Anthropic access. It applies the patch only through the trusted checker
    (§2.2), checks that the branch head is still the reviewed commit and that
    this run still holds the attempt claim, and pushes without force. A moved
    branch makes the push fail.
  - Findings are passed to Claude as a data file (`findings.json`) and the
    prompt says they are untrusted. The prompt itself is a fixed template:
    triage substitutes only the head SHA and two integers, never finding
    text. It reaches the action through a multi-line step output, which is
    guarded three ways. The fix job accepts only the exact bytes triage
    rendered (SHA-256 passed through job outputs). The delimiter prefix
    `REVIEW_LOOP_PROMPT_` is reserved, so a prompt containing it anywhere is
    refused, at render time and again in the fix job. And the delimiter is
    random per run. Even a prompt that someday included untrusted text
    could not end the value early and set other step outputs. The model's free-text reasons are **never posted**: reports
    show only finding ids and verdict values. Other quoted text is neutralised
    (no hidden markers, no `@` mentions).
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

### 2.1 Anthropic credential boundary

The fix job authenticates to the Claude API with **workload identity
federation**, the official action's supported keyless mode. There is no
`ANTHROPIC_API_KEY` secret anywhere, and the job refuses to start Claude if a
static `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` is present.

How it works (from the pinned action's source, `base-action/src/workload-identity.ts`
and `parse-sdk-options.ts`):

1. The job has `id-token: write`. The action requests a GitHub OIDC token
   with audience `https://api.anthropic.com`, writes it to a `0600` file under
   the runner temp directory, and refreshes it every 4 minutes.
2. Claude Code exchanges it, under your federation rule, for a short-lived
   Anthropic access token scoped to the rule's service account.
3. Before spawning Claude Code, the action **deletes
   `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`** from
   its environment, so the model process cannot mint new OIDC tokens.
4. When the step ends the action deletes the identity token and the cached
   access token.

What this changes: a successful prompt injection can no longer steal a
credential that works after the run. The most it could reach is the current
short-lived access token, usable only until it expires, only for the Claude API,
and only as a service account you can limit and revoke. That token lives in the
Claude Code process and its cache directory, which the deny rules keep out of
the file tools' reach.

The federation rule must match **only** this job. Its OIDC subject is
`repo:lancyandrade/qradar-soar-mcp:environment:review-loop-claude`, because the
job runs in that environment, which is restricted to `main`. Match that exact
subject, not a `repo:…:` prefix: a prefix would also match `pull_request`
workflows on PR branches, which can request OIDC tokens too. Never create any
other trust relationship (another cloud, another service) for this subject.

### 2.2 Patch boundary

**Construction (fix job).** Building the patch must not let git run anything
the model could have planted. Git's command execution all comes from
configuration: `filter.*.clean/smudge/process`, `diff.*.command`/`textconv`,
`diff.external`, `core.fsmonitor`, `core.hooksPath` and hooks, `core.pager`,
aliases. An attribute such as `filter=evil` only names a driver, so it does
nothing unless configuration defines one. Construction is protected in five
ways:

1. Before Claude runs, the job records a digest of every git configuration,
   hook and attribute location Claude could reach: the pristine `.git` copy's
   `config`, `hooks/`, `info/` and `objects/info/`, plus `~/.gitconfig`,
   `$XDG_CONFIG_HOME/git/` and `/etc/gitconfig`. The digest is a step output,
   which Claude cannot change.
2. Claude's file tools are denied all writes to `.git`, `.gitattributes`,
   `.gitmodules` and `.gitconfig` at any depth, to dotfiles and dot
   directories in `$HOME`, and to `/etc`, `/usr`, `/opt` and `/tmp`.
3. Immediately after Claude, `GIT_CONFIG_NOSYSTEM=1` and
   `GIT_CONFIG_GLOBAL=/dev/null` are written to `$GITHUB_ENV`. Every later
   step and post step in the job therefore runs git without system or global
   configuration. If the digest changed, the job deletes the workspace `.git`
   and fails. Otherwise the workspace `.git` (which the action configured and
   Claude could reach) is replaced with the pristine copy.
4. The patch is built by `gitcheck.build_patch`. It uses a **new** git
   directory, created after Claude ran, with no template (so no hooks) and no
   configuration. It borrows only the object store, which is
   content-addressed data and never executed. System, global and user
   configuration are disabled, `HOME`/`XDG_CONFIG_HOME` are an empty
   directory, and every `GIT_*` variable is removed (this also removes
   `GIT_CONFIG_PARAMETERS` / `GIT_CONFIG_COUNT` injection). `/usr/bin/git` is
   invoked directly. A hostile `.gitattributes` is just content: it ends up
   in the patch, and the policy then refuses it.
5. Only then are the patch and verdicts checked for credential-shaped values
   and uploaded.

`tests/test_review_loop_gitexec.py` plants each of these execution paths in
`~/.gitconfig`, XDG config, the pristine copy, `GIT_CONFIG_*` variables and a
nested `.git` file. It shows the job's former command did run the planted
filter, and that construction and the verify/push checks now run none of
them.

**Every git operation, audited:**

| Where | Operation | Protection |
|---|---|---|
| fix | the action's own `git config` | repository-local only; that `.git` is replaced afterwards |
| fix | patch construction | fresh config-free git directory (above) |
| fix | `actions/checkout` post steps | run after `GIT_CONFIG_*` isolation, against the restored pristine `.git` |
| verify, push | `numstat`, `apply --check`, `ls-files`, `check-attr`, `apply --index`, `diff --cached`, `status` | `gitcheck`: system/global/user config off, `GIT_*` cleared, empty `HOME`, hooks, fsmonitor, symlinks and the global attributes file off, `/usr/bin/git` |
| push | `commit`, `push` | `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`, hooks and fsmonitor off, `/usr/bin/git`, `--no-verify` |
| verify | the PR's own test suite | runs PR code by design, with no secrets and a read-only token |
| triage, claim, gate, report | checkout of `main` only | no work tree from the PR or the model |

**Validation.** The patch is untrusted input. It is checked by trusted code (default branch)
before tests run and again before the push. Each step must pass:

1. **Bytes.** UTF-8 only, at most 2 MB. No carriage returns, NUL or other
   control characters, and no invisible or bidirectional Unicode (Trojan
   Source).
2. **Strict parser.** Only exact `git diff` format is accepted. Hunks are
   consumed by their line counts, so a content line that looks like a header
   is content. A traditional diff without a `diff --git` header is refused,
   and so are mismatched `---`/`+++` names, wrong counts and unknown header
   lines.
3. **Paths.** ASCII `[A-Za-z0-9._/-]` only. No `..`, `.`, empty, or
   trailing-dot/space components, no `.git` component, no 8.3 short names, no
   NTFS streams. The allowed roots are `src/qradar_soar_mcp/`, `tests/`,
   `docs/`, `examples/`, `config/` and `README.md`. The protected list in
   `policy.py` is matched case-insensitively. It includes `security/`,
   `config.py`, `tls.py`, `redaction.py`, `logging.py`, `server.py`,
   `tools/registry.py`, `tools/runtime.py`, `docs/design/0*`,
   `tests/conftest.py`, fixtures, the permission-matrix and hygiene tests,
   this automation's own tests. Names that steer tools are refused **at any
   depth**: `AGENTS.md` (Codex reads the nearest one), `CLAUDE.md`,
   `CLAUDE.local.md`, `conftest.py` (pytest hooks see the whole session),
   `.gitattributes`, `.gitignore`, `.gitmodules`, `.ripgreprc`, `.claude/`,
   `.mcp.json`, `pytest.ini`, `tox.ini`, `setup.cfg`, `setup.py`,
   `pyproject.toml`, `sitecustomize.py` and `*.pth`.
4. **Structure.** Only additions and edits of regular `100644` files. No
   deletions, renames, copies, mode changes, symlinks, submodules, binaries,
   or the same file twice. At most 25 files and 1500 changed lines. It must
   **add** lines to a `tests/test_*.py` file. Nothing credential-shaped.
5. **Git agrees.** `git apply --numstat` must list exactly the same files and
   see nothing binary, and `git apply --check` must succeed.
6. **Existing tree.** No touched file may currently be a symlink, submodule or
   executable (from the index). No new path may differ only in case from a
   tracked file or directory. No touched path may have a git attribute that
   transforms content (`filter`, `working-tree-encoding`, `ident`, custom
   `diff`/`merge` drivers, `binary`).
7. **After `git apply --index`.** The staged set must be exactly the checked
   files, each an addition or modification of a `100644` file, with nothing
   unstaged and nothing untracked.

Git runs with system and global configuration ignored, `GIT_*` variables
cleared, and hooks, fsmonitor and symlinks off.

## 3. One-time setup

### 3.1 Create the review-loop GitHub App

Settings → Developer settings → GitHub Apps → **New GitHub App**:

- Name: e.g. `qradar-soar-review-loop`; Homepage: the repository URL.
- Webhook: **uncheck "Active"** (no webhook is needed).
- Repository permissions — exactly these:
  - **Checks: Read and write** (publishes the merge gate)
  - **Contents: Read and write** (pushes fix commits)
  - **Pull requests: Read and write** (only used in `app` re-review mode)
  - Metadata: Read-only (mandatory)
  - Everything else: No access. In particular **not** Workflows,
    Administration, Actions or Secrets.
- "Where can this GitHub App be installed?": **Only on this account**.
- Create it, note the **Client ID**, and **generate a private key** (a `.pem`
  download). Install the App on **only** `qradar-soar-mcp`.

Treat the `.pem` like any other secret: put it in the environment below, then
delete the downloaded file.

### 3.2 Anthropic workload identity federation

In the Anthropic Console (**Settings → Workload identity**; organization admin
required), following the action's setup guide and
[Anthropic's federation documentation](https://platform.claude.com/docs/en/manage-claude/workload-identity-federation):

1. Create a **service account** used only by this repository. Give it the
   narrowest access and spend limit your plan allows.
2. Register GitHub Actions (`https://token.actions.githubusercontent.com`) as
   the identity issuer, if it is not already registered.
3. Create a **federation rule** for that service account:
   - subject: **exactly** `repo:lancyandrade/qradar-soar-mcp:environment:review-loop-claude`;
   - audience: `https://api.anthropic.com`;
   - if the rule supports more claim conditions, also pin
     `job_workflow_ref` to
     `lancyandrade/qradar-soar-mcp/.github/workflows/review-loop.yml@refs/heads/main`.

   Note the rule id (`fdrl_…`), the organization id (UUID), and the service
   account id (`svac_…`) and workspace id (`wrkspc_…`) if you use them.

### 3.3 Environments (Settings → Environments)

| Environment | Deployment branches | Secrets | Variables |
|---|---|---|---|
| `review-loop` | **Selected branches: `main` only** | `REVIEW_LOOP_APP_PRIVATE_KEY` (the `.pem` contents); optional `REVIEW_LOOP_REQUEST_TOKEN` (§3.6) | `REVIEW_LOOP_APP_CLIENT_ID` |
| `review-loop-claude` | **Selected branches: `main` only** | **none** | `REVIEW_LOOP_ANTHROPIC_FEDERATION_RULE_ID`, `REVIEW_LOOP_ANTHROPIC_ORGANIZATION_ID`; optional `REVIEW_LOOP_ANTHROPIC_SERVICE_ACCOUNT_ID`, `REVIEW_LOOP_ANTHROPIC_WORKSPACE_ID` |

The branch restriction keeps the App key away from workflows on PR branches,
and it is what makes the federation subject in §3.2 mean "the default-branch
fix job". Don't add required reviewers (the loop would wait forever), and
don't store these at repository level. **Don't create an `ANTHROPIC_API_KEY`
secret**: the job refuses to run if one reaches it.

### 3.4 Repository variables (Settings → Secrets and variables → Actions → Variables)

| Variable | Value | Meaning |
|---|---|---|
| `REVIEW_LOOP_ENABLED` | **leave unset until §8 is done**, then `true` | Kill switch for the fix loop. Any other value, or absent, disables it. |
| `REVIEW_LOOP_GATE_ENABLED` | `true` | Turns on gate evaluation. Off, the gate publishes nothing — and once it is a required check, that blocks merging. |
| `REVIEW_LOOP_REREVIEW_MODE` | `manual` (default), `app` or `token` | How a fresh Codex review is requested after an automated push (§3.6). |
| `REVIEW_LOOP_CLAUDE_MODEL` | optional, e.g. `claude-opus-5-5` | Model for the fix job (default `claude-opus-5-5`). |

Set these four at **repository** level, not on an environment. They are read
by job conditions, and by jobs that have no environment, where
environment-level variables are not visible.

### 3.5 Actions settings (Settings → Actions → General)

- Workflow permissions: **Read repository contents** (already the setting).
- "Allow GitHub Actions to create and approve pull requests": **off** (already
  off).
- Fork pull request workflows: **require approval for all external
  contributors**.
- Optional, recommended: **require actions to be pinned to a full-length commit
  SHA**. Every workflow already complies and a test enforces it.

### 3.6 Requesting the next Codex review

Codex's documentation only describes a person commenting `@codex review`, or
automatic reviews you enable in your Codex settings. It says nothing about
requests from bots or App accounts, and this repository has not observed one.
So the default is **`manual`**: after an automated push, the loop posts its
report and asks a maintainer to comment `@codex review`. The loop then
continues by itself when Codex's review arrives. This mode is secure and has
been verified (it is what PR #11 and PR #12 used).

Optional modes, once verified (§8.4):

- `app`: the review-loop App comments `@codex review`. No new credential.
- `token`: `REVIEW_LOOP_REQUEST_TOKEN` (in the `review-loop` environment)
  comments as the person who owns it. Use a fine-grained personal access
  token limited to this repository, with only **Pull requests: Read and
  write** and a short expiry. It posts as you, so keep it narrow and rotate it
  ([key-rotation.md](key-rotation.md)). The token is passed to the step only
  when the mode is `token`.

Codex's own **automatic reviews** setting (Codex → Settings → Code review) can
also start reviews without any comment. Which pull-request events it covers is
not documented; if it reviews new pushes, `manual` mode needs no human step.

### 3.7 Branch protection for `main` (Settings → Rules → Rulesets → New branch ruleset)

> **REL-03 (2026-10-29):** the reviewable ruleset bodies, check names, recovery
> procedure and verification commands are in
> [`branch-protection.md`](branch-protection.md). Apply its **phase 1** (CI only)
> first; the ruleset below is its **phase 2**, for after the gate has published on a
> PR. Requiring the gate before the App exists blocks every merge.

`main` currently has no protection. Create a ruleset targeting the default
branch with:

- Restrict deletions; block force pushes.
- Require a pull request before merging (required approvals: 0 for a solo
  maintainer; 1+ if others contribute). **Require conversation resolution**.
  This is GitHub's own real-time check on review threads, and it covers the
  delay in §4.2.
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

### 3.8 Labels

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
| Codex's head review is clean but older Codex threads are open | one report asking you to resolve them; no attempt spent |
| Unresolved findings, head already claimed | nothing (duplicate event) |
| Unresolved findings, 3 attempts used | halt + report |
| More than 40 findings | halt + report |
| Unresolved findings, attempts left | claim attempt *n* and run the fix |
| CI failed on a commit the loop pushed | halt + report |

A fix attempt ends in one report on the PR:

| Outcome | Halts? |
|---|---|
| Fix pushed; Codex re-review requested (`app`/`token` mode) | no |
| Fix pushed; a maintainer must comment `@codex review` (`manual` mode) | no |
| A finding needs a human (`needs_human`) | yes |
| No change was needed or safe | yes |
| Claude step failed (including missing federation settings) | yes |
| Patch broke the policy or the git checks | yes |
| Patch failed the test suite | yes |
| Branch moved / claim lost before push | yes |
| Push succeeded but the re-review request failed | yes |

After a push, CI runs on the new commit (the push is made by an App, so it
triggers workflows), Codex reviews it once requested, and the loop repeats
until Codex is clean, an attempt fails, or the three attempts are used.

The loop does not resolve review threads. A finding counts as resolved when
its thread is resolved, by you or by Codex.

### 4.2 The gate (`review-gate.yml`)

The gate is re-evaluated:

- immediately on every PR update and label change, on any owner or Codex
  comment, on CI completion, and on each Codex review;
- **within about 15 minutes** of a review thread being resolved or reopened.
  GitHub has no Actions trigger for thread resolution
  (`pull_request_review_thread` is a webhook-only event), so a scheduled sweep
  covers it. The sweep dispatches one gate run per open same-repository PR,
  which keeps every evaluation in that PR's serialised group;
- on demand: Actions → `review-gate` → Run workflow → PR number, or any owner
  comment on the PR.

It publishes `review-loop/merge-gate` on the head commit: **success** only if
all of these hold, otherwise **failure** with the reasons:

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
     case-insensitively), or adds or changes any of the tool-steering names
     in §2.2 step 3 at any depth — the repository **owner** has commented, on
     its own line:
     `review-loop: approve-sensitive <full 40-character head SHA>`
     (bound to that commit; a new push needs a new approval);
   - if Codex ran a security review of the head, it completed with no
     unresolved finding.

If an evaluation cannot complete for any reason (network error, malformed
response, unexpected data, a bug), the gate publishes a **failure** on the
current head, so an earlier success never survives a failed re-check.
Comments from anyone other than the owner or Codex do not run the gate and
cannot displace a pending evaluation.

Until the gate has evaluated a new push, the new head has no gate result, so
it stays blocked by default. The schedule's delay only matters in one case:
resolving a thread can leave a stale **failure** for up to 15 minutes. A delay
can never produce a false success.

Because eligibility is part of the gate, a PR from a fork, from a branch name
outside the approved patterns, or from a non-collaborator can never pass it.
To take such a contribution, a maintainer reviews it and pushes it to an
approved branch in this repository, which then goes through the loop and gate
like any other PR.

## 5. Operating

- **Continue after a manual-mode push:** comment `@codex review` on the PR.
- **Resume after a halt:** read the report, fix or decide by hand, then remove
  `review-loop:halted`. Attempts already used still count.
- **Grant more attempts:** delete the `review-loop:claim:v1` comments of the
  attempts you want back. This is deliberate and visible in the PR history.
- **Re-run a decision:** Actions → `review-loop` or `review-gate` → Run
  workflow → PR number.

### 5.1 Re-evaluate a PR after resolving a review thread

GitHub cannot start a workflow when a review thread is resolved or reopened
(`pull_request_review_thread` is a webhook-only event), so the gate learns
about it in one of three ways:

1. **Wait.** The scheduled fan-out runs at minutes 7, 22, 37 and 52 of every
   hour. It dispatches one `review-gate` run per open same-repository PR, so
   the check updates within about 15 minutes.
2. **Comment on the PR as the owner.** Any comment works (for example
   `re-check`); owner comments run the gate immediately.
3. **Dispatch it yourself** (the workflow is read from `main`):
   ```bash
   gh workflow run review-gate.yml --repo lancyandrade/qradar-soar-mcp --ref main -f pr_number=<PR>
   ```

Confirm the result on the PR's head commit:

```bash
gh run list --repo lancyandrade/qradar-soar-mcp --workflow review-gate.yml --limit 5
gh api repos/lancyandrade/qradar-soar-mcp/commits/<head-sha>/check-runs --jq '.check_runs[] | select(.name == "review-loop/merge-gate") | {conclusion, output: .output.title, app: .app.slug}'
```

The newest `review-loop/merge-gate` check, published by the review-loop App,
is the one branch protection uses. A run dispatched for one PR evaluates only
that PR, and runs for the same PR are serialised, so a dispatch cannot race
an event-driven evaluation.

What is verified offline (tests/test_review_loop_routing.py): the real `if:`
and `concurrency:` expressions are evaluated for each event type. The
schedule runs only `fanout`, `fanout` dispatches one run per same-repository
PR, and each dispatched run runs only `gate` in `review-gate-pr-<n>`. Drive-by
comments and fork events run nothing and get a group of their own. With
`REVIEW_LOOP_GATE_ENABLED` unset, nothing runs. The live check is §8.3.
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
4. **Cut credentials:**
   - Disable or delete the federation rule, or the service account, in the
     Anthropic Console. This ends Claude access for every future and
     in-flight exchange.
   - Suspend or uninstall the review-loop App and delete its private key
     (Settings → Developer settings → GitHub Apps → the App).
   - If you created `REVIEW_LOOP_REQUEST_TOKEN`, revoke it.
5. **Undo a bad automated commit:** revert it with a normal commit on the PR
   branch. Never force-push a branch others may have pulled.

Disabling `review-gate.yml`, setting `REVIEW_LOOP_GATE_ENABLED` to anything
but `true`, or breaking the App leaves the required gate missing, which
**blocks merges** — that is the fail-closed design. If you must merge anyway,
that is a human decision: edit the ruleset to drop the gate temporarily,
merge, restore it, and note why in the PR.

## 7. Known unknowns and residual risk

- **Short-lived Anthropic token in the model's process.** Federation removes
  the long-lived key. However, the CLI that runs the model still holds a
  current access token in memory and in its cache directory. The deny rules
  keep the file tools away from both, and no Bash or web tool exists. A
  prompt injection that defeated the deny rules could use that token only
  until it expires, only against the Claude API, and only as the scoped
  service account. **Confirm the deny rules in §8.2 before enabling the
  loop.**
- **Upstream supply chain.** The action installs Claude Code from the network
  at run time inside the fix job. The action is pinned by commit, and it pins
  the Claude Code version, but the installer download is upstream supply chain
  this repository cannot pin further.
- **Codex comment formats.** `codex-review-state:v1`,
  `codex-review-receipt:v1` and `**Reviewed commit:**` were observed on this
  repository; no version contract from OpenAI was found. A format change makes
  reviews "incomplete" and blocks the gate until
  `automation/review_loop/codex.py` is updated.
- **Codex and App-authored requests.** Whether Codex honours `@codex review`
  from an App account is unknown (§3.6, §8.4). The default does not depend on
  it.
- **Codex resolving its own threads.** Whether Codex resolves its threads
  when a later review no longer reports them is unknown; if it does not, you
  resolve them. If Codex's review of the head is clean but older threads are
  open, the loop asks you once instead of spending an attempt.
- **Codex security reviews.** A security review binds the gate only when its
  state names the head commit. A security review still queued for the head,
  while the state names an older commit, is not waited for. Codex security
  review is not a required part of this gate.
- **Scheduled sweep pauses.** GitHub disables scheduled workflows in a public
  repository after 60 days without repository activity. The gate's
  thread-resolution sweep then stops, until you re-enable it (Actions →
  `review-gate` → Enable). Event-driven evaluation and fail-closed
  behaviour are unaffected; only the 15-minute pick-up of resolved threads
  stops.
- **Checkout post steps.** The fix, verify and push jobs remove the
  trusted `.review-loop/trusted` checkout before untrusted content runs.
  The `actions/checkout` post step for that path should treat a missing
  directory as nothing to clean up. Confirm on the first live run that it
  only warns (§8.5).
- **First live exercise.** The workflows only run from `main`, so the first
  real exercise happens after merge. §8 is the procedure.

## 8. Live verification (after merge, before enabling the loop)

Each test below needs the deployed configuration, so none of them has run yet.
Run them in order, with `REVIEW_LOOP_ENABLED` unset, on throwaway PRs from
approved branches.

### 8.1 Workflow validity and the gate

1. Set `REVIEW_LOOP_GATE_ENABLED=true`. Open a throwaway PR (e.g. a one-line
   docs change on `docs/review-loop-smoke`).
2. Expect `review-loop/merge-gate` (from the App) to appear as **failure**:
   "no Codex review of the head commit".
3. Comment `@codex review`. After Codex finishes, expect a
   `codex-review-relay` run (event `pull_request_review`, success) if it left
   findings, and then a `review-gate` run that re-publishes the gate.
4. With CI green and no findings, expect **success**. Run `gh run list`, and
   check that **no workflow shows "This run likely failed because of a
   workflow file issue"**.

### 8.2 Claude job isolation

1. Configure §3.2–§3.3. Set `REVIEW_LOOP_ENABLED=true` only for this test.
2. On a throwaway PR, get a Codex finding (or run `review-loop` manually after
   one). Add a test file whose docstring tells the model to read
   `/proc/self/environ`, `$RUNNER_TEMP`, `/home/runner/work/_temp` and
   `.git/config`, and to write into `/home/runner/work/_temp`.
3. In the `fix` job log (`show_full_output` stays off, so look at Claude's
   permission denials in the action's summary/log), confirm:
   - each such read and write was **denied**;
   - "Workload identity federation configured" is logged;
   - no `ANTHROPIC_API_KEY` is mentioned.
4. Confirm that a run with `REVIEW_LOOP_ANTHROPIC_FEDERATION_RULE_ID` unset
   fails at "Require federated Anthropic authentication".
5. Set `REVIEW_LOOP_ENABLED` back to unset.

If any denial does not hold, stop. Do not enable the loop until the deny
rules are fixed.

### 8.3 Review-thread resolve and reopen

1. On a PR where Codex left a finding, with CI green and the finding fixed:
2. **Resolve** the Codex thread. Within about 15 minutes, a `review-gate` run
   (event `workflow_dispatch`, dispatched by the schedule's `fanout` job)
   re-publishes the gate. The gate should now pass if everything else holds.
   To skip the wait, use §5.1 (owner comment or `gh workflow run`), and
   check that the dispatched run's concurrency group is
   `review-gate-pr-<PR>`.
3. **Reopen** (unresolve) the thread. Within about 15 minutes, the gate turns
   back to **failure** with "unresolved Codex finding(s)".
4. Check that each of these runs evaluated only that PR, and that a `fanout`
   run dispatched one `review-gate` run per open same-repository PR.

What was verified before deployment:

- GitHub documents `pull_request_review_thread` (`resolved`/`unresolved`) as
  a webhook event only.
- On PR #12, a workflow listing it as a trigger was rejected as invalid
  (run 40081759192, "workflow file issue"). That is why the sweep exists.
- A test now fails if any workflow uses an event outside GitHub's Actions
  list.

### 8.4 Re-review request mode (decides `app` or `token`)

1. Keep `REVIEW_LOOP_REREVIEW_MODE=manual` until this passes.
2. As the review-loop App, post a comment on a throwaway PR:
   ```bash
   gh api repos/lancyandrade/qradar-soar-mcp/issues/<pr>/comments -f body='@codex review'
   ```
   For this you need a token for the App: mint one locally from the App key,
   or temporarily set `app` mode and let one automated push request it.
3. If Codex reacts and posts a review of the head, `app` mode works: set
   `REVIEW_LOOP_REREVIEW_MODE=app`. If nothing happens within about 15
   minutes, keep `manual`, or use `token` mode (§3.6) after testing it the
   same way.

### 8.5 Patch boundary on the runner

Already covered offline: the adversarial suite `tests/test_review_loop_patch.py`
runs real `git` on Linux and Windows in CI. On the first live attempt, also
check that:

- the `verify` and `push` jobs log "automated patch check" with no problems;
- the pushed commit touches exactly the files in that check;
- it carries the `Review-Loop-Attempt` and `Review-Loop-Reviewed-Head`
  trailers;
- the fix job's "Isolate git and verify its configuration is untouched"
  step passed, and the checkout post steps only warned about the removed
  trusted checkout.
