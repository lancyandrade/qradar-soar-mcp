# Runbook: local artefact hygiene and retention (SEC-14)

Owner decision 2026-10-29 (08 §32, D19): sensitive development artefacts are excluded
from git and from every package, **audit evidence is retained**, and stale artefacts
are cleaned **only by a human**. Nothing in this repository deletes a file
automatically; the check below only reports.

## 1. What must never reach git or a package

| Artefact | Why sensitive | git | sdist / wheel |
|---|---|---|---|
| `.env`, `.env.*` (not `.env.example`) | SOAR key id and secret | ignored (`.gitignore`) | outside the allow-list |
| `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.crt`, `.local/` | CA bundles, approval private keys, lab certificates | ignored | outside the allow-list; `*.pem`/`*.key` also ignored inside the package |
| `audit.jsonl`, any `*.jsonl`, `approvals/`, `snapshots/`, `lab-evidence/` | audit records hold targets, plans, pre/post images of incidents | ignored | outside the allow-list |
| `.playwright-mcp/` | browser-session logs, page dumps and screenshots, possibly of the SOAR UI and incident data | ignored (added by SEC-14; before, this machine's `.git/info/exclude` only) | outside the allow-list |
| `.claude/settings.local.json`, `.claude/worktrees/` | local tool permissions; complete extra checkouts | ignored (added by SEC-14; before, the global and per-machine ignore files only) | outside the allow-list |
| caches: `.venv/`, `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.hypothesis/`, `.coverage`, `dist/`, `build/` | noise; `.coverage` names local paths | ignored | outside the allow-list |
| raw probe captures `scripts/probe/raw/`, `tests/fixtures/raw/` | unsanitised appliance responses | ignored | outside the allow-list |

Packages: the sdist is an explicit allow-list (`only-include`, release-readiness §12.1)
and the wheel is the package directory only; `tests/test_packaging.py` builds both with
canary files in place. The one residual path is an **untracked file under
`src/qradar_soar_mcp/` that no tracked `.gitignore` ignores**, which both archives
would take. Hatch reads `.gitignore` only, so a file hidden by `.git/info/exclude` or a
global excludes file is still packed (release-readiness H-5). The check below fails on
such a file whatever git's other exclude sources say, and REL-04 (release artefacts
built only in CI from a clean checkout) closes the path.

## 2. The check

```bash
uv run python scripts/check_artifact_hygiene.py
```

Read-only. It fails (exit 1) if a sample of every path above is not ignored by a
`.gitignore` **that git tracks** (a per-machine `.git/info/exclude`, a global ignore
file or an untracked `.gitignore` does not count: the next clone would not have it), if
a tracked file matches a sensitive pattern, or if an untracked file in the package
directory is not ignored by a tracked `.gitignore`.
It then lists, by name, size and age only, the local artefacts this runbook asks a
human to review, and every git worktree. It never opens, prints, moves or deletes a
file. `tests/test_artifact_hygiene.py` runs it in CI and proves those properties.

## 3. Retention rules

| Artefact | Keep | Then (a human, after review) |
|---|---|---|
| **Production audit log** (`SOAR_AUDIT_LOG_PATH`, an absolute path outside the repository) | as long as your incident records, at least one year; never truncate or edit it | rotate only by stopping the server, running `qradar-soar-audit verify`, archiving the whole file read-only with its SHA-256, and starting a new file |
| **Lab audit evidence** (`SOAR_TEST_EVIDENCE_DIR`, e.g. `lab-evidence/`) | until the release it supports is superseded, and at least one year | archive with the release record; never edit |
| **Repository-root `audit.jsonl`** left by local runs (release-readiness L-2) | while it holds any record | an empty file may be removed; a non-empty one is verified and archived like a lab log, never just deleted |
| **Approval requests and records** (`SOAR_APPROVAL_BROKER_PATH`) | as long as the audit records that name them | archive together with the audit log |
| **Browser artefacts** (`.playwright-mcp/`) | no longer than needed, at most 14 days | review that nothing is needed as evidence, then delete; never attach to an issue or PR, never paste |
| **Git worktrees** (`git worktree list`) | while their branch is unmerged or has uncommitted work | `git worktree remove <path>` only after `git -C <path> status` is clean and the branch is merged; never `rm -rf` a worktree |
| **Caches and build outputs** | any time | may be deleted freely; they are regenerated |
| **`.env`, keys, `.local/` certificates** | while in use | if one was ever exposed, rotate it first ([key-rotation.md](key-rotation.md)), then delete the copy |

## 4. Reviewing a working copy

Run the check without `--quiet` to see what is on your machine now: it lists the
artefacts of §3 by name, size and age, and every worktree with its branch. Decide each
one under §3 yourself; the check acts on nothing. The state of any one machine is not
recorded in this repository.
