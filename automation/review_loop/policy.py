"""Fixed policy for the review loop.

Everything here is reviewed through a pull request and read from the default
branch at run time. Nothing in this module is taken from an event payload, a
comment body or a repository variable: a value an attacker can type is never a
trust anchor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AppIdentity:
    """A GitHub App and the bot user it acts as.

    Logins are checked, but never alone: the numeric ids are immutable and the
    ``[bot]`` suffix cannot be registered by a person.
    """

    app_id: int
    app_slug: str
    app_owner: str
    bot_user_id: int
    bot_login: str


# Observed on this repository (PR #11): issue comments carry
# performed_via_github_app.id 1144995, slug chatgpt-codex-connector, owner openai;
# the bot user is chatgpt-codex-connector[bot], id 199175422, type Bot.
CODEX = AppIdentity(
    app_id=1144995,
    app_slug="chatgpt-codex-connector",
    app_owner="openai",
    bot_user_id=199175422,
    bot_login="chatgpt-codex-connector[bot]",
)

# The identity GITHUB_TOKEN acts as. Claim and report comments are written with
# it, and only comments from it count toward the attempt ledger.
GITHUB_ACTIONS = AppIdentity(
    app_id=15368,
    app_slug="github-actions",
    app_owner="github",
    bot_user_id=41898282,
    bot_login="github-actions[bot]",
)

BASE_BRANCH = "main"

# Branches the loop will touch. Same-repository branches only (checked
# separately); never the base branch, never a fork.
APPROVED_BRANCH = re.compile(
    r"^(?:phase[0-9]+|fix|feat|build|docs|test|chore|refactor|automation)/"
    r"[a-z0-9][a-z0-9._-]{0,80}$"
)

# PR authors whose branches the loop may push to.
TRUSTED_AUTHOR_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})

MAX_FIX_ATTEMPTS = 3

# Labels. Adding HALTED stops the loop for the PR; removing it is a human decision.
LABEL_HALTED = "review-loop:halted"
LABEL_OPT_OUT = "review-loop:off"

# Hidden markers written by the automation. They only count when the comment
# was written by GITHUB_ACTIONS (checked by numeric id and app id).
CLAIM_MARKER = "review-loop:claim:v1"
REPORT_MARKER = "review-loop:report:v1"
REREVIEW_MARKER = "review-loop:rereview:v1"

# Trailers on commits the loop pushes.
TRAILER_ATTEMPT = "Review-Loop-Attempt"
TRAILER_REVIEWED = "Review-Loop-Reviewed-Head"

# Commit identity for automation commits (the push itself is authenticated by
# the review-loop GitHub App installation token).
COMMIT_AUTHOR_NAME = "qradar-soar-review-loop"
COMMIT_AUTHOR_EMAIL = "review-loop@users.noreply.github.com"

# The CI workflow whose jobs must all pass on the head commit. The names are
# what GitHub shows for ci.yml's jobs; tests/test_review_loop_workflows.py keeps
# this set equal to the jobs ci.yml actually defines.
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUIRED_CI_JOBS = frozenset(
    {
        "secret scan (gitleaks, full history)",
        "test (ubuntu-latest, 3.12)",
        "test (ubuntu-latest, 3.13)",
        "test (windows-latest, 3.12)",
        "test (windows-latest, 3.13)",
        "dependency audit (pip-audit)",
    }
)

# Name of the required check the merge gate publishes (via the review-loop App).
GATE_CHECK_NAME = "review-loop/merge-gate"

# Paths whose change needs an explicit, commit-bound approval from a repository
# admin before the merge gate can pass, and which an automated fix may never
# touch at all.
# Prefixes are compared case-insensitively (see ``path_matches``): Windows and
# macOS checkouts treat `.GITHUB/` and `.github/` as the same directory.
SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    ".github/",
    "automation/",
    "scripts/",
    "src/qradar_soar_mcp/security/",
    "docs/design/0",
    ".gitleaks.toml",
    ".pre-commit-config.yaml",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
    ".claude/",
    ".claude.json",
    ".mcp.json",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "tests/conftest.py",
    "tests/fixtures/",
    "tests/test_permission_matrix.py",
)

# Paths an automated fix may never touch: the sensitive ones, plus the modules
# that carry deny-by-default behaviour outside security/, the tests that pin the
# repository's guarantees, and anything a tool reads as configuration.
FIX_FORBIDDEN_PATH_PREFIXES: tuple[str, ...] = (
    *SENSITIVE_PATH_PREFIXES,
    ".env",
    ".gitmodules",
    ".gitattributes",
    ".gitignore",
    ".ripgreprc",
    ".husky/",
    ".python-version",
    "LICENSE",
    ".review-loop/",
    "src/qradar_soar_mcp/config.py",
    "src/qradar_soar_mcp/tls.py",
    "src/qradar_soar_mcp/redaction.py",
    "src/qradar_soar_mcp/logging.py",
    "src/qradar_soar_mcp/server.py",
    "src/qradar_soar_mcp/tools/registry.py",
    "src/qradar_soar_mcp/tools/runtime.py",
    "tests/test_ci_hygiene.py",
    "tests/test_repo_hygiene.py",
    "tests/test_secret_leak.py",
    "tests/test_chokepoint.py",
    "tests/test_permissions.py",
    "tests/test_review_loop_",
    "tests/review_loop_data.py",
)


def path_matches(path: str, prefixes: tuple[str, ...]) -> bool:
    """Case-insensitive prefix match; a prefix ending in ``/`` also matches the bare dir."""
    folded = path.casefold()
    for prefix in prefixes:
        p = prefix.casefold()
        if folded == p.rstrip("/") or folded.startswith(p):
            return True
    return False


# Credential shapes that must never appear in anything the fix job produced
# (patch, verdicts) - the model ran next to the Anthropic key.
SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),  # JWT
    re.compile(r"(?i)\bx-access-token:"),
)

# Commit-bound approval of a sensitive change, posted by an admin:
#   review-loop: approve-sensitive <40-hex head sha>
SENSITIVE_APPROVAL = re.compile(r"(?m)^review-loop: approve-sensitive ([0-9a-f]{40})\s*$")

# Size bounds for an automated patch.
MAX_PATCH_FILES = 25
MAX_PATCH_CHANGED_LINES = 1500

# Bounds on what the loop will read from GitHub, so a flood of comments
# cannot make a run unbounded; hitting a bound fails closed.
MAX_PAGES = 30
MAX_FINDINGS = 40
MAX_FINDING_BODY_CHARS = 8000
