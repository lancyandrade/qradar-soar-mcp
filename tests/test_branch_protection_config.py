"""REL-03: the proposed `main` rulesets stay in step with the CI they require.

Offline: reads ``.github/workflows/ci.yml`` and the JSON bodies under
``docs/runbooks/rulesets/``. Nothing here talks to GitHub or applies a setting.
"""

from __future__ import annotations

import itertools
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
RULESETS = ROOT / "docs" / "runbooks" / "rulesets"
RUNBOOK = ROOT / "docs" / "runbooks" / "branch-protection.md"
GITHUB_ACTIONS_APP_ID = 15368  # observed on this repository's check runs
MERGE_GATE = "review-loop/merge-gate"


def _ci_check_names() -> set[str]:
    """Each ci.yml job's display name, expanded over its matrix as GitHub does."""
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    names: set[str] = set()
    for job_id, job in ci["jobs"].items():
        template = job.get("name", job_id)
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        if not matrix:
            names.add(template)
            continue
        keys = list(matrix)
        for combo in itertools.product(*(matrix[k] for k in keys)):
            values = dict(zip(keys, combo, strict=True))
            if "${{" in template:
                name = re.sub(
                    r"\$\{\{\s*matrix\.(\w+)\s*\}\}",
                    lambda m, v=values: str(v[m.group(1)]),
                    template,
                )
            else:  # GitHub's default: "<job> (<v1>, <v2>)"
                name = f"{template} ({', '.join(str(v) for v in combo)})"
            names.add(name)
    return names


def _load(name: str) -> dict[str, Any]:
    return json.loads((RULESETS / name).read_text(encoding="utf-8"))


def _rules(ruleset: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["type"]: r.get("parameters", {}) for r in ruleset["rules"]}


def test_ci_check_names_are_the_six_expected():
    assert _ci_check_names() == {
        "secret scan (gitleaks, full history)",
        "test (ubuntu-latest, 3.12)",
        "test (ubuntu-latest, 3.13)",
        "test (windows-latest, 3.12)",
        "test (windows-latest, 3.13)",
        "dependency audit (pip-audit)",
    }


@pytest.mark.parametrize("name", ["main-phase1.json", "main-phase2-merge-gate.json"])
def test_main_rulesets_protect_main(name: str):
    ruleset = _load(name)
    assert ruleset["target"] == "branch" and ruleset["enforcement"] == "active"
    assert ruleset["conditions"]["ref_name"] == {"include": ["~DEFAULT_BRANCH"], "exclude": []}
    assert ruleset["bypass_actors"] == []
    rules = _rules(ruleset)
    assert {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} <= set(rules)
    assert "required_linear_history" not in rules  # merge commits are the merge method
    pr = rules["pull_request"]
    assert pr["required_review_thread_resolution"] is True
    assert pr["allowed_merge_methods"] == ["merge"]
    checks = rules["required_status_checks"]
    assert checks["strict_required_status_checks_policy"] is True
    ci = {c["context"]: c["integration_id"] for c in checks["required_status_checks"]}
    assert {k for k in ci if k != MERGE_GATE} == _ci_check_names()
    assert all(ci[k] == GITHUB_ACTIONS_APP_ID for k in _ci_check_names())


def test_phase1_does_not_require_the_unconfigured_merge_gate():
    contexts = [
        c["context"]
        for c in _rules(_load("main-phase1.json"))["required_status_checks"][
            "required_status_checks"
        ]
    ]
    assert MERGE_GATE not in contexts


def test_phase2_gate_is_pinned_to_a_placeholder_never_to_actions():
    checks = _rules(_load("main-phase2-merge-gate.json"))["required_status_checks"]
    gate = [c for c in checks["required_status_checks"] if c["context"] == MERGE_GATE]
    assert len(gate) == 1
    # A string placeholder: the API refuses the body until the App id is filled in,
    # and the gate can never be pinned to GitHub Actions (which any workflow can use).
    assert gate[0]["integration_id"] == "REPLACE_WITH_REVIEW_LOOP_APP_ID"


def test_release_tags_are_immutable():
    ruleset = _load("release-tags.json")
    assert ruleset["target"] == "tag" and ruleset["bypass_actors"] == []
    assert ruleset["conditions"]["ref_name"]["include"] == ["refs/tags/v*"]
    assert {"deletion", "update", "non_fast_forward"} <= set(_rules(ruleset))


def test_runbook_lists_every_required_check_and_applies_nothing_itself():
    text = RUNBOOK.read_text(encoding="utf-8")
    for name in _ci_check_names() | {MERGE_GATE}:
        assert f"`{name}`" in text, name
    assert "prepared for review, not applied" in text
    assert "not run by this change" in text
