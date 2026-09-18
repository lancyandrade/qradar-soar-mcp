"""P1-16: the documentation states what the code does, checked mechanically.

The README's flag table, tool table, projection field list, budgets and
defaults are compared with the code they describe; every SOAR API claim
carries a confidence mark; every relative link resolves.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from qradar_soar_mcp.config import CAPABILITY_FLAGS, Settings
from qradar_soar_mcp.security.tiers import CAPABILITY_TIERS
from qradar_soar_mcp.tools import TOOL_REGISTRY
from qradar_soar_mcp.tools.investigation import FULL_INCIDENT_BUDGET_CHARS, FULL_INCIDENT_CAPS
from qradar_soar_mcp.tools.projection import (
    ARTIFACT_VALUE_LIMIT,
    COMMENT_LIMIT,
    DESCRIPTION_LIMIT,
    FIELD_LIMIT,
    INCIDENT_FIELDS,
)

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")

REQUIRED_DOCS = (
    "docs/threat-model.md",
    "docs/runbooks/key-rotation.md",
    "docs/open-questions.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
)


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n## ", start + len(heading))
    return text[start : nxt if nxt != -1 else len(text)]


def _table_rows(section: str) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        if line.startswith("|") and not set(line.strip("| ")) <= {"-", "|", " "}:
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]  # drop the header


# ------------------------------------------------------------------ flags


def test_readme_documents_every_capability_flag_with_its_tier():
    rows = _table_rows(_section(README, "## Risk tiers and flags"))
    tier_of: dict[str, int] = {}
    for row in rows:
        tier = row[0]
        for flag in re.findall(r"`(SOAR_ALLOW_[A-Z_]+)`", row[3]):
            tier_of[flag] = int(tier)
    for flag in CAPABILITY_FLAGS:
        assert flag in tier_of, f"{flag} missing from the README tier table"
        assert tier_of[flag] == int(CAPABILITY_TIERS[flag]), flag
    assert "SOAR_ALLOW_SCRIPT_WRITES=true` refuses to start" in README


def test_readme_configuration_reference_covers_env_example():
    documented = set(re.findall(r"`(SOAR_[A-Z_]+)`", README))
    # Grouped rows use `_EXPORT` style suffixes; expand them.
    reference = _section(README, "## Configuration reference")
    for m in re.finditer(r"`(SOAR_ALLOW_PLAYBOOK)_DRAFT` / (.*?)\|", reference):
        for suffix in re.findall(r"`_([A-Z]+)`", m.group(2)):
            documented.add(f"{m.group(1)}_{suffix}")
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    in_example = set(re.findall(r"^#?\s*(SOAR_[A-Z_]+)=", example, flags=re.M))
    missing = sorted(in_example - documented)
    assert missing == [], f"variables in .env.example not documented in the README: {missing}"


# ------------------------------------------------------------------ tools


def test_readme_tool_table_is_the_registry():
    rows = _table_rows(_section(README, "## Tools"))
    listed = {}
    for row in rows:
        name = row[0].strip("`")
        if name.startswith("soar_"):
            listed[name] = (row[1], row[2])
    assert set(listed) == set(TOOL_REGISTRY)
    for name, spec in TOOL_REGISTRY.items():
        tier_text, flag_text = listed[name]
        if name == "soar_invoke_action":
            assert tier_text == "per policy"
        else:
            assert tier_text == str(int(spec.tier)), name
        if spec.capability:
            assert f"`{spec.capability}`" in flag_text, name
        else:
            assert flag_text == "—", name


def test_readme_projection_and_budgets_match_the_code():
    section = re.sub(r"\s+", " ", _section(README, "### What an incident looks like to the model"))
    listed = re.findall(r"`([a-z_]+)`", section.split("Custom fields")[0])
    assert listed == list(INCIDENT_FIELDS)
    assert f"**{FULL_INCIDENT_BUDGET_CHARS:,} characters**" in section
    assert (
        f"({FULL_INCIDENT_CAPS['tasks']} tasks, {FULL_INCIDENT_CAPS['artifacts']} artifacts, "
        f"{FULL_INCIDENT_CAPS['comments']} notes, {FULL_INCIDENT_CAPS['attachments']} attachments)"
        in section
    )
    assert f"at {DESCRIPTION_LIMIT:,} characters" in section
    assert f"note text at {COMMENT_LIMIT:,}" in section
    assert f"artifact values at {ARTIFACT_VALUE_LIMIT:,}" in section
    assert f"custom fields at {FIELD_LIMIT:,}" in section


def test_readme_defaults_match_settings():
    s = Settings.load({})
    reference = _section(README, "## Configuration reference")
    assert f"| `{s.max_tier2_per_hour}` / `{s.max_tier3_per_hour}` |" in reference
    assert f"| `{s.approval_ttl_seconds}` |" in reference
    assert f"| `{s.max_results}` |" in reference
    assert f"| `{s.mcp_host}` / `{s.mcp_port}` |" in reference
    assert f"| `{s.timeout:g}` |" in reference
    assert f"`{s.approval_mode}`" in reference


# ------------------------------------------------------------- confidence


def test_every_api_claim_carries_a_confidence_mark():
    section = _section(README, "## SOAR API behaviours this client relies on")
    claims = [line for line in section.splitlines() if re.match(r"^\d+\.\s", line)]
    assert len(claims) >= 8
    for claim in claims:
        assert any(mark in claim for mark in ("✅", "⚠️", "❓")), claim
    assert "not yet verified by\nthis repository" in section or "not yet verified" in section


def test_readme_makes_no_unverified_claims_about_features():
    for absent in (
        "probes its key's capabilities",
        "docs/soar-api-verified.md` are documented",
        "172.16.",
    ):
        assert absent not in README


def test_readme_recommends_two_instances_and_out_of_band():
    assert "two instances, two keys" in README
    assert "is not human approval" in README
    assert "qradar-soar-approve keygen" in README


# ------------------------------------------------------------------ links


@pytest.mark.parametrize("doc", REQUIRED_DOCS)
def test_required_docs_exist_and_are_substantial(doc: str):
    path = ROOT / doc
    assert path.is_file(), doc
    assert len(path.read_text(encoding="utf-8")) > 1500, doc


@pytest.mark.parametrize("doc", ("README.md", "SECURITY.md", *REQUIRED_DOCS))
def test_relative_links_resolve(doc: str):
    path = ROOT / doc
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#]+?)(?:#[^)]*)?\)", text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (path.parent / target).exists(), f"{doc}: broken link {target}"


def test_threat_model_names_the_implementing_modules():
    text = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    for module in re.findall(r"`((?:security|tools|client)/[a-z_]+\.py)`", text):
        assert (ROOT / "src" / "qradar_soar_mcp" / module).is_file(), module
    for test_file in re.findall(r"`(tests/[a-z_]+\.py)`", text):
        assert (ROOT / test_file).is_file(), test_file
    assert "What this does not protect against" in text


def test_open_questions_reference_real_modules():
    text = (ROOT / "docs" / "open-questions.md").read_text(encoding="utf-8")
    for module in re.findall(r"`((?:security|tools|client)/[a-z_]+\.py)`", text):
        assert (ROOT / "src" / "qradar_soar_mcp" / module).is_file(), module
    assert "DEFERRED-P2" in text and "public-sanitised" in text
    assert "172.16." not in text  # no private topology anywhere in the published tree
