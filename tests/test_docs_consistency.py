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
    DISCOVERY_LIST_BUDGET_CHARS,
    DISCOVERY_PAGE_MAX,
    FIELD_LIMIT,
    FUNCTION_VALUES_MAX,
    INCIDENT_FIELDS,
    INPUT_VALUES_MAX,
    LIST_DESCRIPTION_LIMIT,
    SCRIPT_BODY_LIMIT,
)

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")

REQUIRED_DOCS = (
    "docs/threat-model.md",
    "docs/runbooks/key-rotation.md",
    "docs/runbooks/review-loop.md",
    "docs/open-questions.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
)
# REL-02: the changelog and the release notes of the pending alpha.
CHANGELOG = "CHANGELOG.md"
RELEASE_NOTES = "docs/releases/v0.2.0-alpha.md"
RELEASE_DOCS = (CHANGELOG, RELEASE_NOTES)


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


def test_readme_discovery_budgets_match_the_code():
    """P2-02 (08 §26): the documented script cap and list bounds are the constants."""
    section = re.sub(
        r"\s+", " ", _section(README, "### What SOAR configuration looks like to the model")
    )
    assert f"cut at **{SCRIPT_BODY_LIMIT:,} characters**" in section
    assert f"at most {DISCOVERY_PAGE_MAX} rows per call" in section
    assert f"at most {DISCOVERY_LIST_BUDGET_CHARS:,} characters of rows" in section
    assert f"trimmed at {LIST_DESCRIPTION_LIMIT} characters" in section
    assert f"({INPUT_VALUES_MAX} per input, {FUNCTION_VALUES_MAX} per function" in section
    assert "untrusted data" in section and "never executed" in section
    tools = _section(README, "## Tools")
    assert f"cut at {SCRIPT_BODY_LIMIT:,} characters" in tools
    amendments = (ROOT / "docs/design/08-GREENFIELD-AMENDMENTS.md").read_text(encoding="utf-8")
    assert f"`SCRIPT_BODY_LIMIT` = {SCRIPT_BODY_LIMIT:,} characters" in amendments
    assert f"{SCRIPT_BODY_LIMIT:,} characters" in TOOL_REGISTRY["soar_get_script"].description
    # The body contract (review of PR #8): every field and every text_is value is documented,
    # and nowhere is the body called the original: redaction may have changed it.
    from qradar_soar_mcp.tools.projection import SCRIPT_TEXT_IS, script_body

    body = script_body("x", source_chars=1, redacted=False)
    described = re.sub(r"\s+", " ", TOOL_REGISTRY["soar_get_script"].description)
    for name in (*body, *SCRIPT_TEXT_IS.values()):
        if name != "text":
            assert f"`{name}`" in section or f"`body.{name}`" in section, name
            assert f"`{name}`" in amendments, name
    for name in ("redacted", "truncated", "text_is", "source_chars", "safe_chars"):
        assert name in described, name
    assert "safety-filtered representation" in section and "safety-filtered" in described
    assert "original_chars" not in README + described  # 08 names it once, as history


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


# Sprint 1 (REL-05, REL-03, LAB-01, SEC-14) documents: their links are checked too.
SPRINT1_DOCS = (
    "docs/release-readiness.md",
    "docs/lab-validation-plan.md",
    "docs/runbooks/branch-protection.md",
    "docs/runbooks/artifact-hygiene.md",
    "docs/design/08-GREENFIELD-AMENDMENTS.md",
    "docs/proposals/LAB-03-t3-golden-test-gate.md",
)


@pytest.mark.parametrize(
    "doc", ("README.md", "SECURITY.md", *RELEASE_DOCS, *REQUIRED_DOCS, *SPRINT1_DOCS)
)
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


# ----------------------------------------------- names in the operator docs

OPERATOR_DOCS = (
    "README.md",
    "SECURITY.md",
    ".env.example",
    "docs/threat-model.md",
    "docs/runbooks/key-rotation.md",
    *RELEASE_DOCS,
)
# Read by the approver CLI only; the server never reads it (08 §5).
NON_SERVER_VARIABLES = frozenset({"SOAR_APPROVAL_PRIVATE_KEY_FILE"})


def _settings_variables() -> set[str]:
    return {f"SOAR_{name.upper()}" for name in Settings.model_fields if name != "warnings"}


@pytest.mark.parametrize("doc", OPERATOR_DOCS)
def test_every_documented_variable_exists(doc: str):
    text = (ROOT / doc).read_text(encoding="utf-8")
    named = set(re.findall(r"\b(SOAR_[A-Z][A-Z0-9_]*[A-Z0-9])\b", text))
    # `SOAR_ALLOW_PLAYBOOK_DRAFT` / `_EXPORT` rows name the prefix on its own.
    named.discard("SOAR_ALLOW_PLAYBOOK")
    unknown = sorted(named - _settings_variables() - NON_SERVER_VARIABLES)
    assert unknown == [], f"{doc} names variables the server does not read: {unknown}"


def test_configuration_reference_has_a_row_for_every_setting():
    reference = _section(README, "## Configuration reference")
    rows = " ".join(row[0] for row in _table_rows(reference))
    for m in re.finditer(r"`(SOAR_ALLOW_PLAYBOOK)_DRAFT` / (.*?)\|", reference):
        suffixes = re.findall(r"`_([A-Z]+)`", m.group(2))
        rows += " " + " ".join(f"`{m.group(1)}_{s}`" for s in suffixes)
    missing = sorted(v for v in _settings_variables() if f"`{v}`" not in rows)
    assert missing == [], f"settings without a configuration-reference row: {missing}"


@pytest.mark.parametrize("doc", OPERATOR_DOCS)
def test_every_documented_tool_and_denial_code_exists(doc: str):
    from qradar_soar_mcp.security.permissions import Code

    text = (ROOT / doc).read_text(encoding="utf-8")
    tools = set(re.findall(r"`(soar_[a-z_]+)`", text))
    assert tools <= set(TOOL_REGISTRY), sorted(tools - set(TOOL_REGISTRY))
    codes = set(re.findall(r"\b((?:DENY|REQUIRE)_[A-Z0-9_]+)\b", text))
    known = {str(c) for c in Code}
    assert codes <= known, sorted(codes - known)


def _github_anchor(heading: str) -> str:
    slug = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return slug.replace(" ", "-")


@pytest.mark.parametrize("doc", ("README.md", "SECURITY.md", *RELEASE_DOCS, *REQUIRED_DOCS))
def test_anchors_resolve(doc: str):
    path = ROOT / doc
    text = path.read_text(encoding="utf-8")
    for target, anchor in re.findall(r"\]\(([^)#]*)#([^)]+)\)", text):
        if target.startswith(("http://", "https://")):
            continue
        linked = (path.parent / target) if target else path
        if linked.suffix != ".md":
            continue
        headings = re.findall(r"^#+ (.+)$", linked.read_text(encoding="utf-8"), flags=re.M)
        assert anchor in {_github_anchor(h) for h in headings}, f"{doc}: broken anchor #{anchor}"


# ------------------------------------------- REL-02: changelog and release notes

REPO_BLOB = "https://github.com/lancyandrade/qradar-soar-mcp/blob/"


def _read(doc: str) -> str:
    return (ROOT / doc).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """One line of prose: blockquote markers dropped, whitespace collapsed."""
    return re.sub(r"\s+", " ", re.sub(r"^> ?", "", text, flags=re.M))


def _phase_one_tools() -> set[str]:
    """The approved Phase-1 contract is the tool table of 08 §3; the rest is Phase 2."""
    amendments = _read("docs/design/08-GREENFIELD-AMENDMENTS.md")
    table = _section(amendments, "## 3. Approved Phase-1 tool contract")
    return {row[0].strip("`") for row in _table_rows(table) if row[0].startswith("`soar_")}


def _block(text: str, heading: str) -> str:
    """From ``heading`` up to the next heading of the same or a higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    start = text.index(heading)
    rest = text[start + len(heading) :]
    nxt = re.search(rf"^#{{1,{level}}} ", rest, flags=re.M)
    return text[start : start + len(heading) + nxt.start()] if nxt else text[start:]


def _version() -> str:
    import tomllib

    import qradar_soar_mcp

    version = str(tomllib.loads(_read("pyproject.toml"))["project"]["version"])
    assert qradar_soar_mcp.__version__ == version
    return version


def test_tool_counts_match_the_registry():
    phase_one = _phase_one_tools()
    phase_two = set(TOOL_REGISTRY) - phase_one
    assert phase_one <= set(TOOL_REGISTRY)
    assert (len(phase_one), len(phase_two), len(TOOL_REGISTRY)) == (20, 16, 36)
    claim = f"{len(TOOL_REGISTRY)} MCP tools: {len(phase_one)} Phase-1 and {len(phase_two)} Phase-2"
    for doc in RELEASE_DOCS:
        assert claim in _flat(_read(doc)), doc
    status = _flat(_section(README, "## Release status"))
    assert f"{len(phase_two)} read-only tools, for {len(TOOL_REGISTRY)} tools in all" in status


def test_changelog_lists_every_tool_under_its_phase():
    phase_one = _phase_one_tools()
    release = _block(_read(CHANGELOG), f"## [{_version()}]")
    one = set(re.findall(r"`(soar_[a-z_]+)`", _block(release, "#### Phase 1: ")))
    two = set(re.findall(r"`(soar_[a-z_]+)`", _block(release, "#### Early Phase 2: ")))
    assert one == phase_one
    assert two == set(TOOL_REGISTRY) - phase_one
    assert f"#### Phase 1: {len(one)} tools" in release
    assert f"#### Early Phase 2: {len(two)} discovery tools" in release


def test_release_notes_tool_table_is_the_registry():
    phase_one = _phase_one_tools()
    rows = _table_rows(_section(_read(RELEASE_NOTES), "## 2. What is included"))
    listed: dict[str, set[str]] = {"Phase 1": set(), "Phase 2": set()}
    for group, tools, _tier in rows:
        phase = re.search(r"\((Phase [12])\)", group)
        assert phase, group
        listed[phase.group(1)] |= set(re.findall(r"`(soar_[a-z_]+)`", tools))
    assert listed["Phase 1"] == phase_one
    assert listed["Phase 2"] == set(TOOL_REGISTRY) - phase_one


def test_version_references_are_consistent():
    version = _version()
    releases = re.findall(r"^## \[([^\]]+)\]", _read(CHANGELOG), flags=re.M)
    assert releases[:2] == ["Unreleased", version], releases
    notes = _read(RELEASE_NOTES)
    assert f"docs/releases/v{version}-alpha.md" == RELEASE_NOTES
    assert notes.startswith(f"# qradar-soar-mcp v{version} (alpha)\n")
    assert set(re.findall(r"/blob/([^/]+)/", notes)) == {f"v{version}"}
    assert f"version **{version}**" in README
    assert f"Current version: `{version}`, alpha, pending publication" in README
    assert f"this release ({version})" in _read("SECURITY.md")
    assert "Development Status :: 3 - Alpha" in _read("pyproject.toml")


def test_release_is_marked_pending_not_published():
    version = _version()
    changelog = _read(CHANGELOG)
    heading = re.search(rf"^## \[{re.escape(version)}\](.*)$", changelog, flags=re.M)
    assert heading and heading.group(1) == " - Pending (alpha)", heading
    release = _flat(_block(changelog, f"## [{version}]"))
    assert "alpha, pending publication" in release
    assert "The release gate is **not passed**" in release
    notes = _flat(_read(RELEASE_NOTES))
    assert "**Release status: pending.**" in notes
    assert "the release gate has not passed" in notes
    status = _flat(_section(README, "## Release status"))
    assert "pending publication" in status and "The release gate has not passed" in status
    major, minor, _ = version.split(".")
    assert f"`v{major}.{int(minor) + 1}.0` is not ready" in status
    for doc in RELEASE_DOCS:
        text = _flat(_read(doc))
        assert "No waiver has been recorded" in text, doc
        # REL-05 (08 §32, D14): the owner kept the lab gate.
        assert "T4/T5/T6 have not been waived" in text, doc
        assert "REL-04" in text and "PyPI" in text, doc
    assert "NO-GO" in _flat(_read(CHANGELOG)) and "NO-GO" in notes
    assert "decided not to waive" in status


# Each limitation the code imposes; the release documents must say it.
REQUIRED_LIMITATIONS = (
    "phase 2 is incomplete",
    "always returns `deny_unsupported`",
    "no tier-4",
    "attachment hash and text extraction are deferred",
    "offline-contract-tested, not live-validated",
    "51.0.9.0.20848",
    "no production-readiness claim",
)
# Phrases that would claim something this release does not do.
UNSUPPORTED_CLAIMS = (
    "production-ready",
    "production ready",
    "generally available",
    "pip install qradar-soar-mcp",
    "pypi.org/project",
    "release gate has passed",
    "gate passed",
    "lab validation is complete",
    "waiver was granted",
    "waived by the owner",
)


@pytest.mark.parametrize("doc", RELEASE_DOCS)
def test_release_docs_state_the_limitations_and_claim_nothing_unsupported(doc: str):
    text = _flat(_read(doc)).lower()
    for statement in REQUIRED_LIMITATIONS:
        assert statement in text, f"{doc}: missing {statement!r}"
    for claim in UNSUPPORTED_CLAIMS:
        assert claim not in text, f"{doc}: unsupported claim {claim!r}"
    assert "not reachable" in text or "unreachable" in text, doc
    assert "t4/t5/t6" in text, doc


def test_release_doc_limitations_are_true_of_the_code():
    """What the release documents say is missing is missing from the registry."""
    assert [n for n, s in TOOL_REGISTRY.items() if s.tier >= 4] == []
    invoke = TOOL_REGISTRY["soar_invoke_action"]
    assert invoke.unsupported and int(invoke.tier) == 3
    assert [n for n, s in TOOL_REGISTRY.items() if s.unsupported] == [invoke.name]
    assert [n for n in TOOL_REGISTRY if "content" in n or "extract" in n] == []
    # LAB-01: only the guarded T4 module exists; no T5/T6 test, so none may be claimed.
    lab = sorted(p.name for p in (ROOT / "tests" / "lab").glob("test_*.py"))
    assert lab == ["test_t4_read_only.py"], lab
    for marker in ("lab_write", "lab_destructive"):
        needle = "pytest.mark." + marker  # built, so this file does not match itself
        assert [
            p.name
            for p in (ROOT / "tests").rglob("test_*.py")
            if needle in p.read_text(encoding="utf-8")
        ] == []


def test_release_notes_repository_links_resolve():
    """The notes are pasted into GitHub, so they link to the tag; each target must exist."""
    links = re.findall(r"\]\(([^)]+)\)", _read(RELEASE_NOTES))
    repo = [link for link in links if link.startswith(REPO_BLOB)]
    assert len(repo) >= 10
    for link in repo:
        target, _, anchor = link.removeprefix(REPO_BLOB).partition("#")
        local = ROOT / target.split("/", 1)[1]
        assert local.is_file(), f"broken link {link}"
        if anchor:
            headings = re.findall(r"^#+ (.+)$", local.read_text(encoding="utf-8"), flags=re.M)
            assert anchor in {_github_anchor(h) for h in headings}, f"broken anchor {link}"
    relative = [link for link in links if not link.startswith(("https://", "#"))]
    assert relative == [], f"relative links do not work in a GitHub release body: {relative}"


def test_readme_points_at_the_changelog_and_release_notes():
    status = _section(README, "## Release status")
    assert f"]({CHANGELOG})" in status
    assert f"]({RELEASE_NOTES})" in status
