"""T3 golden-file tests: PILOT (LAB-03; D22 open, scope not approved).

Three of the nine proposed LAB-03 §3 groups, so that the harness can be reviewed with
real outputs before any wider scope is approved:

- **G1** the MCP tool manifest (names, descriptions, tiers, capabilities, schemas,
  annotations);
- **G7** the summary of the committed offline catalog ``tests/fixtures/catalog/lab-v51.json``;
- **G9** the MCP-facing shape (``to_dict``) of every ``SoarError`` class.

The remaining groups (G2 to G6, G8) and the Phase-3 IR corpus (G10, ``P3-10``) are not
here. **These tests do not meet the `07 §7.5` T3 release gate**: the gate needs the
owner's D22 decision, the approved output list and the LAB-03 §9 evidence.

Offline: no ``SOAR_*`` variable (the root scrub applies), no ``.env``, no socket.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest
from mcp.server.mcpserver import MCPServer

from qradar_soar_mcp import errors
from qradar_soar_mcp.catalog import Catalog
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, register_all
from tests.catalog_fixture import FIXTURE
from tests.conftest import SENTINEL
from tests.golden_support import (
    GOLDEN_DIR,
    UPDATE_OPTION,
    GoldenMismatchError,
    canonical,
    check,
    orphans,
)

ROOT = Path(__file__).resolve().parent.parent
CASES = {
    "g1_tool_manifest/manifest",
    "g7_catalog/lab_v51_summary",
    "g9_errors/error_shapes",
}
DETERMINISM_RUNS = 100  # LAB-03 §9 criterion 3, after 07 §6.3


# ------------------------------------------------------------------ producers
async def tool_manifest(state_dir: Path) -> dict[str, Any]:
    rt = Runtime.build({"SOAR_AUDIT_LOG_PATH": str(state_dir / "a.jsonl")})
    try:
        server = MCPServer("golden")
        register_all(server, rt)
        manifest: dict[str, Any] = {}
        for tool in await server.list_tools():
            spec = TOOL_REGISTRY[tool.name]
            manifest[tool.name] = {
                # Python 3.13 strips docstring indentation at compile time and 3.12 does
                # not; cleandoc gives both the same text, so G1 pins content, not the
                # interpreter's whitespace.
                "description": inspect.cleandoc(tool.description or ""),
                "tier": int(spec.tier),
                "capability": spec.capability,
                "input_schema": tool.input_schema,
                "annotations": tool.annotations.model_dump(exclude_none=True)
                if tool.annotations
                else None,
            }
        return manifest
    finally:
        await rt.aclose()


def catalog_summary() -> dict[str, Any]:
    return Catalog.from_json(FIXTURE.read_bytes()).summary()


def error_shapes() -> dict[str, Any]:
    """Each class with a fixed synthetic message, with and without an HTTP status."""
    out: dict[str, Any] = {}
    for name, cls in sorted(inspect.getmembers(errors, inspect.isclass)):
        if not issubclass(cls, errors.SoarError):
            continue
        if cls is errors.SoarPatchRejectedError:
            exc: errors.SoarError = cls(
                "synthetic message", field_failures=[{"field": "properties.example"}]
            )
            out[name] = {"failure_class": cls.failure_class, "to_dict": exc.to_dict()}
            continue
        out[name] = {
            "failure_class": cls.failure_class,
            "to_dict": cls("synthetic message").to_dict(),
            "to_dict_with_status": cls("synthetic message", status=599).to_dict(),
        }
    return out


# ------------------------------------------------------------------- goldens
@pytest.mark.golden
async def test_g1_tool_manifest(tmp_path: Path, golden_update: bool):
    check("g1_tool_manifest/manifest", await tool_manifest(tmp_path), update=golden_update)


@pytest.mark.golden
def test_g7_offline_catalog_summary(golden_update: bool):
    check("g7_catalog/lab_v51_summary", catalog_summary(), update=golden_update)


@pytest.mark.golden
def test_g9_error_shapes(golden_update: bool):
    check("g9_errors/error_shapes", error_shapes(), update=golden_update)


@pytest.mark.golden
async def test_outputs_are_byte_stable(tmp_path: Path):
    """LAB-03 §9 criterion 3: 100 renderings in one process are byte-identical."""
    first_manifest = canonical(await tool_manifest(tmp_path))
    assert canonical(await tool_manifest(tmp_path)) == first_manifest
    for produce in (catalog_summary, error_shapes):
        first = canonical(produce())
        assert all(canonical(produce()) == first for _ in range(DETERMINISM_RUNS)), produce


@pytest.mark.golden
def test_no_orphan_expected_files():
    assert orphans(CASES) == []
    assert {p.parent.name for p in GOLDEN_DIR.rglob("*.json")} == {c.split("/")[0] for c in CASES}


# --------------------------------------------------------- harness behaviour
def test_a_changed_output_fails_with_a_diff(tmp_path: Path):
    check("grp/case", {"a": 1}, update=True, root=tmp_path)
    with pytest.raises(GoldenMismatchError, match=r'(?s)differs.*-  "a": 1.*\+  "a": 2'):
        check("grp/case", {"a": 2}, root=tmp_path)


def test_a_missing_expected_file_fails_and_is_not_created(tmp_path: Path):
    with pytest.raises(GoldenMismatchError, match="missing"):
        check("grp/case", {"a": 1}, root=tmp_path)
    assert not (tmp_path / "grp" / "case.json").exists()


def test_an_orphan_expected_file_is_reported(tmp_path: Path):
    check("grp/kept", {}, update=True, root=tmp_path)
    check("grp/stale", {}, update=True, root=tmp_path)
    assert orphans({"grp/kept"}, root=tmp_path) == ["grp/stale"]


PLANTED = [SENTINEL, "10.1.2.3", "192.168.0.7", "172.20.1.1"]  # check_no_secrets:allow (fake)


@pytest.mark.parametrize("planted", PLANTED)
def test_a_planted_secret_or_private_address_fails(tmp_path: Path, planted: str):
    with pytest.raises(GoldenMismatchError, match="refused") as info:
        check("grp/case", {"value": planted}, update=True, root=tmp_path)
    assert planted not in str(info.value)
    assert not (tmp_path / "grp" / "case.json").exists()
    # A planted value in a committed expected file fails too.
    (tmp_path / "grp").mkdir(exist_ok=True)
    (tmp_path / "grp" / "case.json").write_bytes(canonical({"value": planted}).encode())
    with pytest.raises(GoldenMismatchError, match="refused"):
        check("grp/case", {"value": "x"}, root=tmp_path)


def test_canonical_text_is_sorted_lf_and_newline_terminated():
    text = canonical({"b": [2, 1], "a": "é"})
    assert text == '{\n  "a": "é",\n  "b": [\n    2,\n    1\n  ]\n}\n'
    assert "\r" not in text


def test_ci_never_regenerates_expected_outputs():
    """LAB-03 §7: no workflow passes the golden or snapshot update flags."""
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        assert UPDATE_OPTION not in text, workflow.name
        assert "--snapshot-update" not in text, workflow.name
