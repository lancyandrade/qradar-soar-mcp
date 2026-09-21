"""P2-01: ``soar_refresh_catalog`` and the catalog's place in the runtime (08 §25).

Tier 0, no capability, no mutation, no approval, no mutation audit record; executed by
``run_pipeline`` like every other tool; bypasses the TTL; answers with metadata and counts.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from qradar_soar_mcp.catalog import CatalogService, CollectionsBackend, ExportBackend
from qradar_soar_mcp.catalog.backends import EXPORT_UNAVAILABLE
from qradar_soar_mcp.security.tiers import Tier
from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline
from qradar_soar_mcp.tools import discovery as discovery_tools
from tests.fake_soar import FakeSoar
from tests.test_catalog_backends import EXPECTED_READS
from tests.tool_harness import audit_records, base_env, build_runtime

TOOL = "soar_refresh_catalog"
# P2-02 (08 §26) added these five beside it; tests/test_discovery_tools.py covers them.
P2_02_TOOLS = [
    "soar_list_functions",
    "soar_get_function",
    "soar_list_scripts",
    "soar_get_script",
    "soar_list_message_destinations",
]
# P2-03 (08 §28) added these four; tests/test_discovery_types_fields.py covers them.
P2_03_TOOLS = [
    "soar_list_incident_types",
    "soar_list_phases",
    "soar_list_datatables",
    "soar_list_fields",
]
PHASE_TWO_TOOLS_NOT_YET_IMPLEMENTED = {
    "soar_list_rules",
    "soar_get_rule",
    "soar_list_workflows",
    "soar_get_workflow",
    "soar_list_playbooks",
    "soar_get_playbook",
}


async def call(rt: Runtime) -> dict[str, Any]:
    return await run_pipeline(TOOL_REGISTRY[TOOL], rt, {})


# ------------------------------------------------------------- declaration
def test_it_is_a_tier_0_read_with_no_capability_and_no_mutation():
    spec = TOOL_REGISTRY[TOOL]
    assert spec.tier is Tier.READ and int(spec.tier) == 0
    assert spec.capability is None
    assert spec.mutations == 0 and spec.mutating is False
    assert spec.needs_approval_arg is False and spec.unsupported is None
    assert spec.classify is None
    assert list(inspect.signature(spec.func).parameters) == ["rt"]  # nothing to pass in


def test_the_discovery_module_holds_the_catalog_tool_and_those_of_p2_02_and_p2_03_only():
    assert not (set(TOOL_REGISTRY) & PHASE_TWO_TOOLS_NOT_YET_IMPLEMENTED)
    tree = ast.parse(Path(discovery_tools.__file__).read_text(encoding="utf-8"))
    functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]
    assert functions == [TOOL, *P2_02_TOOLS, *P2_03_TOOLS]


def test_there_is_no_capability_flag_for_catalog_reads():
    from qradar_soar_mcp.config import CAPABILITY_FLAGS, Settings

    assert not [flag for flag in CAPABILITY_FLAGS if "CATALOG" in flag]
    assert not [f for f in Settings.model_fields if f.startswith("allow_") and "catalog" in f]


# ---------------------------------------------------------------- behaviour
async def test_it_returns_compact_metadata_and_counts(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    out = await call(rt)
    await rt.aclose()
    assert out["ok"] is True, out
    data = out["data"]
    assert set(data) == {
        "source",
        "fetched_at",
        "soar_version",
        "org_id",
        "counts",
        "not_loaded",
        "ttl_seconds",
    }
    assert data["source"] == "collections" and data["ttl_seconds"] == 300
    assert data["soar_version"] == "51.0.9.0.20848" and data["org_id"] == "201"
    assert data["fetched_at"].endswith("+00:00")
    assert data["counts"] == {
        "functions": 2,
        "scripts": 2,
        "message_destinations": 2,
        "incident_types": 2,
        "phases": 2,
        "fields": 23,
        "datatables": 2,
        "playbooks": 2,
        "rules": 2,
        "workflows": 0,
        "groups": 2,
    }
    assert set(data["not_loaded"]) == {"api_key_permissions", "installed_apps"}
    assert data["not_loaded"]["api_key_permissions"]["state"] == "not_observable"
    # Compact: counts, never the objects.
    rendered = json.dumps(out)
    assert len(rendered) < 2_000
    for name in ("function_200", "rule_300", "playbook_1000", "input_100", "table_1"):
        assert name not in rendered


async def test_it_bypasses_the_ttl_and_refills_the_cache(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    service = rt.require_catalog()
    first = await service.get()
    assert await service.get() is first  # inside the TTL: no second load
    assert len(fake.requests) == len(EXPECTED_READS)
    out = await call(rt)
    assert out["ok"] is True
    assert len(fake.requests) == 2 * len(EXPECTED_READS)  # the tool reloaded anyway
    refreshed = service.cached()
    assert refreshed is not None and refreshed is not first
    assert await service.get() is refreshed and len(fake.requests) == 2 * len(EXPECTED_READS)
    await rt.aclose()


async def test_it_sees_what_changed_in_soar(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    assert (await call(rt))["data"]["counts"]["scripts"] == 2
    fake.discovery["scripts"]["entities"].pop()
    assert (await call(rt))["data"]["counts"]["scripts"] == 1
    await rt.aclose()


async def test_it_writes_no_mutation_audit_record_and_asks_no_approval(
    fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path)
    out = await call(rt)
    await rt.aclose()
    assert out["ok"] is True and "approval" not in out
    assert audit_records(tmp_path) == []
    assert not list((tmp_path / "state" / "approvals").glob("*"))
    assert [r for r in fake.mutating_requests if not r.path.endswith("/query_paged")] == []


async def test_a_failed_refresh_is_an_ordinary_tool_error_and_keeps_the_cache(
    fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path)
    service = rt.require_catalog()
    good = await service.get()
    fake.fault("GET", r"/scripts$", status=500, raw_body=b"<html>boom</html>")
    out = await call(rt)
    assert out["ok"] is False and out["error"]["code"] == "server_error"
    assert "data" not in out
    assert service.cached() is good
    await rt.aclose()


async def test_without_a_connection_it_fails_as_not_configured(tmp_path: Path):
    rt = Runtime.build({"SOAR_AUDIT_LOG_PATH": str(tmp_path / "a.jsonl")})
    assert rt.catalog is None
    out = await call(rt)
    assert out["ok"] is False and out["error"]["code"] == "not_configured"
    assert "SOAR_BASE_URL" in out["error"]["message"]


# ------------------------------------------------------------------ pipeline
async def test_it_travels_through_the_registry_pipeline(fake: FakeSoar, tmp_path: Path):
    """The same gates as every tool: an unusable runtime denies it before anything is sent."""
    rt = Runtime.build(base_env(tmp_path, SOAR_ALLOW_SCRIPT_WRITES="true"))
    assert not rt.usable
    out = await call(rt)
    assert out["ok"] is False and out["error"]["code"] == "DENY_CONFIG"
    assert fake.requests == []


def test_the_tool_body_reaches_soar_only_through_the_runtime():
    source = Path(discovery_tools.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not [m for m in imported if m.startswith("qradar_soar_mcp.client")]
    # The catalog's data types only: the service that loads one comes from the runtime.
    assert [m for m in imported if m.startswith("qradar_soar_mcp.catalog")] == [
        "qradar_soar_mcp.catalog.models"
    ]
    assert "httpx" not in source
    # P2-02: one tool reads SOAR itself, for the script body the catalog does not hold.
    reaches_client = [
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, ast.AsyncFunctionDef | ast.FunctionDef)
        and any(isinstance(n, ast.Attribute) and n.attr == "require_client" for n in ast.walk(fn))
    ]
    assert reaches_client == ["soar_get_script"]


def test_nothing_but_the_runtime_builds_a_catalog_service():
    import qradar_soar_mcp

    root = Path(qradar_soar_mcp.__file__).parent
    users = [
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if "CatalogService" in path.read_text(encoding="utf-8")
    ]
    assert sorted(users) == ["catalog/__init__.py", "catalog/cache.py", "tools/runtime.py"]


# ------------------------------------------------------------------- runtime
async def test_the_runtime_builds_the_configured_backend(fake: FakeSoar, tmp_path: Path):
    rt = build_runtime(fake, tmp_path)
    assert isinstance(rt.catalog, CatalogService)
    assert isinstance(rt.catalog.backend, CollectionsBackend)
    assert rt.catalog.ttl_seconds == 300
    assert rt.describe()["catalog"] == {"source": "collections", "ttl_seconds": 300}
    await rt.aclose()
    rt = build_runtime(fake, tmp_path, SOAR_CATALOG_TTL_SECONDS="60")
    assert rt.require_catalog().ttl_seconds == 60
    await rt.aclose()


async def test_selecting_export_starts_warns_and_fails_every_load_without_fallback(
    fake: FakeSoar, tmp_path: Path
):
    rt = build_runtime(fake, tmp_path, SOAR_CATALOG_SOURCE="export")
    assert rt.usable  # Phase-1 tools are unaffected
    assert isinstance(rt.require_catalog().backend, ExportBackend)
    assert any(EXPORT_UNAVAILABLE in w for w in rt.warnings)
    out = await call(rt)
    await rt.aclose()
    assert out["ok"] is False
    assert out["error"] == {"code": "catalog_unavailable", "message": EXPORT_UNAVAILABLE}
    assert fake.requests == []  # no export request, and the collections were not read instead


@pytest.mark.parametrize("value", ["", "EXPORTS", "both", "export,collections"])
async def test_an_invalid_source_never_selects_the_export(
    fake: FakeSoar, tmp_path: Path, value: str
):
    rt = build_runtime(fake, tmp_path, SOAR_CATALOG_SOURCE=value)
    assert isinstance(rt.require_catalog().backend, CollectionsBackend)
    assert any("SOAR_CATALOG_SOURCE" in w for w in rt.warnings)
    await rt.aclose()
