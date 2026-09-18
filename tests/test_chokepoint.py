"""P1-13 complementary chokepoint tests (07 §3.1).

1. ``test_no_mutation_under_default_config``: every registered tool, invoked
   with minimal valid arguments under the default configuration, sends no
   mutating request to SOAR (POST/PATCH/PUT/DELETE; ``query_paged`` is a read).
2. Static AST checks: no function under ``tools/`` reaches the client outside a
   ``@soar_tool`` body; no tools module imports ``qradar_soar_mcp.client``
   except ``runtime.py``; only ``registry.py`` calls tool bodies; the server
   and CLI never import client mutation APIs.
"""

from __future__ import annotations

import ast
import contextlib
from pathlib import Path

import pytest
import respx

import qradar_soar_mcp
from qradar_soar_mcp.tools import TOOL_REGISTRY, run_pipeline
from tests.fake_soar import BASE_URL
from tests.test_permission_matrix import MINIMAL_ARGS, build_state

PKG = Path(qradar_soar_mcp.__file__).parent
TOOLS_DIR = PKG / "tools"

MUTATING_CLIENT_METHODS = {
    "add",
    "create",
    "apply_patch",
    "assign",
    "close",
    "set_status",
    "invoke",
    "post",
    "patch",
    "patch_object",
}
API_ACCESSORS = {"require_client"}


async def test_no_mutation_under_default_config(tmp_path: Path):
    """The spy: every tool under default config, nothing mutating reaches SOAR."""
    if not TOOL_REGISTRY:
        pytest.skip("no real tools registered yet (P1-14)")
    rt, fake = build_state(tmp_path, "default", "stdio")
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=fake.handler)
        for name, spec in TOOL_REGISTRY.items():
            with contextlib.suppress(Exception):
                await run_pipeline(spec, rt, dict(MINIMAL_ARGS[name]))
        await rt.aclose()
    mutating = [r for r in fake.mutating_requests if not r.path.endswith("/query_paged")]
    assert mutating == [], [(r.method, r.path) for r in mutating]


# ---------------------------------------------------------------- static


def _decorator_names(fn: ast.AsyncFunctionDef | ast.FunctionDef) -> set[str]:
    names = set()
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, ast.Attribute):
            names.add(target.attr)
    return names


def _touches_client(fn: ast.AST) -> list[str]:
    hits = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute):
            if node.attr in API_ACCESSORS or node.attr in MUTATING_CLIENT_METHODS:
                hits.append(node.attr)
            if node.attr == "client" and isinstance(node.value, ast.Name) and node.value.id == "rt":
                hits.append("rt.client")
    return hits


def _modules():
    for path in sorted(TOOLS_DIR.glob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_every_client_touching_function_in_tools_is_a_soar_tool():
    offenders = []
    for path, tree in _modules():
        if path.name in {"registry.py", "runtime.py"}:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                hits = _touches_client(node)
                if hits and "soar_tool" not in _decorator_names(node):
                    # Classifiers are the one sanctioned helper: async, _classify_*, read-only.
                    if (
                        node.name.startswith("_classify")
                        and isinstance(node, ast.AsyncFunctionDef)
                        and not (set(hits) & MUTATING_CLIENT_METHODS)
                    ):
                        continue
                    offenders.append(f"{path.name}:{node.name} -> {sorted(set(hits))}")
    assert offenders == [], f"functions reaching the client outside @soar_tool: {offenders}"


def test_tools_modules_do_not_import_the_client_package():
    offenders = []
    for path, tree in _modules():
        if path.name == "runtime.py":
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "qradar_soar_mcp.client"
            ):
                offenders.append(f"{path.name}: from {node.module}")
            if isinstance(node, ast.Import) and any(
                a.name.startswith("qradar_soar_mcp.client") for a in node.names
            ):
                offenders.append(f"{path.name}: import client")
    assert offenders == []


def test_only_registry_calls_tool_bodies():
    for path, tree in _modules():
        if path.name == "registry.py":
            continue
        for node in ast.walk(tree):
            assert not (isinstance(node, ast.Attribute) and node.attr == "func"), (
                f"{path.name} touches ToolSpec.func"
            )


def test_registered_functions_carry_the_marker():
    import inspect

    for name, spec in TOOL_REGISTRY.items():
        assert getattr(spec.func, "__soar_tool__", None) is spec, name
        assert inspect.iscoroutinefunction(spec.func)
        assert next(iter(inspect.signature(spec.func).parameters)) == "rt"


@pytest.mark.parametrize("module", ["server.py", "cli.py"])
def test_server_and_cli_never_import_client_mutation_apis(module: str):
    path = PKG / module
    if not path.exists():
        pytest.skip(f"{module} arrives in P1-14")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "qradar_soar_mcp.client"
        ):
            raise AssertionError(f"{module} imports {node.module}")
        if isinstance(node, ast.Attribute) and node.attr in MUTATING_CLIENT_METHODS - {
            "post",
            "patch",
        }:
            raise AssertionError(f"{module} references mutating method .{node.attr}")
