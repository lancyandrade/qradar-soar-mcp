"""P1-04 / 08 §4: client/ may only call the Phase-1 known-good REST surface.

Enforced by AST inspection:

* every ``org_path(...)`` argument and every absolute ``/rest/...`` literal in the
  client package is on the allow-list;
* every call of a verb helper (``get``, ``post``, ``patch``, ``patch_object``) is
  an allowed *(method, path)* pair, so ``PATCH`` exists for ``incidents/{id}`` only
  (08 §4 as amended by §21, P1-CORR-01);
* the three calls the verified record retired for QRadar SOAR 51.0.9.0.20848
  appear nowhere, and neither does any request to a single task: the verified
  ``PUT /tasks/{id}`` has an unverified body, so no task mutation of any shape
  exists in production code;
* no client module defines or calls PUT, DELETE, HEAD or OPTIONS.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import qradar_soar_mcp.client as client_pkg

CLIENT_DIR = Path(client_pkg.__file__).parent

# 08 §4 as amended by §21: (method, path) with every placeholder rendered as {id}.
ALLOWED_CALLS = {
    ("GET", "/rest/session"),
    ("POST", "incidents/query_paged"),
    ("GET", "incidents/{id}"),
    ("POST", "incidents"),
    ("PATCH", "incidents/{id}"),
    ("GET", "incidents/{id}/tasks"),
    ("GET", "incidents/{id}/artifacts"),
    ("POST", "incidents/{id}/artifacts"),
    ("GET", "incidents/{id}/comments"),
    ("POST", "incidents/{id}/comments"),
    ("GET", "incidents/{id}/attachments"),
    ("GET", "users"),
    ("GET", "types/incident/fields"),
}
ALLOWED_ORG_SUFFIXES = {path for _, path in ALLOWED_CALLS if not path.startswith("/rest/")}
ALLOWED_ABSOLUTE = {path for _, path in ALLOWED_CALLS if path.startswith("/rest/")}
# Contradicted on 51.0.9.0.20848 (docs/soar-api-verified.md §3, D1/D3/D4).
RETIRED_CALLS = {
    ("PATCH", "tasks/{id}"),
    ("GET", "incidents/{id}/actions"),
    ("POST", "incidents/{id}/action_invocations"),
}
VERB_HELPERS = {"get": "GET", "post": "POST", "patch": "PATCH", "patch_object": "PATCH"}
FORBIDDEN_VERBS = {"put", "delete", "head", "options"}


def _template(node: ast.AST) -> str | None:
    """Render a Constant or f-string argument with every placeholder as ``{id}``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            else:
                parts.append("{id}")
        return "".join(parts)
    return None


def _modules() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text(encoding="utf-8"))) for p in sorted(CLIENT_DIR.glob("*.py"))]


def _is_org_path(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "org_path"
    )


def _is_http_receiver(node: ast.AST, module: str) -> bool:
    """``self._c`` in a domain module; ``self`` inside the SoarClient itself."""
    if module == "base.py":
        return isinstance(node, ast.Name) and node.id == "self"
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "_c"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _calls() -> tuple[set[tuple[str, str]], list[str]]:
    """Every (method, path) the client sends, and the call sites it could not resolve."""
    pairs: set[tuple[str, str]] = set()
    unresolved: list[str] = []
    for path, tree in _modules():
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            names: dict[str, str] = {}
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and _is_org_path(node.value)
                ):
                    assert isinstance(node.value, ast.Call)
                    template = _template(node.value.args[0])
                    if template is not None:
                        names[node.targets[0].id] = template.lstrip("/")
            for node in ast.walk(fn):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in VERB_HELPERS
                    and _is_http_receiver(node.func.value, path.name)
                ):
                    continue
                method = VERB_HELPERS[node.func.attr]
                arg = node.args[0] if node.args else None
                target: str | None = None
                if arg is not None and _is_org_path(arg):
                    assert isinstance(arg, ast.Call)
                    rendered = _template(arg.args[0])
                    target = rendered.lstrip("/") if rendered is not None else None
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    target = arg.value
                elif isinstance(arg, ast.Name):
                    target = names.get(arg.id)
                if target is None:
                    # Only SoarClient's own pass-through helpers take a bare path parameter.
                    if not (path.name == "base.py" and fn.name in VERB_HELPERS):
                        unresolved.append(f"{path.name}:{fn.name}:{node.lineno}")
                    continue
                pairs.add((method, target))
    return pairs, unresolved


def test_every_org_path_is_on_the_allow_list():
    seen: set[str] = set()
    for path, tree in _modules():
        for node in ast.walk(tree):
            if _is_org_path(node):
                assert isinstance(node, ast.Call)
                if not node.args:
                    continue
                template = _template(node.args[0])
                assert template is not None, f"{path.name}: org_path argument is not a literal"
                template = template.lstrip("/")
                assert template in ALLOWED_ORG_SUFFIXES, (
                    f"{path.name}: {template!r} is not a Phase-1 endpoint"
                )
                seen.add(template)
    assert seen == ALLOWED_ORG_SUFFIXES, f"unused allow-list entries: {ALLOWED_ORG_SUFFIXES - seen}"


def test_absolute_rest_literals_are_on_the_allow_list():
    for path, tree in _modules():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("/rest/")
            ):
                if path.name == "base.py" and node.value.startswith("/rest/orgs/"):
                    continue  # the org_path prefix itself
                assert node.value in ALLOWED_ABSOLUTE, f"{path.name}: {node.value!r}"


def test_every_call_is_an_allowed_method_and_path():
    pairs, unresolved = _calls()
    assert unresolved == [], f"verb calls whose path cannot be checked: {unresolved}"
    assert pairs - ALLOWED_CALLS == set(), f"calls outside 08 §4: {pairs - ALLOWED_CALLS}"
    assert pairs == ALLOWED_CALLS, f"unused allow-list entries: {ALLOWED_CALLS - pairs}"


def test_calls_retired_by_the_verified_record_are_gone():
    """P1-CORR-01: no PATCH /tasks/{id}, no GET /incidents/{id}/actions, no invocation POST."""
    pairs, _ = _calls()
    assert pairs & RETIRED_CALLS == set()
    scopes = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    for path, tree in _modules():
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, scopes) and node.body and isinstance(node.body[0], ast.Expr)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) in docstrings:
                    continue  # prose may name the retired calls; code may not
                assert "action_invocations" not in node.value, f"{path.name}: {node.value!r}"
                assert not re.search(r"/actions\b", node.value), f"{path.name}: {node.value!r}"


def test_no_task_mutation_of_any_shape_exists_in_the_client():
    """P1-CORR-01 D1: PUT /tasks/{id} is verified, its body is not. Until it is, the client
    sends nothing to a single task by any method, so no guessed payload can exist."""
    pairs, _ = _calls()
    assert {(m, path) for m, path in pairs if path.startswith("tasks")} == set()
    assert {m for m, path in pairs if "tasks" in path} == {"GET"}
    import qradar_soar_mcp.client.tasks as tasks_module

    tree = ast.parse(Path(tasks_module.__file__).read_text(encoding="utf-8"))
    methods = [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not n.name.startswith("_")
    ]
    assert methods == ["list"]


def test_no_forbidden_http_verbs_anywhere_in_client():
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.name.lower() not in FORBIDDEN_VERBS, f"{path.name} defines {node.name}"
            if isinstance(node, ast.Attribute):
                assert node.attr.lower() not in FORBIDDEN_VERBS, f"{path.name} calls .{node.attr}"
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value.upper() not in {"PUT", "DELETE"}, (
                    f"{path.name}: literal {node.value}"
                )


def test_no_phase_two_paths_or_words():
    banned = re.compile(
        r"table_data|/functions|/playbooks|/scripts|/workflows|rest/const|configurations|/contents|/history"
    )
    for path in sorted(CLIENT_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#") or '"""' in line:
                continue
            assert not banned.search(line), f"{path.name}:{lineno}: {line.strip()}"
