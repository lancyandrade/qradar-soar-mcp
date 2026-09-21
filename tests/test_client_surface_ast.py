"""P1-04 / 08 §4: client/ may only call the known-good REST surface: Phase 1, plus the
read-only discovery calls of P2-01 (08 §25), which live in ``discovery.py`` and nowhere else.

Enforced by AST inspection:

* every ``org_path(...)`` argument and every absolute ``/rest/...`` literal in the
  client package is on the allow-list;
* every call of a verb helper (``get``, ``post``, ``patch``, ``patch_object``,
  ``put``) is an allowed *(method, path)* pair, so ``PATCH`` exists for
  ``incidents/{id}`` only and ``PUT`` for ``tasks/{id}`` only (08 §4 as amended by
  §21 and §24, P1-CORR-01 and P1-CORR-02);
* the three calls the verified record retired for QRadar SOAR 51.0.9.0.20848
  appear nowhere;
* a single task is reached by exactly the two verified calls, ``GET`` and ``PUT
  /tasks/{id}``, from the task client only;
* no client module defines or calls DELETE, HEAD or OPTIONS, and ``put`` is defined
  once, in ``base.py``;
* the discovery calls are exactly the reads the verified record lists, all ``GET`` but
  the criteria-only playbook query; only ``discovery.py`` names a Phase-2 path; and the
  configuration export, import, execution and single-object Phase-2 reads appear nowhere.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import qradar_soar_mcp.client as client_pkg

CLIENT_DIR = Path(client_pkg.__file__).parent

# 08 §4 as amended by §21 and §24: (method, path) with every placeholder rendered as {id}.
ALLOWED_CALLS = {
    ("GET", "/rest/session"),
    ("POST", "incidents/query_paged"),
    ("GET", "incidents/{id}"),
    ("POST", "incidents"),
    ("PATCH", "incidents/{id}"),
    ("GET", "incidents/{id}/tasks"),
    ("GET", "tasks/{id}"),
    ("PUT", "tasks/{id}"),
    ("GET", "incidents/{id}/artifacts"),
    ("POST", "incidents/{id}/artifacts"),
    ("GET", "incidents/{id}/comments"),
    ("POST", "incidents/{id}/comments"),
    ("GET", "incidents/{id}/attachments"),
    ("GET", "users"),
    ("GET", "types/incident/fields"),
}
# 08 §25 (P2-01): the read-only collection calls of docs/soar-api-verified.md Q1, Q4, Q5
# and §2, as the catalog's collections backend uses them. discovery.py only.
DISCOVERY_MODULE = "discovery.py"
DISCOVERY_CALLS = {
    ("GET", "/rest/const"),
    ("GET", "functions"),
    ("GET", "functions/{id}"),
    ("GET", "types/__function/fields"),
    ("GET", "actions"),
    ("GET", "workflows"),
    ("GET", "scripts"),
    ("GET", "message_destinations"),
    ("GET", "incident_types"),
    ("GET", "phases"),
    ("GET", "groups"),
    ("GET", "types"),
    ("GET", "types/incident/fields"),
    ("GET", "types/task/fields"),
    ("GET", "types/artifact/fields"),
    ("POST", "playbooks/query_paged"),
}
PHASE_ONE_CALLS = frozenset(ALLOWED_CALLS)
ALLOWED_CALLS |= DISCOVERY_CALLS
ALLOWED_ORG_SUFFIXES = {path for _, path in ALLOWED_CALLS if not path.startswith("/rest/")}
ALLOWED_ABSOLUTE = {path for _, path in ALLOWED_CALLS if path.startswith("/rest/")}
# Contradicted on 51.0.9.0.20848 (docs/soar-api-verified.md §3, D1/D3/D4).
RETIRED_CALLS = {
    ("PATCH", "tasks/{id}"),
    ("GET", "incidents/{id}/actions"),
    ("POST", "incidents/{id}/action_invocations"),
}
VERB_HELPERS = {
    "get": "GET",
    "post": "POST",
    "patch": "PATCH",
    "patch_object": "PATCH",
    "put": "PUT",
}
FORBIDDEN_VERBS = {"delete", "head", "options"}


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


def _calls(
    only: str | None = None, skip: str | None = None
) -> tuple[set[tuple[str, str]], list[str]]:
    """Every (method, path) the client sends, and the call sites it could not resolve."""
    pairs: set[tuple[str, str]] = set()
    unresolved: list[str] = []
    for path, tree in _modules():
        if (only is not None and path.name != only) or path.name == skip:
            continue
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


def test_a_single_task_is_reached_by_the_two_verified_calls_only():
    """P1-CORR-02 (08 §24): GET and PUT /tasks/{id}, as P2-00b verified them, and PUT
    exists for nothing else. No PATCH, no POST, no task-tree read."""
    pairs, _ = _calls()
    assert {(m, path) for m, path in pairs if path.startswith("tasks")} == {
        ("GET", "tasks/{id}"),
        ("PUT", "tasks/{id}"),
    }
    assert {path for m, path in pairs if m == "PUT"} == {"tasks/{id}"}
    assert not any("tasktree" in path for _, path in pairs)
    import qradar_soar_mcp.client.tasks as tasks_module

    tree = ast.parse(Path(tasks_module.__file__).read_text(encoding="utf-8"))
    methods = [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not n.name.startswith("_")
    ]
    assert methods == ["list", "get", "set_status"]
    # Only the task client calls put, and only base.py defines it.
    for path, module in _modules():
        for node in ast.walk(module):
            if isinstance(node, ast.Attribute) and node.attr == "put":
                assert path.name == "tasks.py", f"{path.name} calls .put"
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "put":
                assert path.name == "base.py", f"{path.name} defines put"


def test_no_forbidden_http_verbs_anywhere_in_client():
    for path, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.name.lower() not in FORBIDDEN_VERBS, f"{path.name} defines {node.name}"
            if isinstance(node, ast.Attribute):
                assert node.attr.lower() not in FORBIDDEN_VERBS, f"{path.name} calls .{node.attr}"
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value.upper() != "DELETE", f"{path.name}: literal {node.value}"
                # The PUT literal lives where request() checks the method and its one path.
                assert node.value.upper() != "PUT" or path.name == "base.py", (
                    f"{path.name}: literal {node.value}"
                )


def test_no_phase_two_paths_or_words():
    """Outside ``discovery.py`` the Phase-1 rule is unchanged."""
    banned = re.compile(
        r"table_data|/functions|/playbooks|/scripts|/workflows|rest/const|configurations|/contents|/history"
    )
    for path in sorted(CLIENT_DIR.glob("*.py")):
        if path.name == DISCOVERY_MODULE:
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#") or '"""' in line:
                continue
            assert not banned.search(line), f"{path.name}:{lineno}: {line.strip()}"


# ------------------------------------------------------------ P2-01 discovery
def test_the_discovery_module_makes_exactly_the_verified_reads():
    pairs, unresolved = _calls(only=DISCOVERY_MODULE)
    assert unresolved == []
    assert pairs == DISCOVERY_CALLS
    assert {m for m, _ in pairs} == {"GET", "POST"}
    assert {path for m, path in pairs if m == "POST"} == {"playbooks/query_paged"}


def test_the_phase_one_modules_gained_no_call():
    pairs, _ = _calls(skip=DISCOVERY_MODULE)
    assert pairs == PHASE_ONE_CALLS


def test_discovery_is_read_only_and_names_no_unverified_or_privileged_call():
    text = (CLIENT_DIR / DISCOVERY_MODULE).read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"patch", "patch_object", "put", "request"}, node.attr
    strings = [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    docstring = ast.get_docstring(tree) or ""
    for literal in strings:
        if literal.strip() == docstring.strip() or "\n" in literal:
            continue  # prose
        for word in (
            "configurations",
            "exports",
            "imports",
            "execution",
            "tasktree",
            "table_data",
            "/contents",
            "/history",
            "apikeys",
            "permissions",
            "session",
        ):
            assert word not in literal, f"discovery.py names {word!r}: {literal!r}"
    # The GET playbook collection answers 500 on this version: listing is the POST only.
    pairs, _ = _calls(only=DISCOVERY_MODULE)
    assert {(m, path) for m, path in pairs if path.startswith("playbooks")} == {
        ("POST", "playbooks/query_paged")
    }


def test_the_playbook_query_body_is_built_in_the_client_from_two_integers():
    """The one POST is criteria-only by construction: no caller-supplied body or filter."""
    tree = ast.parse((CLIENT_DIR / DISCOVERY_MODULE).read_text(encoding="utf-8"))
    posts = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "post"
    ]
    assert len(posts) == 1
    body = next(k.value for k in posts[0].keywords if k.arg == "json_body")
    assert isinstance(body, ast.Dict)
    assert [k.value for k in body.keys if isinstance(k, ast.Constant)] == [
        "filters",
        "start",
        "length",
    ]
    filters = body.values[0]
    assert isinstance(filters, ast.List) and filters.elts == []
    method = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "playbooks_page"
    )
    assert [a.arg for a in method.args.kwonlyargs] == ["start", "length"]
    assert [a.arg for a in method.args.args] == ["self"]


def test_no_discovery_method_takes_a_path_a_method_or_a_body():
    tree = ast.parse((CLIENT_DIR / DISCOVERY_MODULE).read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
    for fn in cls.body:
        if isinstance(fn, ast.AsyncFunctionDef):
            names = {a.arg for a in (*fn.args.args, *fn.args.kwonlyargs)} - {"self"}
            assert names <= {"function_id", "type_name", "start", "length"}, (fn.name, names)
