"""P1-04 / 08 §4: client/ may only call the Phase-1 known-good REST surface.

Enforced by AST inspection: every ``org_path(...)`` argument and every absolute
``/rest/...`` literal in the client package must match the allow-list, and no
client module may use an HTTP verb other than GET, POST or PATCH.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import qradar_soar_mcp.client as client_pkg

CLIENT_DIR = Path(client_pkg.__file__).parent

ALLOWED_ORG_SUFFIXES = {
    "incidents/query_paged",
    "incidents",
    "incidents/{id}",
    "incidents/{id}/tasks",
    "tasks/{id}",
    "incidents/{id}/artifacts",
    "incidents/{id}/comments",
    "incidents/{id}/attachments",
    "users",
    "types/incident/fields",
    "incidents/{id}/actions",
    "incidents/{id}/action_invocations",
}
ALLOWED_ABSOLUTE = {"/rest/session"}
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


def test_every_org_path_is_on_the_allow_list():
    seen: set[str] = set()
    for path, tree in _modules():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "org_path"
            ):
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
