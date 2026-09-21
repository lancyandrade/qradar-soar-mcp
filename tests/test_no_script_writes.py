"""P2-02 acceptance (06 P2-02, 08 §26): no write path for scripts exists anywhere in the
product code. This is the roadmap's "grep test", done on the syntax tree so that it
cannot be passed by spelling a path differently and does not trip over prose.

What fails it, anywhere under ``src/qradar_soar_mcp``:

* a request helper other than ``get`` (``post``, ``put``, ``patch``, ``patch_object``,
  ``delete``, ``request``, ``stream``, ``send``, ...) whose arguments name a script path,
  whether the path is a literal, an f-string, an ``org_path(...)`` call, a local variable
  assigned from one of those, or a concatenation;
* a script path literal outside ``client/discovery.py``, or one inside it that is not an
  argument of ``self._c.get(...)``;
* an ``org_path(...)`` whose collection is not a literal (``org_path(f"{kind}/{id}")``,
  ``org_path(path)``): a helper that takes its collection from a caller could be pointed
  at scripts without ever naming them. ``test_client_surface_ast.py`` refuses such a call
  as well, by pinning every (method, path) of ``client/`` to an allow-list;
* a function, method or MCP tool whose name says it creates, changes, removes, deploys or
  runs a script, or a client method about scripts beyond the two reads;
* ``exec``, ``eval``, ``compile``, a dynamic import or a subprocess in the modules that
  handle script source: the body is shown, never run.

The detector is tested against the mutations it exists to catch, so an empty result means
"none found", not "cannot see".
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

import qradar_soar_mcp
from qradar_soar_mcp.client.discovery import DiscoveryClient
from qradar_soar_mcp.config import ConfigError, Settings
from qradar_soar_mcp.tools import TOOL_REGISTRY

PKG = Path(qradar_soar_mcp.__file__).parent
SCRIPT_READER = "client/discovery.py"  # the only module that may name a script path
# The modules through which script source passes.
SOURCE_HANDLERS = ("client/discovery.py", "tools/discovery.py", "tools/projection.py")

# ``scripts`` or ``script`` as a whole path segment: "scripts", "scripts/{id}",
# "/rest/orgs/1/scripts/7", "playbooks/1/scripts". Not "descriptions", not "script_text".
SCRIPT_PATH = re.compile(r"(?:^|/)scripts?(?:/|$)")
# Every way product code could send a request. ``get`` is the one allowed near a script.
REQUEST_HELPERS = {
    "get",
    "post",
    "put",
    "patch",
    "patch_object",
    "delete",
    "head",
    "options",
    "request",
    "stream",
    "send",
    "build_request",
}
WRITE_WORDS = (
    "create|add|new|update|edit|modify|change|write|save|store|set|put|patch|post|upload|"
    "import|deploy|publish|enable|disable|rename|delete|remove|destroy|drop|run|exec|execute|"
    "eval|invoke|compile"
)
MUTATING_NAME = re.compile(rf"(?:^|_)(?:{WRITE_WORDS})_(?:\w+_)?scripts?(?:_|$)", re.IGNORECASE)
MUTATING_NAME_REVERSED = re.compile(rf"(?:^|_)scripts?_(?:{WRITE_WORDS})(?:_|$)", re.IGNORECASE)
FORBIDDEN_CALLS = {"exec", "eval", "compile", "__import__", "import_module", "run_path"}
FORBIDDEN_MODULES = {"subprocess", "importlib", "runpy", "code", "codeop", "pickle", "marshal"}


def _render(node: ast.AST, names: dict[str, str]) -> str:
    """The text a path expression can be seen to contain; placeholders become ``{}``."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else ""
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}"
            for v in node.values
        )
    if isinstance(node, ast.Name):
        return names.get(node.id, "")
    if isinstance(node, ast.BinOp):
        return _render(node.left, names) + _render(node.right, names)
    if isinstance(node, ast.Call):
        parts = [*node.args, *(k.value for k in node.keywords)]
        if isinstance(node.func, ast.Attribute):
            parts.append(node.func.value)  # "scripts/{}".format(...), "/".join([...])
        return "/".join(filter(None, (_render(p, names) for p in parts)))
    if isinstance(node, ast.List | ast.Tuple):
        return "/".join(filter(None, (_render(e, names) for e in node.elts)))
    return ""


def _is_script_path(text: str) -> bool:
    return SCRIPT_PATH.search(text) is not None


def _is_path_literal(text: str) -> bool:
    """A string that is a script path by itself: it has a slash and no whitespace. The bare
    word ``scripts`` is also the name of a catalog section, so alone it proves nothing; as
    the argument of ``org_path`` or of a request helper it is caught by the other rules."""
    return "/" in text and not re.search(r"\s", text) and _is_script_path(text)


def _is_org_path(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "org_path"
    )


def _script_paths(tree: ast.AST) -> list[tuple[ast.AST, str]]:
    """Every expression that names a script path: ``org_path(...)`` calls and literals."""
    out: list[tuple[ast.AST, str]] = []
    for node in ast.walk(tree):
        if _is_org_path(node):
            assert isinstance(node, ast.Call)
            text = _render(ast.Tuple(elts=list(node.args)), {})
            if _is_script_path(text):
                out.append((node, text))
        elif isinstance(node, ast.Constant | ast.JoinedStr):
            text = _render(node, {})
            if _is_path_literal(text):
                out.append((node, text))
    return out


def violations(source: str, filename: str) -> list[str]:
    """Every way ``source`` could write a script, or reach one other than by ``get``."""
    tree = ast.parse(source, filename=filename)
    found: list[str] = []
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    inside_a_get: set[int] = set()
    for scope in (tree, *functions):
        names: dict[str, str] = {}
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                rendered = _render(node.value, names)
                for target in targets:
                    if isinstance(target, ast.Name) and rendered:
                        names[target.id] = rendered
        for node in ast.walk(scope):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in REQUEST_HELPERS
            ):
                continue
            arguments = ast.Tuple(elts=[*node.args, *(k.value for k in node.keywords)])
            if not _is_script_path(_render(arguments, names)):
                continue
            if node.func.attr == "get":
                inside_a_get.update(id(n) for n in ast.walk(node))
            else:
                found.append(f"{filename}:{node.lineno}: .{node.func.attr}() on a script path")
    for node in ast.walk(tree):
        if _is_org_path(node):
            assert isinstance(node, ast.Call)
            collection = _render(ast.Tuple(elts=list(node.args)), {}).lstrip("/")
            if not re.match(r"[A-Za-z_]", collection):
                found.append(
                    f"{filename}:{node.lineno}: org_path() whose collection is not a literal"
                )
    for node, text in _script_paths(tree):
        line = getattr(node, "lineno", 0)
        if filename != SCRIPT_READER:
            found.append(f"{filename}:{line}: names the script path {text!r}")
        elif id(node) not in inside_a_get:
            found.append(f"{filename}:{line}: script path {text!r} outside a get()")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and (
            MUTATING_NAME.search(node.name) or MUTATING_NAME_REVERSED.search(node.name)
        ):
            found.append(f"{filename}:{node.lineno}: {node.name} is named like a script write")
    return sorted(set(found))


def _product_modules() -> list[tuple[str, str]]:
    return [
        (path.relative_to(PKG).as_posix(), path.read_text(encoding="utf-8"))
        for path in sorted(PKG.rglob("*.py"))
    ]


# ------------------------------------------------------------ the product
def test_no_product_module_can_write_a_script():
    modules = _product_modules()
    assert len(modules) > 30 and SCRIPT_READER in dict(modules)
    found = [v for name, source in modules for v in violations(source, name)]
    assert found == [], "a script write path exists:\n" + "\n".join(found)


def test_the_script_reads_are_the_two_verified_gets_and_nothing_else():
    source = dict(_product_modules())[SCRIPT_READER]
    tree = ast.parse(source)
    paths = sorted(text for node, text in _script_paths(tree) if _is_org_path(node))
    assert paths == ["scripts", "scripts/{}"]
    methods = {
        name: list(inspect.signature(member).parameters)
        for name, member in inspect.getmembers(DiscoveryClient, inspect.isfunction)
        if "script" in name.lower()
    }
    assert methods == {"scripts": ["self"], "script_source": ["self", "script_id"]}


def test_no_tool_writes_or_runs_a_script():
    about_scripts = {name: spec for name, spec in TOOL_REGISTRY.items() if "script" in name}
    assert set(about_scripts) == {"soar_list_scripts", "soar_get_script"}
    for name, spec in about_scripts.items():
        assert int(spec.tier) == 0 and spec.capability is None and spec.mutations == 0, name
        assert not spec.mutating and not spec.needs_approval_arg, name
    for name, spec in TOOL_REGISTRY.items():
        params = set(inspect.signature(spec.func).parameters)
        assert not {p for p in params if "script_text" in p or p in {"body", "source"}}, name


def test_no_capability_can_enable_script_writes():
    from qradar_soar_mcp.config import CAPABILITY_FLAGS
    from qradar_soar_mcp.security.tiers import CAPABILITY_TIERS

    assert not [flag for flag in (*CAPABILITY_FLAGS, *CAPABILITY_TIERS) if "SCRIPT" in flag]
    with pytest.raises(ConfigError, match="SOAR_ALLOW_SCRIPT_WRITES"):
        Settings.load({"SOAR_ALLOW_SCRIPT_WRITES": "true"})


@pytest.mark.parametrize("module", SOURCE_HANDLERS)
def test_script_source_is_never_run_imported_or_evaluated(module: str):
    tree = ast.parse(dict(_product_modules())[module])
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            assert name not in FORBIDDEN_CALLS, f"{module}:{node.lineno}: {name}()"
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in FORBIDDEN_MODULES, f"{module}: {alias.name}"
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in FORBIDDEN_MODULES, (
                f"{module}: from {node.module}"
            )


# ------------------------------------------------- the detector detects
CLEAN = """
class DiscoveryClient:
    async def scripts(self):
        return await self._c.get(self._c.org_path("scripts"))

    async def script_source(self, script_id):
        return await self._c.get(self._c.org_path(f"scripts/{int(script_id)}"))
"""

MUTATIONS = {
    "post to the collection": 'await self._c.post(self._c.org_path("scripts"), json_body=b)',
    "put to one script": 'await self._c.put(self._c.org_path(f"scripts/{script_id}"), json_body=b)',
    "patch one script": 'await self._c.patch(self._c.org_path(f"scripts/{sid}"), json_body=b)',
    "patch_object": 'await self._c.patch_object(self._c.org_path(f"scripts/{sid}"), b)',
    "delete one script": 'await self._c.delete(self._c.org_path(f"scripts/{sid}"))',
    "generic request": 'await self._c.request("DELETE", self._c.org_path(f"scripts/{sid}"))',
    "generic request, keyword": 'await c.request(method="PUT", path=f"/rest/orgs/1/scripts/{sid}")',
    "through a local name": (
        'path = self._c.org_path(f"scripts/{sid}")\n        await self._c.put(path, json_body=b)'
    ),
    "concatenated": 'await self._c.post(self._c.org_path("scripts/" + str(sid)), json_body=b)',
    "formatted": 'await self._c.post(self._c.org_path("scripts/{}".format(sid)), json_body=b)',
    "raw httpx": 'await self._http.post(f"/rest/orgs/{org}/scripts", json=b)',
    "streamed": 'self._http.stream("PUT", f"/rest/orgs/{org}/scripts/{sid}")',
    "playbook-local script": (
        'await self._c.post(self._c.org_path(f"playbooks/{pid}/scripts"), json_body=b)'
    ),
    "a path held outside a get": 'WRITE_TARGET = "scripts/query_paged"',
    "a caller-chosen collection": (
        'await self._c.patch(self._c.org_path(f"{kind}/{sid}"), json_body=b)'
    ),
    "a caller-chosen path": "await self._c.post(self._c.org_path(sid), json_body=b)",
}


def test_the_detector_passes_the_two_reads():
    assert violations(CLEAN, SCRIPT_READER) == []


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_the_detector_catches(name: str):
    source = CLEAN + f"\n    async def anything(self, sid, b):\n        {MUTATIONS[name]}\n"
    assert violations(source, SCRIPT_READER), name


def test_the_detector_catches_a_script_path_in_any_other_module():
    source = 'async def f(c):\n    return await c.get(c.org_path("scripts"))\n'
    assert violations(source, SCRIPT_READER) == []
    assert violations(source, "client/incidents.py")
    assert violations(source, "tools/discovery.py")


@pytest.mark.parametrize(
    "name",
    [
        "create_script",
        "update_script",
        "delete_scripts",
        "save_playbook_script",
        "script_update",
        "soar_run_script",
        "soar_set_script",
        "deploy_script",
    ],
)
def test_the_detector_catches_a_function_named_like_a_script_write(name: str):
    assert violations(f"async def {name}(self):\n    return None\n", "tools/discovery.py")


@pytest.mark.parametrize(
    "name",
    [
        "scripts",
        "script_source",
        "parse_script",
        "summarise_script",
        "describe_script",
        "script_body",
        "soar_get_script",
        "soar_list_scripts",
        "description",
    ],
)
def test_the_detector_leaves_the_read_names_alone(name: str):
    assert violations(f"async def {name}(self):\n    return None\n", "tools/discovery.py") == []
