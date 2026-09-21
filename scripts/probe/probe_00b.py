"""P2-00b: close the remaining P2-00 research gaps. Read-only; verified TLS only.

    uv run python scripts/probe/guarded.py probe_00b.py --only preflight
    uv run python scripts/probe/guarded.py probe_00b.py --doc-index --grep Task
    uv run python scripts/probe/guarded.py probe_00b.py --doc-page resource_TaskREST.html \
        --grep "tasks/\\{task_id\\}" --context 15
    uv run python scripts/probe/guarded.py probe_00b.py      # preflight, then every read step

What is different from ``probe.py``:

* **TLS is verified or the run does not start.** The context is built from
  ``SOAR_CA_BUNDLE`` / ``P2_PROBE_CA_BUNDLE`` (or Python's default TLS trust
  configuration when neither is set), with the chain and the host name checked.
  ``tls_check.inspect`` is deliberately NOT used here: it opens one unverified
  handshake to describe the certificate, and P2-00b never connects unverified.
  ``lab-pinned`` and ``SOAR_VERIFY_SSL=false`` are refused.
* **One added request, opt-in.** Everything still goes through
  ``safe_http.ReadOnlyClient``: GET, plus the ``query_paged`` POSTs that P2-00
  approved. ``--only execution_query`` adds the single owner-approved
  ``POST playbooks/execution/query_paged`` (one exact body, once, never retried). No
  PUT, PATCH, DELETE or other POST can be sent from this file.
* **One bounded scan** (at most ``SCAN_LIMIT`` incidents, newest first) serves the
  attachment, carried-``actions`` and comment questions together and stops
  looking for each as soon as it is answered.
* **The on-box API reference is read as text** so that a request *body* can be
  researched without sending it. It is IBM's static documentation, not appliance
  data, but it goes through the same verifier as everything else.

Ids stay in memory. Output is templates, statuses, key names, types, booleans
and buckets.
"""

from __future__ import annotations

import argparse
import contextlib
import html
import json
import re
import ssl
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import task_candidate
from probe import (
    EXPECTED_VERSION,
    INC,
    ORG,
    OUT_DIR,
    Ctx,
    Facts,
    _distribution,
    a_comments,
    a_const,
    a_workflow,
    bucket,
    error_facts,
    own_key_permissions,
    rows_of,
)
from probe_env import ROOT, ProbeEnv, ProbeEnvError, load_env
from safe_http import (
    DEFAULT_MAX_BYTES,
    EXECUTION_QUERY_BODY,
    EXECUTION_QUERY_SUFFIX,
    ReadOnlyClient,
    Result,
)
from sanitise import (
    EnumCollector,
    UnsafeArtefactError,
    dump_verified,
    safe_keys,
    safe_keys_matching,
    safe_text,
    shape_of,
)
from task_candidate import UI_FORMAT_PARAMS

SCAN_LIMIT = 10  # owner-set ceiling for every bounded search in P2-00b
PAGE_LENGTH = 10  # owner-set maximum page length
MAX_PLAYBOOK_PAGES = 10  # playbook definitions only (configuration), never incidents
MAX_DOC_SWEEP = 200  # static reference pages, never appliance data
# The representation the reference's data types describe (json_ObjectHandleFormat,
# json_TextContentOutputFormat): nothing is resolved to a name or converted to plain text.
CANONICAL_PARAMS = {"handle_format": "objects", "text_content_output_format": "objects_no_convert"}
PREFIX = "p2_00b_"
LEDGER = "_ledger_00b.json"
STEPS = ("preflight", "docs", "metadata", "scan", "filters", "workflows", "execution_query")
# IBM's built-in object types. A rule can also target a data table, whose name an
# administrator chose, so any other value is counted and never recorded.
BUILTIN_OBJECT_TYPES = frozenset(
    {"incident", "task", "note", "milestone", "artifact", "attachment", "actioninvocation"}
)
EXIT_MUTATING_KEY = 4
EXIT_DESIGNATED_STOP = 5


class StopResearchError(RuntimeError):
    """A stop condition of the ticket was met. The message is a fixed sentence."""


# ------------------------------------------------------------------------ TLS
def verified_context(env: ProbeEnv) -> tuple[ssl.SSLContext, str]:
    """A context that checks the chain and the host name, or no run at all.

    No network I/O, no fallback, no pinning. Messages name variables, never a path.
    """
    if env.scheme != "https":
        raise SystemExit("SOAR_BASE_URL must be https for the probe")
    if env.tls_mode not in ("auto", "system", "ca-bundle"):
        raise SystemExit("P2-00b runs with verified TLS only: unset P2_PROBE_TLS_MODE")
    if env.verify_ssl.lower() == "false":
        raise SystemExit("P2-00b runs with verified TLS only: SOAR_VERIFY_SSL=false is refused")
    legacy = env.verify_ssl if env.verify_ssl.lower() not in ("true", "") else ""
    named = [b for b in (env.soar_ca_bundle, env.ca_bundle, legacy) if b]
    if len({str(Path(b).resolve()) for b in named}) > 1:
        raise SystemExit("two different CA bundles are configured; refusing to choose one")
    context: ssl.SSLContext | None = None
    # With cafile given, Python's default trust is NOT loaded: the bundle is the trust.
    with contextlib.suppress(ssl.SSLError, OSError, ValueError):
        context = (
            ssl.create_default_context(cafile=named[0]) if named else ssl.create_default_context()
        )
    if context is None:  # raised outside the handler: the error text can carry the path
        raise SystemExit("the configured CA bundle could not be loaded as a PEM bundle")
    label = "ca_bundle" if named else "python_default"
    if not context.check_hostname or context.verify_mode is not ssl.CERT_REQUIRED:
        raise SystemExit("the TLS context does not verify certificates and host names")
    return context, label


# ------------------------------------------------------------------- recorder
@dataclass(slots=True)
class Recorder:
    """Sends through the read-only client, keeps the ledger, writes verified fixtures."""

    env: ProbeEnv
    client: ReadOnlyClient
    out_dir: Path
    echo: Callable[[str], None] = print
    rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    written: list[str] = field(default_factory=list)
    docs_read: list[str] = field(default_factory=list)
    execution_round: str = ""  # names the owner approval an execution query belongs to

    @property
    def literals(self) -> dict[str, str]:
        return self.env.literals()

    @property
    def org(self) -> str:
        return ORG.format(org_id=self.env.org_id)

    def say(self, line: str) -> None:
        self.echo(safe_text(line, self.literals))

    def send(
        self,
        key: str,
        question: str,
        method: str,
        path: str,
        template: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Any = None,
        headers_only: bool = False,
        default_params: bool = True,
        quiet: bool = False,
        max_bytes: int = DEFAULT_MAX_BYTES,
        format_headers: Mapping[str, str] | None = None,
    ) -> Result:
        r = self.client.request(
            method,
            path,
            template,
            params=params,
            json_body=json_body,
            headers_only=headers_only,
            default_params=default_params,
            max_bytes=max_bytes,
            format_headers=format_headers,
        )
        row = self.rows.get(key)
        if row is None:
            self.rows[key] = {"step": key, "question": question, "count": 1, **r.ledger_row()}
        else:  # the same step repeated across the bounded scan: count it, keep every status
            row["count"] += 1
            row["statuses"] = sorted({*row.get("statuses", [row["status"]]), r.status}, key=str)
        if not quiet:
            self.say(
                f"{question:6} {r.method:4} {r.template} -> {r.status or r.error} "
                f"{r.content_type or ''} {r.size_bucket}"
            )
        return r

    def write(
        self,
        key: str,
        question: str,
        r: Result | None,
        facts: Facts,
        *,
        shape_source: Any = None,
        note: str = "",
        name_keyed: bool = False,
    ) -> None:
        enums = EnumCollector()
        shape = (
            shape_of(shape_source, enums=enums, name_keyed=name_keyed)
            if shape_source is not None
            else None
        )
        kept = enums.to_json()
        if "object_type" in kept:
            kept["object_type"] = [
                v for v in kept["object_type"] if str(v).lower() in BUILTIN_OBJECT_TYPES
            ]
        if r is not None and not r.ok and r.json is not None:
            facts = {**facts, "server_error": error_facts(r, self.literals)}
        document = {
            "_fixture": "verified-shape",
            "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
            "_ticket": "P2-00b",
            "_question": question,
            "_request": None
            if r is None
            else {"method": r.method, "path": r.template, "query_keys": list(r.query_keys)},
            "_status": None if r is None else r.status,
            "_content_type": None if r is None else r.content_type,
            "_error": None if r is None else r.error,
            "_note": note,
            "_facts": facts,
            "_enums": kept,
            "shape": shape,
        }
        try:
            dump_verified(self.out_dir / f"{PREFIX}{key}.json", document, self.literals)
            self.written.append(key)
        except UnsafeArtefactError as exc:
            self.say(f"{key} NOT WRITTEN: {exc}")

    def finish(self) -> None:
        previous: dict[str, Any] = {}
        path = self.out_dir / LEDGER
        if path.is_file():
            previous = json.loads(path.read_text(encoding="utf-8"))
        merged = {row["step"]: row for row in previous.get("requests", []) if "step" in row}
        merged.update(self.rows)
        summary = {
            "_fixture": "verified-ledger",
            "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
            "_ticket": "P2-00b",
            "requests": list(merged.values()),
            "documentation_pages_read": sorted(
                {*previous.get("documentation_pages_read", []), *self.docs_read}
            ),
            "refused_by_policy": self.client.refused,
        }
        try:
            dump_verified(path, summary, self.literals)
        except UnsafeArtefactError as exc:
            self.say(f"ledger NOT WRITTEN: {exc}")
        self.say(
            f"{self.client.requests_sent} request(s) sent; {len(self.written)} fixture(s) written "
            f"to {self.out_dir.relative_to(ROOT).as_posix()}; refused by policy: "
            f"{len(self.client.refused)}"
        )


# ------------------------------------------------------- on-box documentation
DOC_BASE = "/docs/rest-api/"
_PAGE = re.compile(r"^[A-Za-z0-9_]{1,120}\.html$")
_HREF = re.compile(r'href="([A-Za-z0-9_]{1,120}\.html)(?:#[^"]*)?"')
_ANY_HREF = re.compile(r'(?:href|src)="([^"#]{1,200})(?:#[^"]*)?"')
_ANCHOR = re.compile(r'(?i)<a\s[^>]*href="([A-Za-z0-9_]{1,120})\.html(?:#[^"]*)?"[^>]*>')
_DROP = re.compile(r"(?is)<(script|style|head)\b.*?</\1>")
_BREAK = re.compile(
    r"(?i)</(tr|p|div|h[1-6]|li|table|caption|pre|dt|dd|ul|ol|section|thead)>|<br\s*/?>"
)
_CELL = re.compile(r"(?i)</t[dh]>")
_TAG = re.compile(r"<[^>]+>")
_SPACE = re.compile(r"[ \t\r\f\v]+")


def doc_lines(body: bytes) -> list[str]:
    """A documentation page as plain lines; a link to another page becomes ``[[page]]``."""
    text = _DROP.sub(" ", body.decode("utf-8", "replace"))
    text = _ANCHOR.sub(r" [[\1]] ", text)
    text = _CELL.sub(" | ", _BREAK.sub("\n", text))
    text = html.unescape(_TAG.sub(" ", text))
    lines = (_SPACE.sub(" ", line).strip() for line in text.split("\n"))
    return [line for line in lines if line]


def fetch_doc(rec: Recorder, page: str) -> Result | None:
    if not _PAGE.match(page):
        rec.say("a documentation page is named like resource_TaskREST.html")
        return None
    r = rec.send(
        f"doc:{page}", "docs", "GET", DOC_BASE + page, DOC_BASE + page, default_params=False,
        quiet=True,
    )  # fmt: skip
    if r.ok:
        rec.docs_read.append(page)
    return r


def doc_index(rec: Recorder, pattern: str) -> None:
    r = fetch_doc(rec, "index.html")
    if r is None or not r.ok:
        rec.say(f"documentation index -> {None if r is None else r.status or r.error}")
        return
    text = r.body.decode("utf-8", "replace")
    pages = sorted(set(_HREF.findall(text)))
    rx = re.compile(pattern, re.I)
    wanted = [p for p in pages if rx.search(p)]
    rec.say(f"documentation index: {len(pages)} page(s); {len(wanted)} match")
    for page in wanted[:300]:
        rec.say("  " + page)
    # Anything the reference links to that is NOT one of its own pages: a machine-readable
    # description (OpenAPI, WADL, XSD) would be evidence for a request schema.
    others = sorted({h for h in _ANY_HREF.findall(text) if not _PAGE.match(h)})
    rec.say(f"other link target(s): {len(others)}")
    for target in others[:60]:
        rec.say("  " + target[:120])


def doc_page(
    rec: Recorder,
    page: str,
    pattern: str,
    context: int,
    max_lines: int,
    span: tuple[int, int] | None = None,
) -> None:
    r = fetch_doc(rec, page)
    if r is None or not r.ok:
        rec.say(f"{page} -> {None if r is None else r.status or r.error}")
        return
    lines = doc_lines(r.body)
    rx = re.compile(pattern, re.I)
    keep: set[int] = set()
    for i, line in enumerate(lines):
        if span is not None and not span[0] <= i <= span[1]:
            continue
        if rx.search(line):
            keep.update(range(max(0, i - context), min(len(lines), i + context + 1)))
    rec.say(f"{page}: {len(lines)} line(s); {len(keep)} shown")
    last = -1
    for i in sorted(keep)[:max_lines]:
        if last >= 0 and i != last + 1:
            rec.say("    ...")
        rec.say(f"{i:5} {lines[i][:400]}")
        last = i


# Where a generated reference conventionally puts a machine-readable description of its
# requests. A closed list: nothing here is taken from the command line or from a response.
DOC_ARTIFACTS = (
    "swagger.json", "openapi.json", "openapi.yaml", "ui/swagger.json", "ui/index.html",
    "application.wadl", "downloads.html", "syntax_json.html", "data.html",
)  # fmt: skip


DOC_ROOTS = ("/docs/", "/docs/index.html")  # a closed list


def doc_artifacts(rec: Recorder) -> None:
    """Does the reference ship an OpenAPI/WADL description? Status and media type only."""
    found: dict[str, Any] = {}
    for name in DOC_ARTIFACTS:
        r = rec.send(
            f"doc:{name}", "docs", "GET", DOC_BASE + name, DOC_BASE + name, default_params=False,
            headers_only=True, quiet=True,
        )  # fmt: skip
        found[name] = {"status": r.status, "content_type": r.content_type}
        rec.say(f"docs   {name}: {r.status or r.error} {r.content_type or ''}")
    # Is anything other than the REST reference published under /docs/ (a product guide)?
    roots: dict[str, Any] = {}
    for root in DOC_ROOTS:
        r = rec.send(f"doc:{root}", "docs", "GET", root, root, default_params=False, quiet=True)
        links = sorted(set(_ANY_HREF.findall(r.body.decode("utf-8", "replace")))) if r.ok else []
        local = [h for h in links if ":" not in h and not h.startswith(("#", "//"))]
        roots[root] = {"status": r.status, "content_type": r.content_type,
                       "local_links": bucket(len(local))}  # fmt: skip
        rec.say(f"docs   {root}: {r.status or r.error} {r.content_type or ''}")
        for link in local[:25]:
            rec.say("         -> " + link[:100])
    rec.write(
        "doc_artifacts", "docs", None, {"candidates": found, "documentation_roots": roots},
        note="is a machine-readable request schema published next to the reference?",
    )  # fmt: skip


SWAGGER = "ui/swagger.json"
_TEMPLATE_PATH = re.compile(r"^/[A-Za-z_{}/.-]{1,160}$")  # no digits: nothing appliance-specific
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,40}$")
LIVE_ONLY_TASK_KEYS = ("auto_deactivate", "form", "task_layout", "user_notes")


def _ref(node: object) -> str | None:
    ref = node.get("$ref") if isinstance(node, Mapping) else None
    name = ref.rsplit("/", 1)[-1] if isinstance(ref, str) else ""
    return name if _IDENT.match(name) else None


def _schema(node: object) -> Facts:
    """A schema node as type name and references. Descriptions and examples are never kept."""
    if not isinstance(node, Mapping):
        return {}
    kind = node.get("type")
    return {
        "type": kind if isinstance(kind, str) and _TOKEN.match(kind) else None,
        "ref": _ref(node) or _ref(node.get("items")),
        "read_only": node.get("readOnly") is True,
    }


def _definition(definitions: Mapping[str, Any], name: str | None) -> Facts:
    node = definitions.get(name) if name else None
    if not isinstance(node, Mapping):
        return {"found": False}
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    required = node.get("required") if isinstance(node.get("required"), list) else []
    return {
        "found": True,
        "properties": {k: _schema(v) for k, v in props.items() if _IDENT.match(str(k))},
        "read_only_properties": sorted(
            k for k, v in props.items() if isinstance(v, Mapping) and v.get("readOnly") is True
        ),
        "required": sorted(k for k in required if isinstance(k, str) and _IDENT.match(k)),
        "has_example": "example" in node,
        "composed_of": [r for r in map(_ref, node.get("allOf", [])) if r]
        if isinstance(node.get("allOf"), list) else [],
    }  # fmt: skip


def _operation(op: object) -> Facts:
    if not isinstance(op, Mapping):
        return {"documented": False}
    params = [x for x in op.get("parameters", []) if isinstance(x, Mapping)]
    body = next((x for x in params if x.get("in") == "body"), None)
    responses = op.get("responses") if isinstance(op.get("responses"), Mapping) else {}
    return {
        "documented": True,
        "consumes": [c for c in op.get("consumes", []) if isinstance(c, str) and len(c) < 60],
        "parameters": {
            str(x.get("name")): str(x.get("in")) for x in params
            if re.match(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$", str(x.get("name")))
        },
        "body_parameter_required": None if body is None else body.get("required") is True,
        "request_schema": _schema(body.get("schema")) if body else None,
        "request_example_present": bool(body) and any(
            k in body or (isinstance(body.get("schema"), Mapping) and k in body["schema"])
            for k in ("example", "examples", "x-example", "x-examples")
        ),
        "responses": {
            str(code): _schema(node.get("schema")) if isinstance(node, Mapping) else {}
            for code, node in responses.items() if re.match(r"^[0-9]{3}$|^default$", str(code))
        },
    }  # fmt: skip


def doc_swagger(rec: Recorder, pattern: str) -> None:
    """The machine-readable description next to the reference: the task PUT, as a schema."""
    r = rec.send(
        f"doc:{SWAGGER}", "docs", "GET", DOC_BASE + SWAGGER, DOC_BASE + SWAGGER,
        default_params=False, max_bytes=60_000_000,
    )  # fmt: skip
    spec = r.json if isinstance(r.json, Mapping) else {}
    paths = spec.get("paths") if isinstance(spec.get("paths"), Mapping) else {}
    definitions = spec.get("definitions") if isinstance(spec.get("definitions"), Mapping) else {}
    if not paths:
        rec.say(f"docs   {SWAGGER}: no paths (status {r.status}, truncated={r.truncated})")
        return
    version = spec.get("swagger") or spec.get("openapi")
    task = next((v for k, v in paths.items() if str(k).endswith("/tasks/{task_id}")), {})
    task = task if isinstance(task, Mapping) else {}
    put, get = _operation(task.get("put")), _operation(task.get("get"))
    request_ref = (put.get("request_schema") or {}).get("ref")
    response_ref = (get.get("responses", {}).get("200") or {}).get("ref")
    body = _definition(definitions, request_ref)
    rx = re.compile(pattern, re.I)
    matching = sorted(
        f"{method.upper()} {path}" for path, ops in paths.items()
        if isinstance(ops, Mapping) and _TEMPLATE_PATH.match(str(path)) and rx.search(str(path))
        for method in ops if method in ("get", "put", "post", "delete", "patch")
    )  # fmt: skip
    task_bodies = sorted(
        f"{method.upper()} {path} -> {ref}" for path, ops in paths.items()
        if isinstance(ops, Mapping) and _TEMPLATE_PATH.match(str(path))
        for method, op in ops.items() if method in ("put", "post", "patch")
        if (ref := (_operation(op).get("request_schema") or {}).get("ref")) and "Task" in ref
    )  # fmt: skip
    facts = {
        "spec_version": version
        if isinstance(version, str) and re.match(r"^[0-9]{1,2}(\.[0-9]{1,2}){1,2}$", version)
        else None,
        "operations_whose_body_is_a_task_type": task_bodies[:40],
        "definitions_named_like_a_task": sorted(
            k for k in definitions if _IDENT.match(str(k)) and "Task" in str(k)
        )[:40],
        "task_get_response_has_a_schema": bool(response_ref),
        "top_level_keys": safe_keys(spec),
        "paths": bucket(len(paths)),
        "definitions": bucket(len(definitions)),
        "task_put": put,
        "task_get_response_ref": response_ref,
        "task_put_request_ref": request_ref,
        "request_body_definition": body,
        "live_only_task_keys_in_request_definition": {
            k: k in body.get("properties", {}) for k in LIVE_ONLY_TASK_KEYS
        },
        "paths_matching": {"pattern": pattern, "operations": matching[:80]},
    }
    rec.write(
        "doc_swagger_task_put", "docs", None, facts,
        note="schema facts from the description published next to the reference; no prose",
    )  # fmt: skip
    brief = {k: v for k, v in facts.items() if k != "request_body_definition"}
    rec.say(f"docs   swagger: {json.dumps(brief, sort_keys=True)}")
    rec.say(
        "docs   request body definition: "
        + json.dumps({k: v for k, v in body.items() if k != "properties"}, sort_keys=True)
    )
    rec.say(f"docs   request body properties: {sorted(body.get('properties', {}))}")


def doc_swagger_grep(rec: Recorder, pattern: str, max_hits: int = 120) -> None:
    """Where does the published description mention ``pattern``? For a human to read.

    One static GET. Matches on a data type's or a property's name or description, and on an
    operation's summary. Lines go through the same verifier as everything else; nothing is
    stored: what is learned is recorded by hand, as a paraphrase, in the research notes.
    """
    r = rec.send(
        f"doc:{SWAGGER}", "docs", "GET", DOC_BASE + SWAGGER, DOC_BASE + SWAGGER,
        default_params=False, max_bytes=60_000_000, quiet=True,
    )  # fmt: skip
    spec = r.json if isinstance(r.json, Mapping) else {}
    definitions = spec.get("definitions") if isinstance(spec.get("definitions"), Mapping) else {}
    paths = spec.get("paths") if isinstance(spec.get("paths"), Mapping) else {}
    rx = re.compile(pattern, re.I)
    hits: list[str] = []

    def text_of(node: Mapping[str, Any]) -> str:
        said = node.get("description")
        return " ".join(said.split())[:420] if isinstance(said, str) else ""

    for name, node in definitions.items():
        if not isinstance(node, Mapping) or not _IDENT.match(str(name)):
            continue
        if rx.search(str(name)) or rx.search(text_of(node)):
            hits.append(f"{name}: {text_of(node)}")
        props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
        for key, prop in props.items():
            if not isinstance(prop, Mapping) or not _IDENT.match(str(key)):
                continue
            if rx.search(str(key)) or rx.search(text_of(prop)):
                facts = _schema(prop)
                kind = facts.get("ref") or facts.get("type")
                hits.append(
                    f"{name}.{key} [{kind}; readOnly={facts.get('read_only')}]: {text_of(prop)}"
                )
    for path, ops in paths.items():
        if not isinstance(ops, Mapping) or not _TEMPLATE_PATH.match(str(path)):
            continue
        for method, op in ops.items():
            if isinstance(op, Mapping) and method in ("get", "put", "post", "delete", "patch"):
                said = " ".join(str(op.get(k, "")) for k in ("summary", "description"))
                if rx.search(said):
                    hits.append(f"{method.upper()} {path}: {' '.join(said.split())[:420]}")
    rec.say(
        f"swagger: {len(definitions)} data type(s), {len(paths)} path(s); "
        f"{len(hits)} mention(s); showing {min(len(hits), max_hits)}"
    )
    for hit in hits[:max_hits]:
        rec.say("  " + hit)


def doc_find(rec: Recorder, pattern: str) -> None:
    """Which documented endpoints mention ``pattern``? Reads every resource page, once."""
    index = fetch_doc(rec, "index.html")
    if index is None or not index.ok:
        rec.say(f"documentation index -> {None if index is None else index.status or index.error}")
        return
    names = sorted(set(_HREF.findall(index.body.decode("utf-8", "replace"))))
    pages = [p for p in names if p.startswith("resource_")][:MAX_DOC_SWEEP]
    rx = re.compile(pattern, re.I)
    hits: list[str] = []
    for page in pages:
        r = fetch_doc(rec, page)
        lines = doc_lines(r.body) if r is not None and r.ok else []
        heading = ""
        for line in lines:
            heading = line if _SECTION.match(line) else heading
            if rx.search(line) and heading and f"{page}: {heading}" not in hits:
                hits.append(f"{page}: {heading}")
    rec.say(f"{len(pages)} resource page(s) read; {len(hits)} endpoint section(s) match")
    for hit in hits[:80]:
        rec.say("  " + hit)


# What the reference says about a request, recorded as schema facts: type names, property
# names, JSON types, response codes and two flags read from the description. No prose.
_ROW = re.compile(r"(?is)<tr\b[^>]*>(.*?)</tr>")
_CELLS = re.compile(r"(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_TYPE_TEXT = re.compile(r"^[A-Za-z][A-Za-z0-9_ ]{0,80}$")
_SECTION = re.compile(r"^(GET|PUT|POST|DELETE|PATCH) /orgs/")
_TYPE_LINK = re.compile(r"\[\[json_([A-Za-z0-9_]{1,100})\]\]")
_CODE = re.compile(r"^\d{3}$")
_BLOCKS = ("Request Parameters", "Request Body", "Response Codes", "Response Body")
DOC_ENDPOINTS: tuple[tuple[str, str, str, str], ...] = (
    ("task_put", "resource_TaskREST.html", "PUT", "/orgs/{org_id}/tasks/{task_id}"),
    ("task_get", "resource_TaskREST.html", "GET", "/orgs/{org_id}/tasks/{task_id}"),
    ("execution_query", "resource_PlaybookExecutionREST.html", "POST",
     "/orgs/{org_id}/playbooks/execution/query_paged"),
    ("execution_activities", "resource_PlaybookExecutionREST.html", "POST",
     "/orgs/{org_id}/playbooks/execution/{execution_id}/activities"),
    # The only documented consumer of the invoke data types: inbox e-mail messages.
    ("email_action_invocations", "resource_EmailREST.html", "POST",
     "/orgs/{org_id}/email/messages/action_invocations"),
)  # fmt: skip
DOC_TYPES = (
    "TaskDTO", "StatusDTO", "ObjectHandle", "ObjectHandleFormat", "TextContentDTO",
    "TextContentOutputFormat", "ActionInfoDTO", "ActionInvokeDTO", "MultipleActionInvokeDTO",
    "ActionInvocationDTO", "PlaybookActionInfoDTO", "CommentDTO", "QueryFilterDTO",
    "QueryConditionDTO", "LogicType", "PlaybookExecutionDetailDTO",
    "PlaybookExecutionActivityStatusDTO", "ActivityExecutionStatus", "PlaybookExecutionStatus",
)  # fmt: skip
MAX_FOLLOWED_TYPES = 12


def _plain(fragment: str) -> str:
    return " ".join(html.unescape(_TAG.sub(" ", fragment)).split())


def dto_facts(body: bytes) -> Facts:
    """A data-type page: ``{property: {type, constraints, read-only?, create-only?}}``.

    An enum page lists values instead of properties; its tokens are kept the same way.
    """
    properties: dict[str, dict[str, Any]] = {}
    values: list[str] = []
    columns: list[str] = []  # from the header row: a table has 3 columns, or 4 with constraints
    for row in _ROW.findall(_DROP.sub(" ", body.decode("utf-8", "replace"))):
        cells = [_plain(c) for c in _CELLS.findall(row)]
        if re.search(r"(?i)<th\b", row):  # a header is told by its tag: "name" is a property too
            columns = [c.lower() for c in cells]
            continue
        if not cells or not _IDENT.match(cells[0]) or len(cells) != len(columns):
            continue
        cell = dict(zip(columns, cells, strict=True))
        if "data type" in cell:
            said = cell.get("description", "").lower()
            kind, limits = cell["data type"], cell.get("constraints", "")
            properties[cells[0]] = {
                "type": kind if _TYPE_TEXT.match(kind) else "<unparsed>",
                "constraints": limits if _TYPE_TEXT.match(limits) else "",
                "documented_read_only": "readonly" in said or "read only" in said
                or "read-only" in said,
                "documented_create_only": "only used during create" in said,
            }  # fmt: skip
        elif columns[:1] == ["value"]:
            values.append(cells[0])
    return {"properties": properties, "enum_values": values[:40]}


def endpoint_facts(lines: list[str], method: str, path: str) -> Facts:
    """One endpoint section of a resource page: body types, response codes, query parameters."""
    starts = [i for i, line in enumerate(lines) if line == f"{method} {path}"]
    if not starts:
        return {"documented": False}
    start = starts[-1]  # the first occurrence is the table of contents
    end = next((i for i in range(start + 1, len(lines)) if _SECTION.match(lines[i])), len(lines))
    section = lines[start:end]

    def block(label: str) -> list[str]:
        if label not in section:
            return []
        first = section.index(label) + 1
        stop = next((i for i in range(first, len(section)) if section[i] in _BLOCKS), len(section))
        return section[first:stop]

    def cells(label: str) -> list[str]:
        # Table cells, whether the page puts one cell or one row on a line.
        return [c.strip() for c in " ".join(block(label)).split("|")]

    def linked_type(label: str) -> str | None:
        found = _TYPE_LINK.search(" ".join(block(label)))
        return found.group(1) if found else None

    params = cells("Request Parameters")
    return {
        "documented": True,
        "request_body_type": linked_type("Request Body"),
        "response_body_type": linked_type("Response Body"),
        "response_codes": [int(c) for c in cells("Response Codes") if _CODE.match(c)],
        "parameters": {params[i - 1]: c for i, c in enumerate(params)
                       if c in ("query", "header", "path") and i
                       and re.match(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$", params[i - 1])},
    }  # fmt: skip


def docs(rec: Recorder, ctx: Ctx) -> None:
    """The documented contract of the requests this ticket must NOT send blind."""
    pages: dict[str, list[str]] = {}
    wanted = list(DOC_TYPES)
    for key, page, method, path in DOC_ENDPOINTS:
        if page not in pages:
            r = fetch_doc(rec, page)
            pages[page] = doc_lines(r.body) if r is not None and r.ok else []
        facts = endpoint_facts(pages[page], method, path)
        rec.write(
            f"doc_{key}", "docs", None, {"method": method, "path": path, **facts},
            note="from the appliance's own API reference; the request itself was not sent",
        )  # fmt: skip
        rec.say(f"docs   {method} {path}: {json.dumps(facts, sort_keys=True)}")
        wanted += [t for t in (facts.get("request_body_type"), facts.get("response_body_type"))
                   if isinstance(t, str)]  # fmt: skip
    seen: set[str] = set()
    for name in wanted:
        if name in seen or len(seen) >= len(DOC_TYPES) + MAX_FOLLOWED_TYPES:
            continue
        seen.add(name)
        r = fetch_doc(rec, f"json_{name}.html")
        if r is None or not r.ok:
            rec.say(f"docs   {name}: {None if r is None else r.status or r.error}")
            continue
        facts = dto_facts(r.body)
        rec.write(
            f"doc_type_{name}", "docs", None, {"data_type": name, **facts},
            note="property names, JSON types and flags from the appliance's API reference",
        )  # fmt: skip
        props = facts["properties"]
        rec.say(
            f"docs   {name}: {len(props)} propert(ies); read-only="
            f"{sorted(k for k, v in props.items() if v['documented_read_only'])}; "
            f"enum_values={facts['enum_values']}"
        )


# ---------------------------------------------------------------------- steps
def preflight(rec: Recorder, ctx: Ctx) -> None:
    """Version, then: is the key's permission set readable, and is it read-only?"""
    r = rec.send("const", "ver", "GET", "/rest/const", "/rest/const")
    facts = a_const(ctx, r) if r.ok else {}
    rec.write("const", "version", r, facts)
    rec.say(f"       matches_expected_version={facts.get('matches_expected_version')}")
    r = rec.send("apikeys", "Q6", "GET", rec.org + "/apikeys", ORG + "/apikeys")
    facts = own_key_permissions(rec.env.key_id)(ctx, r) if r.ok else {}
    rec.write(
        "apikeys", "Q6", r, facts,
        note="a denial is the expected answer for a read-only key",
    )  # fmt: skip
    if ctx.counts.get("own_mutating_permissions", 0) > 0:
        raise StopResearchError(
            "the key's own permission set is readable and contains mutating categories; "
            "this research needs a read-only key"
        )
    rec.say(f"       key introspection readable={r.ok}; mutating categories listed=False")


_OBJECT_PERM_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("read", re.compile(r"^(read|list|view|download|get)")),
    ("feature_switch", re.compile(r"_enabled$")),
    ("create", re.compile(r"^(create|add)")),
    ("delete", re.compile(r"^(delete|remove)")),
    ("assign", re.compile(r"^assign|members")),
    ("annotate", re.compile(r"^comment|^attach")),
    ("edit", re.compile(r"")),
)


def _object_perms(doc: Mapping[str, Any]) -> Facts:
    """The object's own ``perms`` map as three statements (owner ruling, P2-00b Stage 1).

    Never a permission name, a value or a count, and no reading of what a category permits:
    nothing here is exercised.
    """
    perms = doc.get("perms")
    if not isinstance(perms, Mapping):
        return {"perms_map_present": False}
    # Generic categories, as for the key's own permissions (probe.PERMISSION_CATEGORIES): the
    # first pattern that matches wins, and whatever matches none of them counts as "edit".
    by_category: dict[str, list[bool]] = {name: [] for name, _ in _OBJECT_PERM_CATEGORIES}
    for key, value in perms.items():
        name = next(n for n, rx in _OBJECT_PERM_CATEGORIES if rx.search(str(key)))
        by_category[name].append(value is True)
    changing = [v for n in ("edit", "assign", "create", "delete") for v in by_category[n]]
    return {
        "perms_map_present": True,
        "read": "all true" if all(by_category["read"]) else "not all true",
        "edit_assign_create_delete": "at least one true" if any(changing) else "all false",
        "annotate": "at least one true" if any(by_category["annotate"]) else "all false",
    }


def _carried(entries: list[Any]) -> Facts:
    """The D3 reader contract (positive integer ``id`` + non-empty ``name``) against real rows."""
    rows = [e for e in entries if isinstance(e, Mapping)]

    def positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    keys = safe_keys(rows[0]) if rows else []
    return {
        "entries": bucket(len(entries)),
        "every_entry_is_an_object": len(rows) == len(entries),
        "entry_keys": keys,
        "every_entry_has_positive_int_id": bool(rows)
        and all(positive_int(e.get("id")) for e in rows),
        "every_entry_has_nonempty_str_name": bool(rows)
        and all(isinstance(e.get("name"), str) and e["name"].strip() for e in rows),
        "keys_beyond_id_and_name": [k for k in keys if k not in ("id", "name")],
    }


def _task_facts(doc: Mapping[str, Any]) -> Facts:
    status = doc.get("status")
    return {
        "key_count": len(safe_keys(doc)),
        "status_is_single_letter": isinstance(status, str) and len(status) == 1,
        "status_value": status if status in ("O", "C") else "other",
        "version_like_keys": safe_keys_matching(doc, r"^vers$|version|etag|revision|modif"),
        "closed_date_is_null": doc.get("closed_date") is None,
        "custom": doc.get("custom") is True,
        "required": doc.get("required") is True,
        "active": doc.get("active") is True,
        "frozen": doc.get("frozen") is True,
        "in_training_incident": doc.get("inc_training") is True,
        "has_inc_id": isinstance(doc.get("inc_id"), int),
        "carried_actions": bucket(len(doc["actions"]))
        if isinstance(doc.get("actions"), list)
        else "n/a",
        "object_perms": _object_perms(doc),
    }


def metadata(rec: Recorder, ctx: Ctx) -> None:
    """GET-visible metadata that bears on tasks, manual actions and executions."""
    r = rec.send("actions", "D4", "GET", rec.org + "/actions", ORG + "/actions")
    rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)] if r.ok else []
    ctx.counts["org_actions"] = len(rows)
    for row in rows:
        if isinstance(row.get("id"), int):
            ctx.ids.setdefault("org_action:" + str(row["id"]), str(row.get("name", "")))
    targets = [str(x.get("object_type", "")).lower() for x in rows]
    rec.write(
        "actions", "D4", r,
        {
            "rules": bucket(len(rows)),
            "type_distribution": _distribution(rows, "type"),
            "enabled": bucket(sum(1 for x in rows if x.get("enabled") is True)),
            "targets_builtin": {
                t: bucket(targets.count(t)) for t in sorted(BUILTIN_OBJECT_TYPES) if t in targets
            },
            "targets_other": bucket(sum(1 for t in targets if t not in BUILTIN_OBJECT_TYPES)),
            "enabled_rules_on_tasks": bucket(
                sum(1 for x in rows if x.get("enabled") is True
                    and str(x.get("object_type", "")).lower() == "task")
            ),
        },
        note="the org's rules; a task change can trigger an enabled automatic rule on tasks",
    )  # fmt: skip
    for key, suffix in (
        ("type_actioninvocation", "/types/actioninvocation"),
        ("type_actioninvocation_fields", "/types/actioninvocation/fields"),
    ):
        template = ORG + suffix
        r = rec.send(key, "D4", "GET", rec.org + suffix, template)
        rec.write(key, "D4", r, {"rows": bucket(len(rows_of(r.json)))}, shape_source=r.json)
    books: list[Mapping[str, Any]] = []
    total: int | None = None
    for page in range(MAX_PLAYBOOK_PAGES):  # configuration, not incidents; still bounded
        body = {"filters": [], "start": page * PAGE_LENGTH, "length": PAGE_LENGTH}
        r = rec.send(
            "playbooks", "D1", "POST", rec.org + "/playbooks/query_paged",
            ORG + "/playbooks/query_paged", params={"return_level": "normal"}, json_body=body,
            quiet=page > 0,
        )  # fmt: skip
        rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)] if r.ok else []
        books += rows
        found = r.json.get("recordsTotal") if isinstance(r.json, Mapping) else None
        total = found if isinstance(found, int) else total
        if not rows or total is None or len(books) >= total:
            break
    on_tasks = [x for x in books if str(x.get("object_type", "")).lower() == "task"]
    rec.write(
        "playbooks", "D1", r,
        {
            "page_length": PAGE_LENGTH,
            "page_ceiling": MAX_PLAYBOOK_PAGES,
            "every_playbook_seen": total is not None and total <= len(books),
            "playbooks_on_tasks": bucket(len(on_tasks)),
            "enabled_automatic_playbooks_on_tasks": bucket(
                sum(1 for x in on_tasks if x.get("status") == "enabled"
                    and x.get("activation_type") == "automatic")
            ),
        },
        note="risk input for the task experiment: what a task change could trigger",
    )  # fmt: skip
    r = rec.send(
        "execution_statistics", "Q8", "GET", rec.org + "/playbooks/execution/statistics",
        ORG + "/playbooks/execution/statistics",
    )  # fmt: skip
    stats = r.json if isinstance(r.json, Mapping) else {}
    counts = [v for v in stats.values() if isinstance(v, int) and not isinstance(v, bool)]
    rec.write(
        "execution_statistics", "Q8", r,
        {"any_execution_recorded": any(c > 0 for c in counts), "top_level_keys": safe_keys(stats)},
        shape_source=r.json,
        note="is there any execution for an execution query to return?",
    )  # fmt: skip


def scan(rec: Recorder, ctx: Ctx) -> None:
    """One bounded pass: attachment, carried ``actions``, comments, and a task's shape."""
    org = rec.org
    if rec.env.incident_id:
        candidates, source, available = [rec.env.incident_id], "owner-chosen incident", "n/a"
    else:
        body = {
            "filters": [],
            "sorts": [{"field_name": "create_date", "type": "desc"}],
            "start": 0,
            "length": SCAN_LIMIT,
        }
        q = rec.send(
            "scan_query", "scan", "POST", org + "/incidents/query_paged",
            ORG + "/incidents/query_paged", json_body=body,
        )  # fmt: skip
        rows = rows_of(q.json) if q.ok else []
        candidates = [
            str(row["id"]) for row in rows
            if isinstance(row, Mapping) and isinstance(row.get("id"), int)
        ][:SCAN_LIMIT]  # fmt: skip
        total = q.json.get("recordsTotal") if isinstance(q.json, Mapping) else None
        source, available = (
            "bounded scan, newest first",
            bucket(total) if isinstance(total, int) else "n/a",
        )
    open_goals = {"actions", "attachment", "comments", "task"}
    looked = 0
    seen = {"training": False, "closed": False, "active": False}
    incident_perms: Facts | None = None
    for incident_id in candidates:
        if not open_goals:
            break
        looked += 1
        base = f"{org}/incidents/{incident_id}"
        inc = rec.send("scan_incident", "scan", "GET", base, INC, quiet=True)
        doc = inc.json if inc.ok and isinstance(inc.json, Mapping) else {}
        if incident_perms is None and doc:
            incident_perms = _object_perms(doc)
        seen["training"] |= doc.get("inc_training") is True
        seen["closed"] |= doc.get("plan_status") == "C"
        seen["active"] |= doc.get("plan_status") == "A"
        if "actions" in open_goals and isinstance(doc.get("actions"), list) and doc["actions"]:
            _record_carried(rec, ctx, "incident", inc, doc["actions"])
            open_goals.discard("actions")
        if open_goals & {"actions", "task"}:
            tasks = rec.send(
                "scan_tasks", "scan", "GET", base + "/tasks", INC + "/tasks", quiet=True
            )
            task_rows = (
                [t for t in rows_of(tasks.json) if isinstance(t, Mapping)] if tasks.ok else []
            )
            for row in task_rows:
                if (
                    "actions" in open_goals
                    and isinstance(row.get("actions"), list)
                    and row["actions"]
                ):
                    _record_carried(rec, ctx, "task", tasks, row["actions"])
                    open_goals.discard("actions")
            listed = bool(task_rows) and isinstance(task_rows[0].get("id"), int)
            if "task" in open_goals and (rec.env.task_id or listed):
                _record_task(rec, task_rows)
                open_goals.discard("task")
        if "actions" in open_goals:
            arts = rec.send(
                "scan_artifacts", "scan", "GET", base + "/artifacts", INC + "/artifacts", quiet=True
            )
            for row in rows_of(arts.json) if arts.ok else []:
                if (
                    isinstance(row, Mapping)
                    and isinstance(row.get("actions"), list)
                    and row["actions"]
                ):
                    _record_carried(rec, ctx, "artifact", arts, row["actions"])
                    open_goals.discard("actions")
                    break
        if "attachment" in open_goals:
            atts = rec.send(
                "scan_attachments", "Q7", "GET", base + "/attachments", INC + "/attachments",
                quiet=True,
            )  # fmt: skip
            found = [a for a in rows_of(atts.json) if isinstance(a, Mapping)] if atts.ok else []
            if found and isinstance(found[0].get("id"), int | str):
                _record_attachment(rec, base, atts, found)
                open_goals.discard("attachment")
        if "comments" in open_goals:
            notes = rec.send(
                "scan_comments", "OQ10", "GET", base + "/comments", INC + "/comments", quiet=True
            )
            if notes.ok and rows_of(notes.json):
                thread = {**a_comments(ctx, notes), **_thread_facts(rows_of(notes.json))}
                rec.say(f"OQ10   comments: {json.dumps(thread, sort_keys=True)}")
                rec.write(
                    "comments", "OQ10", notes, thread, shape_source=notes.json,
                    note="first incident in the bounded scan that has notes",
                )  # fmt: skip
                open_goals.discard("comments")
    facts = {
        "source": source,
        "limit": SCAN_LIMIT,
        "incidents_available": available,
        "incidents_looked_at": looked,
        "answered": sorted({"actions", "attachment", "comments", "task"} - open_goals),
        "not_found_within_limit": sorted(open_goals),
        "training_incident_seen": seen["training"],
        "active_incident_seen": seen["active"],
        "closed_incident_seen": seen["closed"],
        "first_incident_object_perms": incident_perms,
    }
    rec.write(
        "scan", "scan", None, facts, note="at most 10 incidents; each search stops at its first hit"
    )
    rec.say(f"scan   {json.dumps(facts, sort_keys=True)}")


def _thread_facts(rows: list[Any]) -> Facts:
    """How replies are represented. Booleans and a depth; never a note's text or id."""
    top = [n for n in rows if isinstance(n, Mapping)]

    def kids(note: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        children = note.get("children")
        return [c for c in children if isinstance(c, Mapping)] if isinstance(children, list) else []

    def depth(note: Mapping[str, Any], level: int = 1) -> int:
        return max([level, *(depth(c, level + 1) for c in kids(note))]) if level < 20 else level

    pairs = [(n, c) for n in top for c in kids(n)]
    return {
        "top_level_notes": bucket(len(top)),
        "any_reply_nested_under_children": bool(pairs),
        "max_depth": max((depth(n) for n in top), default=0),
        "every_reply_has_an_integer_parent_id": bool(pairs)
        and all(isinstance(c.get("parent_id"), int) for _, c in pairs),
        "reply_parent_id_equals_the_parent_note_id": bool(pairs)
        and all(c.get("parent_id") == n.get("id") for n, c in pairs),
        "top_level_parent_id_is_null": bool(top) and all(n.get("parent_id") is None for n in top),
        "a_reply_is_also_listed_at_top_level": any(n.get("parent_id") is not None for n in top),
    }


def _record_carried(rec: Recorder, ctx: Ctx, kind: str, r: Result, entries: list[Any]) -> None:
    facts = {"carried_by": kind, **_carried(entries)}
    ids = [e.get("id") for e in entries if isinstance(e, Mapping)]
    if ctx.counts.get("org_actions"):
        known = [ctx.ids.get(f"org_action:{i}") for i in ids]
        facts["every_id_is_an_org_rule_id"] = all(k is not None for k in known)
        facts["every_name_equals_the_org_rule_name"] = all(
            isinstance(e, Mapping) and ctx.ids.get(f"org_action:{e.get('id')}") == e.get("name")
            for e in entries
        )
    rec.write(
        "carried_actions", "D3", r, facts, shape_source=entries,
        note="the first non-empty carried actions list in the bounded scan; nothing is invoked",
    )  # fmt: skip
    rec.say(f"D3     carried actions: {json.dumps(facts, sort_keys=True)}")


def _record_task(rec: Recorder, task_rows: list[Mapping[str, Any]]) -> None:
    """One task, read only: the owner-designated one if there is one, else the first listed."""
    designated = rec.env.task_id
    task_id = designated or str(task_rows[0]["id"])
    statuses = {str(t.get("status")) for t in task_rows}
    r = rec.send("task", "D1", "GET", f"{rec.org}/tasks/{task_id}", ORG + "/tasks/{task_id}")
    doc = r.json if r.ok and isinstance(r.json, Mapping) else {}
    facts = {
        **_task_facts(doc),
        "owner_designated_task": bool(designated),
        # Compared in memory; neither id is ever printed or stored.
        "belongs_to_the_designated_incident": bool(designated and rec.env.incident_id)
        and str(doc.get("inc_id")) == rec.env.incident_id,
        "listed_among_the_incident_tasks": any(str(t.get("id")) == task_id for t in task_rows),
        "tasks_in_incident": bucket(len(task_rows)),
        "statuses_in_incident": sorted(s for s in statuses if s in ("O", "C")),
        "custom_tasks_in_incident": bucket(sum(1 for t in task_rows if t.get("custom") is True)),
        "list_row_keys_equal_single_object_keys": bool(doc and task_rows)
        and set(safe_keys(task_rows[0])) == set(safe_keys(doc)),
    }
    rec.write(
        "task", "D1", r, facts, shape_source=r.json,
        note="read only: the shape a task change would have to respect; nothing is changed",
    )  # fmt: skip
    rec.say(f"D1     task: {json.dumps(facts, sort_keys=True)}")
    _record_canonical(rec, task_id, doc)


def _record_canonical(
    rec: Recorder, task_id: str, doc: Mapping[str, Any], key: str = "task_canonical"
) -> None:
    # The same task as the reference's data types describe it: handles as {id, name} objects
    # and text as {format, content} without conversion. Still a GET; nothing is changed.
    c = rec.send(
        key, "D1", "GET", f"{rec.org}/tasks/{task_id}", ORG + "/tasks/{task_id}",
        params=CANONICAL_PARAMS,
    )  # fmt: skip
    canon = c.json if c.ok and isinstance(c.json, Mapping) else {}
    handles = [k for k, v in canon.items() if isinstance(v, Mapping) and set(v) == {"id", "name"}]
    text = [
        k for k, v in canon.items() if isinstance(v, Mapping) and set(v) == {"format", "content"}
    ]
    canonical_facts = {
        "params": CANONICAL_PARAMS,
        "same_keys_as_default_representation": bool(canon)
        and set(safe_keys(canon)) == set(safe_keys(doc)),
        "handle_object_keys": sorted(k for k in handles if k in safe_keys(canon)),
        "text_object_keys": sorted(k for k in text if k in safe_keys(canon)),
        "keys_whose_json_type_differs": sorted(
            k for k in safe_keys(canon)
            if k in doc and type(canon[k]).__name__ != type(doc[k]).__name__
        ),
    }  # fmt: skip
    rec.write(
        key, "D1", c, canonical_facts, shape_source=c.json,
        note="the representation the documented TaskDTO describes; read only",
    )  # fmt: skip
    rec.say(f"D1     {key}: {json.dumps(canonical_facts, sort_keys=True)}")


def _record_attachment(
    rec: Recorder, base: str, atts: Result, found: list[Mapping[str, Any]]
) -> None:
    att = INC + "/attachments/{attachment_id}"
    rec.write(
        "attachment_list", "Q7", atts, {"attachment_metadata_keys": safe_keys(found[0])},
        shape_source=atts.json, note="attachment metadata of the first incident that has one",
    )  # fmt: skip
    one = f"{base}/attachments/{found[0]['id']}"
    meta = rec.send("attachment_metadata", "Q7", "GET", one, att)
    rec.write("attachment_metadata", "Q7", meta, {}, shape_source=meta.json)
    head = rec.send(
        "attachment_contents", "Q7", "GET", one + "/contents", att + "/contents", headers_only=True
    )
    kind = (head.content_type or "").split("/")[0]
    facts = {
        "content_type": head.content_type,
        "content_type_family": kind if kind in ("application", "text", "image") else "other",
        "content_length_present": head.has_content_length,
        "declared_size": head.size_bucket,
        "transfer_encoding_chunked": head.chunked,
        "has_content_disposition": head.has_content_disposition,
        "body_was_not_read": True,
    }
    rec.write(
        "attachment_contents", "Q7", head, facts,
        note="status and headers only; the stream is closed without reading the body",
    )  # fmt: skip
    rec.say(f"Q7     attachment contents: {json.dumps(facts, sort_keys=True)}")


def designated(rec: Recorder, ctx: Ctx) -> int:
    """Stage 1B: the incident and the task the owner designated, and nothing else.

    GET only. No preflight, no query, no listing of the incident's other tasks, no read of
    any object that is not the designated incident, the designated task, or a note, an
    attachment or an artifact OF that incident. Both ids stay in memory. A 403/404 on either
    object, or a task that does not belong to the incident, stops the step.
    """
    env = rec.env
    if not env.incident_id or not env.task_id:
        rec.say("1B     set P2_PROBE_INCIDENT_ID and P2_PROBE_TASK_ID (git-ignored .env)")
        return 2
    base = f"{rec.org}/incidents/{env.incident_id}"
    inc = rec.send("designated_incident", "1B", "GET", base, INC)
    task = rec.send(
        "designated_task", "1B", "GET", f"{rec.org}/tasks/{env.task_id}", ORG + "/tasks/{task_id}"
    )
    idoc = inc.json if inc.ok and isinstance(inc.json, Mapping) else {}
    tdoc = task.json if task.ok and isinstance(task.json, Mapping) else {}
    member = str(tdoc.get("inc_id")) == env.incident_id if tdoc else None  # compared in memory
    summary: Facts = {
        "incident_http_status": inc.status or inc.error,
        "task_http_status": task.status or task.error,
        "task_belongs_to_the_designated_incident": member,
    }
    if not (inc.ok and task.ok and member):
        summary["stopped"] = (
            "visibility blocker: a designated object is not readable with this credential"
            if not (inc.ok and task.ok)
            else "the designated task does not belong to the designated incident"
        )
        rec.write("designated", "1B", None, summary, note="stopped; nothing else was requested")
        rec.say(f"1B     STOPPED: {json.dumps(summary, sort_keys=True)}")
        return EXIT_DESIGNATED_STOP

    # Both are readable and consistent: the prepared read-only inspection, this incident only.
    actions = {
        "incident": idoc.get("actions") if isinstance(idoc.get("actions"), list) else None,
        "task": tdoc.get("actions") if isinstance(tdoc.get("actions"), list) else None,
    }
    rec.write(
        "designated_task", "1B", task, _task_facts(tdoc), shape_source=task.json,
        note="the owner-designated disposable task; read only, nothing is changed",
    )  # fmt: skip
    _record_canonical(rec, env.task_id, tdoc, key="designated_task_canonical")
    atts = rec.send(
        "designated_attachments", "Q7", "GET", base + "/attachments", INC + "/attachments"
    )
    found = [x for x in rows_of(atts.json) if isinstance(x, Mapping)] if atts.ok else []
    if found and isinstance(found[0].get("id"), int | str):
        _record_attachment(rec, base, atts, found)
    notes = rec.send("designated_comments", "OQ10", "GET", base + "/comments", INC + "/comments")
    note_rows = rows_of(notes.json) if notes.ok else []
    if note_rows:
        thread = {**a_comments(ctx, notes), **_thread_facts(note_rows)}
        rec.write(
            "comments", "OQ10", notes, thread, shape_source=notes.json,
            note="notes of the owner-designated incident; shape only",
        )  # fmt: skip
        rec.say(f"OQ10   comments: {json.dumps(thread, sort_keys=True)}")
    arts = rec.send("designated_artifacts", "D3", "GET", base + "/artifacts", INC + "/artifacts")
    art_rows = [x for x in rows_of(arts.json) if isinstance(x, Mapping)] if arts.ok else []
    carried_by_artifact = next(
        (x["actions"] for x in art_rows if isinstance(x.get("actions"), list) and x["actions"]),
        None,
    )
    for kind, entries, source in (
        ("incident", actions["incident"], inc),
        ("task", actions["task"], task),
        ("artifact", carried_by_artifact, arts),
    ):
        if entries:
            _record_carried(rec, ctx, kind, source, entries)
            break
    summary.update(
        {
            "incident": {
                "plan_status": idoc.get("plan_status") if idoc.get("plan_status") in ("A", "C")
                else "other",
                "training_incident": idoc.get("inc_training") is True,
                "object_perms": _object_perms(idoc),
            },
            "exposes": {
                "attachment": bool(found),
                "attachments_http_status": atts.status or atts.error,
                "note": bool(note_rows),
                "comments_http_status": notes.status or notes.error,
                "artifacts": bucket(len(art_rows)),
                "carried_actions_on_incident": bucket(len(actions["incident"] or [])),
                "carried_actions_on_task": bucket(len(actions["task"] or [])),
                "carried_actions_on_an_artifact": carried_by_artifact is not None,
                "task_shape": bool(tdoc),
            },
        }
    )  # fmt: skip
    rec.write("designated", "1B", None, summary, note="owner-designated objects; GET only")
    rec.say(f"1B     designated: {json.dumps(summary, sort_keys=True)}")
    return 0


def designated_task_check(rec: Recorder, ctx: Ctx) -> int:
    """Stage 1B: ONE GET of the designated task, in the output formats the UI uses.

    It is sent only when a valid close/reopen observation pair is on record
    (``shape_request.py --compare close reopen``). It is the read a candidate PUT body would
    be built from, so what is recorded is what that construction needs: the safe state
    facts, the key set against the observed requests, and JSON types. ``required: true`` is
    a recorded risk indicator (owner decision), not a stop. Nothing is changed.
    """
    env = rec.env
    if not env.incident_id or not env.task_id:
        rec.say("1B     set P2_PROBE_INCIDENT_ID and P2_PROBE_TASK_ID (git-ignored .env)")
        return 2
    pair = _fixture(rec.out_dir, "ui_request_pair").get("_facts", {})
    if pair.get("valid_pair") is not True:
        rec.say("1B     no valid close/reopen observation pair is on record; nothing was sent")
        for problem in pair.get("problems", ["run: shape_request.py --compare close reopen"]):
            rec.say(f"         - {problem}")
        return 2
    r = rec.send(
        "designated_task_ui_formats", "1B", "GET", f"{rec.org}/tasks/{env.task_id}",
        ORG + "/tasks/{task_id}", params=UI_FORMAT_PARAMS,
    )  # fmt: skip
    doc = r.json if r.ok and isinstance(r.json, Mapping) else {}
    facts: Facts = {
        "params": UI_FORMAT_PARAMS,
        "task_http_status": r.status or r.error,
        "task_is_the_designated_task": str(doc.get("id")) == env.task_id if doc else None,
        "task_belongs_to_the_designated_incident": str(doc.get("inc_id")) == env.incident_id
        if doc else None,
    }  # fmt: skip
    if doc:
        facts.update(_task_facts(doc))
        facts["required_is_a_recorded_risk_indicator"] = doc.get("required") is True
        facts["handle_forms"] = {
            k: _value_form(doc[k]) for k in ("phase_id", "owner_id", "at_id", "category_id",
                                             "inc_owner_id") if k in doc
        }  # fmt: skip
        facts["instructions_form"] = _value_form(doc.get("instructions"))
        facts["live_only_keys_present"] = {
            k: k in doc for k in ("auto_deactivate", "form", "task_layout", "user_notes")
        }
        # An open task is what a CLOSE request is built from, a closed one a REOPEN request.
        facts["appropriate_observation"] = {"O": "close", "C": "reopen"}.get(
            str(doc.get("status")), "none"
        )
        for label in ("close", "reopen"):
            seen = _fixture(rec.out_dir, f"ui_request_{label}")
            keys = set(seen.get("_facts", {}).get("top_level_keys", []))
            shape = seen.get("shape") if isinstance(seen.get("shape"), Mapping) else {}
            facts[f"against_the_{label}_request"] = {
                "same_key_set": set(safe_keys(doc)) == keys,
                "keys_whose_json_type_differs": {
                    k: {"fresh_get": task_candidate.json_type(doc[k]),
                        "observed": task_candidate.observed_type(shape[k])}
                    for k in sorted(safe_keys(doc))
                    if k in shape and task_candidate.json_type(doc[k])
                    != task_candidate.observed_type(shape[k])
                },
            }  # fmt: skip
    rec.write(
        "designated_task_ui_formats", "1B", r, facts, shape_source=r.json,
        note="the designated task in the UI's output formats; one GET; nothing is changed",
    )  # fmt: skip
    rec.say(f"1B     designated task (UI formats): {json.dumps(facts, sort_keys=True)}")
    blocked = (
        not doc
        or not facts["task_is_the_designated_task"]
        or not facts["task_belongs_to_the_designated_incident"]
    )
    return EXIT_DESIGNATED_STOP if blocked else 0


TASKTREE = INC + "/tasktree"
# What the appliance's reference documents as the caller's permission to write to and to
# close an object (json_TaskPermsDTO, inherited from ObjectPermsDTO). Schema key names.
STATUS_CHANGE_FLAGS = ("read", "write", "close")  # all three must read true (owner)


def find_tasks(node: object, task_id: str, depth: int = 0) -> list[Mapping[str, Any]]:
    """Every task-shaped object with this id anywhere in a tree. Compared in memory."""
    found: list[Mapping[str, Any]] = []
    if depth > 12:
        return found
    if isinstance(node, Mapping):
        if str(node.get("id")) == task_id and "status" in node and "inc_id" in node:
            found.append(node)
        for value in node.values():
            found += find_tasks(value, task_id, depth + 1)
    elif isinstance(node, list):
        for value in node:
            found += find_tasks(value, task_id, depth + 1)
    return found


def narrow_tasktree(tree: object, task_id: str, incident_id: str) -> tuple[Mapping[str, Any], str]:
    """``(the designated task, "")`` or ``({}, why not)``. Exactly one match, or nothing."""
    found = find_tasks(tree, task_id)
    if len(found) != 1:
        return {}, "no matching task" if not found else "more than one matching task"
    if str(found[0].get("inc_id")) != incident_id:
        return {}, "the matching task is not in the designated incident"
    return found[0], ""


def status_change_flag_values(doc: Mapping[str, Any]) -> dict[str, bool | None]:
    """``read`` / ``write`` / ``close`` of the task's own ``perms`` map, one boolean each.

    Owner instruction (P2-00b): these three, by their documented schema names, are reported
    individually so that a failing gate names the flag. Every other flag of the map stays
    inside the three generic statements of ``_object_perms``.
    """
    perms = doc.get("perms")
    perms = perms if isinstance(perms, Mapping) else {}
    return {k: perms[k] if isinstance(perms.get(k), bool) else None for k in STATUS_CHANGE_FLAGS}


def status_change_flags(doc: Mapping[str, Any]) -> str:
    """One statement over the documented read/write/close flags."""
    perms = doc.get("perms")
    if not isinstance(perms, Mapping) or any(k not in perms for k in STATUS_CHANGE_FLAGS):
        return "not reported"
    return "all true" if all(perms[k] is True for k in STATUS_CHANGE_FLAGS) else "not all true"


def representation_facts(out_dir: Path, fresh: Mapping[str, Any]) -> Facts:
    """The fresh task against the observed UI requests and the recorded direct GET."""
    direct = _fixture(out_dir, "designated_task_ui_formats").get("shape")
    classes = {
        "fresh_read": _class_of(fresh.get("task_layout")) if "task_layout" in fresh else "absent",
        "direct_task_get": _shape_class_of(direct.get("task_layout"))
        if isinstance(direct, Mapping) and "task_layout" in direct else "not on record",
    }  # fmt: skip
    against: Facts = {}
    for label in ("close", "reopen"):
        seen = _fixture(out_dir, f"ui_request_{label}")
        shape = seen.get("shape") if isinstance(seen.get("shape"), Mapping) else {}
        keys = set(seen.get("_facts", {}).get("top_level_keys", []))
        classes[f"observed_{label}_put"] = (
            _shape_class_of(shape["task_layout"]) if "task_layout" in shape else "not on record"
        )
        against[label] = {
            "same_key_set": bool(keys) and set(safe_keys(fresh)) == keys,
            "keys_whose_json_type_differs": {
                k: {"fresh": task_candidate.json_type(fresh[k]),
                    "observed": task_candidate.observed_type(shape[k])}
                for k in sorted(safe_keys(fresh))
                if k in shape and task_candidate.json_type(fresh[k])
                != task_candidate.observed_type(shape[k])
            },
        }  # fmt: skip
    return {"task_layout_class": classes, "against_the_observed_put": against}


def _class_of(value: object) -> str:
    if isinstance(value, list):
        return "empty list" if not value else "non-empty list"
    return task_candidate.json_type(value)


def _shape_class_of(shape: object) -> str:
    if isinstance(shape, list):
        return "empty list" if not shape else "non-empty list"
    return "object" if isinstance(shape, Mapping) else str(shape)


def tasktree_read(rec: Recorder, ctx: Ctx) -> int:
    """Stage A: ONE GET of the designated incident's task tree, as the web UI reads it.

    The format controls travel as headers, as the UI sends them. The tree is narrowed in
    memory to exactly one designated task; nothing about any other task is kept.
    """
    env = rec.env
    if not env.incident_id or not env.task_id:
        rec.say("1B     set P2_PROBE_INCIDENT_ID and P2_PROBE_TASK_ID (git-ignored .env)")
        return 2
    r = rec.send(
        "tasktree", "1B", "GET", f"{rec.org}/incidents/{env.incident_id}/tasktree", TASKTREE,
        default_params=False, format_headers=UI_FORMAT_PARAMS,
    )  # fmt: skip
    task, why = narrow_tasktree(r.json, env.task_id, env.incident_id) if r.ok else ({}, "")
    facts: Facts = {
        "path_template": TASKTREE,
        "format_controls": {"sent_as": "headers", **UI_FORMAT_PARAMS},
        "http_status": r.status or r.error,
        "content_type": r.content_type,
        "tree_top_level_type": task_candidate.json_type(r.json),
        "tree_top_level_keys": safe_keys(r.json) if isinstance(r.json, Mapping) else [],
        "designated_task_found_exactly_once": bool(task),
        "not_found_because": why or None,
        "task_belongs_to_the_designated_incident": bool(task),
    }
    if task:
        facts.update(_task_facts(task))
        facts["documented_status_change_flags"] = {
            "flags": list(STATUS_CHANGE_FLAGS),
            "statement": status_change_flags(task),
        }
        facts["handle_forms"] = {
            k: _value_form(task[k]) for k in ("phase_id", "owner_id", "at_id", "category_id",
                                              "inc_owner_id") if k in task
        }  # fmt: skip
        facts["instructions_form"] = _value_form(task.get("instructions"))
        facts["live_only_keys_present"] = {
            k: k in task for k in ("auto_deactivate", "form", "task_layout", "user_notes")
        }
        facts.update(representation_facts(rec.out_dir, task))
    rec.write(
        "tasktree_task", "1B", r, facts, shape_source=task or None,
        note="the designated task as the incident's task tree returns it; GET only; "
        "the rest of the tree is not kept",
    )  # fmt: skip
    rec.say(f"1B     tasktree: {json.dumps(facts, sort_keys=True)}")
    return 0 if task else EXIT_DESIGNATED_STOP


EXIT_NO_GO = 6
PUT_TEMPLATE = ORG + "/tasks/{task_id}"


def preflight_close(rec: Recorder, ctx: Ctx) -> int:
    """Stage E: the pre-mutation report for the CLOSE step. Two GETs; it cannot send a PUT.

    A fresh read of the source representation (the incident's task tree, narrowed in memory
    to exactly one designated task), the incident (its phase kept in memory only), the real
    candidate builder's verdict, and the permission evidence. GO needs every one of them.
    """
    env = rec.env
    if not env.incident_id or not env.task_id:
        rec.say("1B     set P2_PROBE_INCIDENT_ID and P2_PROBE_TASK_ID (git-ignored .env)")
        return 2
    base = f"{rec.org}/incidents/{env.incident_id}"
    tree = rec.send(
        "preflight_tasktree", "1B", "GET", base + "/tasktree", TASKTREE,
        default_params=False, format_headers=UI_FORMAT_PARAMS,
    )  # fmt: skip
    task, why = narrow_tasktree(tree.json, env.task_id, env.incident_id) if tree.ok else ({}, "")
    inc = rec.send(
        "preflight_incident", "1B", "GET", base, INC,
        default_params=False, format_headers=UI_FORMAT_PARAMS,
    )  # fmt: skip
    idoc = inc.json if inc.ok and isinstance(inc.json, Mapping) else {}
    phase = idoc.get("phase_id")  # kept in memory; never recorded
    candidate = task_candidate.build_candidate(
        task or None, target="C", observation=_fixture(rec.out_dir, "ui_request_close"),
        task_id=env.task_id, incident_id=env.incident_id,
    )  # fmt: skip
    flags = status_change_flags(task) if task else "not reported"
    reasons = list(candidate.stops)
    if not task:
        reasons.insert(0, f"the source read did not yield exactly one designated task ({why})")
    if not isinstance(phase, int) or isinstance(phase, bool):
        reasons.append("the incident phase could not be captured")
    if flags == "not all true":
        reasons.append(
            "the task reports that this credential may not both write to it and close it "
            "(documented TaskPermsDTO flags); a refusal would verify nothing and is not tested"
        )
    facts: Facts = {
        "representation": representation_facts(rec.out_dir, task) if task else None,
        "candidate_source": {"endpoint": TASKTREE, "format_controls_sent_as": "headers",
                             **UI_FORMAT_PARAMS, "http_status": tree.status or tree.error,
                             "narrowed_to_exactly_one_designated_task": bool(task)},
        "fresh_task": _task_facts(task) if task else None,
        "close_candidate": {"built": candidate.ok, "changed_keys": list(candidate.changed_keys),
                            "stops": list(candidate.stops)},
        "permission_evidence": {
            "documented": "TaskPermsDTO (inherited from ObjectPermsDTO): write = the caller is "
            "allowed to write to the object; close = the caller is allowed to close the object",
            "live_object_level_statements": _object_perms(task) if task else None,
            "documented_status_change_flags": {"flags": list(STATUS_CHANGE_FLAGS),
                                               "statement": flags},
            "uncertain": flags == "not reported",
        },
        "incident": {"http_status": inc.status or inc.error,
                     "phase_id_captured_in_memory": isinstance(phase, int)},
        "proposed_put": {"method": "PUT", "path_template": PUT_TEMPLATE, "query": {},
                         "format_headers": UI_FORMAT_PARAMS, "body": "the close candidate"},
        "planned_requests": {"total": task_candidate.MAX_EXPERIMENT_REQUESTS, "get": 7, "put": 2},
        "go": not reasons,
        "no_go_reasons": reasons,
    }  # fmt: skip
    rec.write("preflight_close", "1B", None, facts, note="pre-mutation report; nothing was changed")
    for key, value in facts.items():
        rec.say(f"PRE    {key}: {json.dumps(value, sort_keys=True)}")
    rec.say("PRE    " + ("GO" if not reasons else "NO-GO: no PUT is sent"))
    return 0 if not reasons else EXIT_NO_GO


def _value_form(value: object) -> str:
    if isinstance(value, Mapping):
        keys = set(map(str, value))
        return "object{id,name}" if keys == {"id", "name"} else (
            "object{format,content}" if keys == {"format", "content"} else "object"
        )  # fmt: skip
    return task_candidate.json_type(value)


def _fixture(out_dir: Path, name: str) -> Mapping[str, Any]:
    path = out_dir / f"{PREFIX}{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _plan_status(value: str) -> dict[str, str]:
    return {"field_name": "plan_status", "method": "equals", "value": value}


def filters(rec: Recorder, ctx: Ctx) -> None:
    """AND within one filter, OR across filters. One row per query; counts stay in memory."""
    queries: dict[str, list[list[dict[str, str]]]] = {
        "active": [[_plan_status("A")]],
        "closed": [[_plan_status("C")]],
        "and": [[_plan_status("A"), _plan_status("C")]],
        "or": [[_plan_status("A")], [_plan_status("C")]],
    }
    counts: dict[str, int] = {}
    last: Result | None = None
    for name, groups in queries.items():
        body = {"filters": [{"conditions": g} for g in groups], "start": 0, "length": 1}
        last = rec.send(
            f"filter_{name}", "OQ14", "POST", rec.org + "/incidents/query_paged",
            ORG + "/incidents/query_paged", json_body=body,
        )  # fmt: skip
        doc = last.json if isinstance(last.json, Mapping) else {}
        if isinstance(doc.get("recordsFiltered"), int):
            counts[name] = doc["recordsFiltered"]
        if isinstance(doc.get("recordsTotal"), int):
            counts["total"] = doc["recordsTotal"]
    facts: Facts = {"all_queries_answered": len(counts) == len(queries) + 1}
    if facts["all_queries_answered"]:
        distinguishable = counts["active"] > 0 and counts["closed"] > 0
        facts.update(
            {
                "both_conditions_match_something": distinguishable,
                "and_within_one_filter_is_intersection": counts["and"] == 0,
                "or_across_filters_is_union": counts["or"] == counts["active"] + counts["closed"],
                "active_plus_closed_equals_total": counts["active"] + counts["closed"]
                == counts["total"],
                "verdict": "verified" if distinguishable and counts["and"] == 0
                and counts["or"] == counts["active"] + counts["closed"]
                else "not distinguishable" if not distinguishable else "contradicted",
            }
        )  # fmt: skip
    rec.write("filter_semantics", "OQ14", last, facts, note="plan_status A / C; one row per query")
    rec.say(f"OQ14   filter semantics: {json.dumps(facts, sort_keys=True)}")


def workflows(rec: Recorder, ctx: Ctx) -> None:
    r = rec.send("workflows", "05§2", "GET", rec.org + "/workflows", ORG + "/workflows")
    rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)] if r.ok else []
    rec.write("workflows", "05§2", r, {"rows": bucket(len(rows))})
    ident = next((x.get("workflow_id", x.get("id")) for x in rows), None)
    if not isinstance(ident, int):
        rec.say("05§2   no workflow exists in this org; the workflow shape stays unverified")
        return
    one = rec.send(
        "workflow", "05§2", "GET", f"{rec.org}/workflows/{ident}", ORG + "/workflows/{workflow_id}"
    )
    rec.write(
        "workflow", "05§2", one, a_workflow(ctx, one) if one.ok else {}, shape_source=one.json
    )


def execution_query(rec: Recorder, ctx: Ctx) -> None:
    """The owner-approved execution query (P2-00b). Exact body; once per approved round.

    Each round is one explicit owner approval and is recorded in its own fixture. A round
    that has a fixture is never sent again, and a failed send is not retried.
    """
    key = "execution_query" + (f"_{rec.execution_round}" if rec.execution_round else "")
    if (rec.out_dir / f"{PREFIX}{key}.json").is_file():
        rec.say(f"Q8     {key}: already sent once for this round; it is not sent again")
        return
    r = rec.send(
        key, "Q8", "POST", rec.org + EXECUTION_QUERY_SUFFIX,
        ORG + EXECUTION_QUERY_SUFFIX, json_body=dict(EXECUTION_QUERY_BODY),
    )  # fmt: skip
    rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)] if r.ok else []
    doc = r.json if isinstance(r.json, Mapping) else {}
    total = doc.get("recordsTotal")
    facts = {
        "round": rec.execution_round or "first",
        "body_sent": "the approved body, exactly: no filters, start 0, length 1",
        "wrapper_keys": safe_keys(doc),
        "any_execution_row": bool(rows),
        "records_total": bucket(total) if isinstance(total, int) else "n/a",
        "row_keys": safe_keys(rows[0]) if rows else [],
        "result_like_keys": safe_keys_matching(rows[:1], r"result|output|function|detail|msg"),
    }
    rec.write(
        key, "Q8", r, facts, shape_source=r.json,
        note="owner-approved for P2-00b, once per round; criteria-only body; nothing is executed",
    )  # fmt: skip
    rec.say(f"Q8     execution query: {json.dumps(facts, sort_keys=True)}")


# Steps that are never part of a default run: they must be named with --only.
OPT_IN_STEPS = frozenset({"execution_query"})

RUNNERS: dict[str, Callable[[Recorder, Ctx], None]] = {
    "preflight": preflight,
    "docs": docs,
    "metadata": metadata,
    "scan": scan,
    "filters": filters,
    "workflows": workflows,
    "execution_query": execution_query,
}


def run(rec: Recorder, only: frozenset[str] | None = None) -> int:
    """Preflight always runs first; a mutating key stops everything after it."""
    ctx = Ctx(ids={"org_id": rec.env.org_id})
    try:
        for name in STEPS:
            default = only is None and name not in OPT_IN_STEPS
            if name == "preflight" or default or (only is not None and name in only):
                RUNNERS[name](rec, ctx)
    except StopResearchError as exc:
        rec.say(f"STOPPED: {exc}")
        rec.finish()
        return EXIT_MUTATING_KEY
    rec.finish()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--only", default="", metavar="STEP[,STEP]", help=", ".join(STEPS))
    parser.add_argument("--doc-index", action="store_true", help="list the on-box reference pages")
    parser.add_argument("--doc-page", default="", metavar="PAGE.html")
    parser.add_argument("--grep", default=".", help="regular expression for --doc-index/--doc-page")
    parser.add_argument("--context", type=int, default=6)
    parser.add_argument("--max-lines", type=int, default=260)
    parser.add_argument("--lines", default="", metavar="A-B", help="only this line range")
    parser.add_argument(
        "--doc-artifacts", action="store_true",
        help="look for an OpenAPI/WADL description next to the reference",
    )  # fmt: skip
    parser.add_argument(
        "--designated", action="store_true",
        help="GET only the owner-designated incident and task (and that incident's own "
        "notes, attachments and artifacts); no preflight, no query",
    )  # fmt: skip
    parser.add_argument(
        "--designated-task", action="store_true",
        help="ONE GET of the designated task in the UI's output formats (needs a valid pair)",
    )  # fmt: skip
    parser.add_argument(
        "--preflight-close", action="store_true",
        help="the pre-mutation report for closing the designated task: two GETs, never a PUT",
    )  # fmt: skip
    parser.add_argument(
        "--tasktree", action="store_true",
        help="ONE GET of the designated incident's task tree, narrowed to the designated task",
    )  # fmt: skip
    parser.add_argument(
        "--execution-round", default="", metavar="NAME",
        help="with --only execution_query: the owner approval this send belongs to",
    )  # fmt: skip
    parser.add_argument(
        "--doc-swagger", action="store_true",
        help="read the task PUT from the machine-readable description (--grep filters paths)",
    )  # fmt: skip
    parser.add_argument(
        "--doc-swagger-grep", default="", metavar="REGEX",
        help="which data types, properties and operations of the description mention this",
    )  # fmt: skip
    parser.add_argument(
        "--doc-find", default="", metavar="REGEX",
        help="which documented endpoints mention this (reads every resource page)",
    )  # fmt: skip
    args = parser.parse_args(argv)
    if not re.fullmatch(r"([a-z][a-z0-9_]{0,20})?", args.execution_round):
        print("--execution-round is a short lower-case word")
        return 2
    try:
        env = load_env()
    except ProbeEnvError as exc:
        print(f"cannot run: {exc} (values come from the environment or a git-ignored .env)")
        return 2
    context, label = verified_context(env)
    print(f"TLS: verified ({label}); chain and host name are checked; no unverified connection")
    client = ReadOnlyClient(env, context)
    rec = Recorder(env, client, OUT_DIR, execution_round=args.execution_round)
    try:
        docs_only = (args.doc_index, args.doc_page, args.doc_find, args.doc_artifacts,
                     args.doc_swagger, args.doc_swagger_grep)  # fmt: skip
        if any(docs_only):
            if args.doc_index:
                doc_index(rec, args.grep)
            if args.doc_artifacts:
                doc_artifacts(rec)
            if args.doc_swagger:
                doc_swagger(rec, args.grep)
            if args.doc_swagger_grep:
                doc_swagger_grep(rec, args.doc_swagger_grep, args.max_lines)
            if args.doc_find:
                doc_find(rec, args.doc_find)
            if args.doc_page:
                first, _, last = args.lines.partition("-")
                span = (int(first), int(last)) if first.isdigit() and last.isdigit() else None
                doc_page(rec, args.doc_page, args.grep, args.context, args.max_lines, span)
            rec.finish()
            return 0
        if args.preflight_close:
            code = preflight_close(rec, Ctx(ids={"org_id": env.org_id}))
            rec.finish()
            return code
        if args.tasktree:
            code = tasktree_read(rec, Ctx(ids={"org_id": env.org_id}))
            rec.finish()
            return code
        if args.designated_task:
            code = designated_task_check(rec, Ctx(ids={"org_id": env.org_id}))
            rec.finish()
            return code
        if args.designated:
            code = designated(rec, Ctx(ids={"org_id": env.org_id}))
            rec.finish()
            return code
        only = frozenset(k for k in args.only.split(",") if k) or None
        unknown = sorted((only or frozenset()) - set(STEPS))
        if unknown:
            print("unknown step(s): " + ", ".join(unknown))
            return 2
        return run(rec, only)
    except (httpx.HTTPError, OSError) as exc:  # never let a message with a URL escape
        print(f"probe aborted: {type(exc).__name__}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
