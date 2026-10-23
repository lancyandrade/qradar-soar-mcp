"""P2-04 research addendum: what is a workflow, and how does it refer to a function?

    uv run python scripts/probe/guarded.py probe_p2_04.py --swagger      # R1
    uv run python scripts/probe/guarded.py probe_p2_04.py --doc-pages    # R2
    uv run python scripts/probe/guarded.py probe_p2_04.py --workflows    # R3, then R4+R5 if allowed

Owner-approved, read-only, in this order and nothing else can be sent from this file:

* ``--swagger`` (R1): ``GET /docs/rest-api/ui/swagger.json``, the description published next
  to the on-box reference. Kept: the documented ``/workflows`` paths with their methods,
  parameters and response references; the ``WorkflowDTO`` definition and the definitions
  its properties reference, as property names, JSON types and ``$ref`` names. No prose.
  *Documented* evidence.
* ``--doc-pages`` (R2): ``GET /docs/rest-api/json_WorkflowDTO.html`` and
  ``GET /docs/rest-api/resource_WorkflowREST.html``. Kept: property names, types and the
  two documented flags of the data type; the endpoint sections of the resource page that
  name ``/workflows``, with body types, response codes and parameter names. The matching
  lines are shown for a human through the verifier and never stored. *Documented*.
* ``--workflows`` (R3): ``GET /rest/orgs/{org_id}/workflows`` with the two parameters P2-00
  verified it with, **once**. Kept: the row-count bucket, key names, JSON types and
  allow-listed enum tokens, and the row keys against the documented ``WorkflowDTO``.
  *Observed*. There is no single-workflow read: R1 and R2 established that this version
  documents none, so the XML comes from the collection row (``content.xml``, documented
  as a string) and nowhere else.

  Then R5, offline, over **one** row chosen deterministically: the row whose documented
  identity equals the owner's ``P2_PROBE_WORKFLOW_ID`` (in memory, never written or
  printed); else the only row, when the collection holds exactly one; else the run stops
  and asks for a selector. Its XML is analysed in memory by :func:`analyse_xml` with no
  further request. A document that declares a DTD or an entity, or references an entity
  that XML does not predefine, is refused unparsed; the parser fetches nothing; size and
  node counts are bounded. Kept: the root's local name, a classification of every
  namespace (an exact OMG or W3C allow-list, an IBM host class, or ``other``; never the
  URI), element local names by class, attribute *names* by element, which elements carry
  an identifier attribute (by attribute name), the source- and target-like attribute
  names and whether their values correspond to element identifiers, count buckets, and,
  for elements outside the OMG and W3C classes whose text parses as JSON, the key names
  and JSON types of that payload, with the keys that name a function candidate and the
  *form* of their value (integer, string, uuid-shaped string, object, other) listed
  apart. Never a text body, a value, a name, an id, a uuid or a script.

Every request goes through ``safe_http.ReadOnlyClient``, which refuses every other method.
The collection read stops, and writes nothing about the answer, when the status or the
container is not what the record describes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET  # see analyse_xml: nothing external is resolved

import httpx
from probe import EXPECTED_VERSION, ORG, OUT_DIR, Facts, bucket
from probe_00b import (
    _IDENT,
    _SECTION,
    _TEMPLATE_PATH,
    BUILTIN_OBJECT_TYPES,
    DOC_BASE,
    SWAGGER,
    Recorder,
    _definition,
    _operation,
    doc_lines,
    dto_facts,
    endpoint_facts,
    fetch_doc,
    verified_context,
)
from probe_env import ProbeEnvError, load_env
from safe_http import ReadOnlyClient, Result
from sanitise import (
    NAME_KEYED_CONTAINERS,
    SCHEMA_KEY,
    EnumCollector,
    UnsafeArtefactError,
    _generic_violations,
    dump_verified,
    safe_keys,
    shape_of,
)

TICKET = "P2-04"
PREFIX = "p2_04_"
LEDGER = "_ledger_p2_04.json"
EXIT_STOP = 5
WORKFLOWS = "/workflows"
DTO = "WorkflowDTO"
DOC_TYPE_PAGE = f"json_{DTO}.html"
DOC_RESOURCE_PAGE = "resource_WorkflowREST.html"
MAX_FOLLOWED_DEFINITIONS = 12
# What the P2-00 record verified of the collection (tests/fixtures/soar/verified/workflows.json).
COLLECTION_WRAPPER = "entities"
# Bounds of the offline XML analysis. Exceeding one is a recorded refusal, never a partial.
MAX_XML_CHARS = 2_000_000
MAX_XML_NODES = 20_000
MAX_JSON_CHARS = 200_000
MAX_JSON_DEPTH = 6
MAX_NAMES = 80  # distinct element or attribute names kept per list
MAX_KEYS_PER_OBJECT = 12  # more distinct keys in one JSON object is a name-keyed map
# Objects under these keys are keyed by names an administrator or an app chose.
NAME_KEYED_JSON_CONTAINERS = NAME_KEYED_CONTAINERS | {"inputs", "input_values", "params"}
# The only namespaces recognised by URI, exactly. Anything else is classified, never kept.
KNOWN_NAMESPACES: dict[str, str] = {
    "http://www.omg.org/spec/BPMN/20100524/MODEL": "bpmn_model",
    "http://www.omg.org/spec/BPMN/20100524/DI": "bpmn_di",
    "http://www.omg.org/spec/DD/20100524/DC": "omg_dc",
    "http://www.omg.org/spec/DD/20100524/DI": "omg_di",
    "http://www.w3.org/2001/XMLSchema-instance": "xsi",
    "http://www.w3.org/2001/XMLSchema": "xsd",
    "http://www.w3.org/XML/1998/namespace": "xml",
}
STANDARD_CLASSES = frozenset(KNOWN_NAMESPACES.values())
VENDOR_HOST_SUFFIX = ".ibm.com"  # a class, derived from the document; the URI is not kept
_DTD_OR_ENTITY = re.compile(r"<!(DOCTYPE|ENTITY)", re.I)
_UNDEFINED_ENTITY = re.compile(r"&(?!(amp|lt|gt|quot|apos|#[0-9]{1,7}|#x[0-9a-fA-F]{1,6});)")
_SOURCE_TARGET = re.compile(r"^(source|target)(ref|_?id)?$", re.I)
# Keys and attributes whose string values are names or identifiers, never schema keys.
_IDENTITY_VALUE_KEY = re.compile(r"name|_?id$|uuid|label|title|key$|ref$", re.I)
_FUNCTION_KEY = re.compile(r"function", re.I)
_REFERENCE_KEY = re.compile(r"uuid|programmatic|_id$|^id$|name", re.I)
# Where a row carries its identity: the documented ``workflow_id`` (R1, R2), then ``id``.
ID_KEYS = ("workflow_id", "id")


# ------------------------------------------------------------------ recording
def write(
    rec: Recorder, key: str, question: str, r: Result | None, facts: Facts, *,
    note: str, shape_source: Any = None,
) -> None:  # fmt: skip
    enums = EnumCollector()
    shape = shape_of(shape_source, enums=enums) if shape_source is not None else None
    kept = enums.to_json()
    if "object_type" in kept:
        kept["object_type"] = [v for v in kept["object_type"] if str(v) in BUILTIN_OBJECT_TYPES]
    document = {
        "_fixture": "verified-shape",
        "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
        "_ticket": TICKET,
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
        dump_verified(rec.out_dir / f"{PREFIX}{key}.json", document, rec.literals)
        rec.written.append(key)
    except UnsafeArtefactError as exc:
        rec.say(f"{key} NOT WRITTEN: {exc}")


def finish(rec: Recorder) -> None:
    path = rec.out_dir / LEDGER
    previous = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    merged = {row["step"]: row for row in previous.get("requests", []) if "step" in row}
    for step, row in rec.rows.items():
        # An earlier answer of the same step with another status is history, not noise:
        # it stays on the ledger under ``step@status`` (the 403 of 2026-09-22, say).
        earlier = merged.get(step)
        if earlier is not None and earlier.get("status") != row.get("status"):
            merged[f"{step}@{earlier.get('status')}"] = {
                **earlier,
                "step": f"{step}@{earlier.get('status')}",
            }
        merged[step] = row
    summary = {
        "_fixture": "verified-ledger",
        "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
        "_ticket": TICKET,
        "requests": list(merged.values()),
        "documentation_pages_read": sorted(
            {*previous.get("documentation_pages_read", []), *rec.docs_read}
        ),
        "refused_by_policy": rec.client.refused,
    }
    try:
        dump_verified(path, summary, rec.literals)
    except UnsafeArtefactError as exc:
        rec.say(f"ledger NOT WRITTEN: {exc}")
    rec.say(f"{rec.client.requests_sent} request(s) sent; {len(rec.written)} fixture(s) written")


def _fixture(rec: Recorder, key: str) -> Facts:
    path = rec.out_dir / f"{PREFIX}{key}.json"
    if not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    return doc.get("_facts") if isinstance(doc.get("_facts"), Mapping) else {}


# ----------------------------------------------------------------- R1: swagger
def workflow_swagger_facts(spec: Mapping[str, Any]) -> Facts:
    """The documented ``/workflows`` operations and the ``WorkflowDTO`` family, as names,
    JSON types and references. Descriptions, summaries and examples are never read."""
    paths = spec.get("paths") if isinstance(spec.get("paths"), Mapping) else {}
    definitions = spec.get("definitions") if isinstance(spec.get("definitions"), Mapping) else {}
    operations: dict[str, Facts] = {}
    for path, ops in sorted(paths.items()):
        template = str(path)
        if not _TEMPLATE_PATH.match(template) or WORKFLOWS not in template:
            continue
        if not isinstance(ops, Mapping):
            continue
        for method, op in ops.items():
            if method in ("get", "put", "post", "delete", "patch"):
                operations[f"{method.upper()} {template}"] = _operation(op)
    followed: dict[str, Facts] = {}
    wanted = [DTO]
    while wanted and len(followed) < MAX_FOLLOWED_DEFINITIONS:
        name = wanted.pop(0)
        if name in followed:
            continue
        found = _definition(definitions, name)
        followed[name] = found
        for prop in found.get("properties", {}).values():
            ref = prop.get("ref")
            if isinstance(ref, str) and ref not in followed and ref not in wanted:
                wanted.append(ref)
    return {
        "spec_version": spec.get("swagger")
        if isinstance(spec.get("swagger"), str) and re.match(r"^[0-9.]{1,8}$", spec["swagger"])
        else None,
        "paths_mentioning_workflows": operations,
        "definitions_named_like_a_workflow": sorted(
            k for k in definitions if _IDENT.match(str(k)) and "workflow" in str(k).lower()
        )[:40],
        "definitions": followed,
    }


def swagger(rec: Recorder) -> int:
    r = rec.send(
        f"doc:{SWAGGER}", "docs", "GET", DOC_BASE + SWAGGER, DOC_BASE + SWAGGER,
        default_params=False, max_bytes=60_000_000,
    )  # fmt: skip
    spec = r.json if isinstance(r.json, Mapping) else {}
    if r.status != 200 or not isinstance(spec.get("paths"), Mapping):
        rec.say(f"STOPPED: {SWAGGER} -> {r.status or r.error}, no paths; nothing written")
        return EXIT_STOP
    facts = workflow_swagger_facts(spec)
    write(
        rec, "doc_swagger_workflows", "docs", r, facts,
        note="documented, not live: the /workflows operations and the WorkflowDTO family of "
        "the description published next to the reference, as names, JSON types and "
        "references; no description text is kept",
    )  # fmt: skip
    rec.say("swagger: " + json.dumps(facts, sort_keys=True))
    return 0


# --------------------------------------------------------------- R2: doc pages
def doc_pages(rec: Recorder, context: int, max_lines: int) -> int:
    r = fetch_doc(rec, DOC_TYPE_PAGE)
    if r is None or not r.ok:
        rec.say(f"STOPPED: {DOC_TYPE_PAGE} -> {None if r is None else r.status or r.error}")
        return EXIT_STOP
    facts = dto_facts(r.body)
    write(
        rec, f"doc_type_{DTO}", "docs", None, {"data_type": DTO, **facts},
        note="property names, JSON types and flags from the appliance's API reference",
    )  # fmt: skip
    props = facts["properties"]
    rec.say(f"docs   {DTO}: {len(props)} propert(ies): " + json.dumps(props, sort_keys=True))

    page = fetch_doc(rec, DOC_RESOURCE_PAGE)
    if page is None or not page.ok:
        rec.say(f"STOPPED: {DOC_RESOURCE_PAGE} -> {None if page is None else page.status}")
        return EXIT_STOP
    lines = doc_lines(page.body)
    sections = sorted({line for line in lines if _SECTION.match(line) and WORKFLOWS in line})
    endpoints: dict[str, Facts] = {}
    for section in sections:
        method, _, path = section.partition(" ")
        if _TEMPLATE_PATH.match(path):
            endpoints[section] = endpoint_facts(lines, method, path)
    write(
        rec, "doc_workflow_rest", "docs", None, {"endpoints": endpoints},
        note="from the appliance's own API reference: every endpoint section that names "
        "/workflows, with its body types, response codes and parameter names; not sent",
    )  # fmt: skip
    rec.say(f"docs   {DOC_RESOURCE_PAGE}: " + json.dumps(endpoints, sort_keys=True))
    # The smallest relevant part of the page, for a human, through the verifier.
    rx = re.compile(r"workflow", re.I)
    keep: set[int] = set()
    for i, line in enumerate(lines):
        if rx.search(line):
            keep.update(range(max(0, i - context), min(len(lines), i + context + 1)))
    shown = sorted(keep)[:max_lines]
    rec.say(f"{DOC_RESOURCE_PAGE}: {len(lines)} line(s); {len(shown)} shown")
    last = -1
    for i in shown:
        if last >= 0 and i != last + 1:
            rec.say("    ...")
        rec.say(f"{i:5} {lines[i][:400]}")
        last = i
    return 0


# ------------------------------------------------------------- R3: collection
def collection_problem(r: Result) -> str | None:
    """Why this answer is not the container P2-00 verified, or None. Key names only."""
    if r.status != 200:
        return f"status {r.status or r.error}"
    if not isinstance(r.json, Mapping) or COLLECTION_WRAPPER not in r.json:
        return f"the answer is not a {COLLECTION_WRAPPER!r} wrapper"
    rows = r.json[COLLECTION_WRAPPER]
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        return f"{COLLECTION_WRAPPER!r} is not a list of objects"
    return None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def select_row(rows: list[Mapping[str, Any]], chosen: str) -> tuple[Mapping[str, Any] | None, str]:
    """The one research workflow, deterministically: the row whose ``workflow_id`` (the
    documented identity) or ``id`` equals the owner's ``P2_PROBE_WORKFLOW_ID``; else, when
    the collection holds exactly one row, that row; else none. Never "the first one" of
    several. The chosen id is used in memory and is never written or printed."""
    if chosen:
        if not chosen.isdigit():
            return None, "P2_PROBE_WORKFLOW_ID is not a positive integer"
        wanted = int(chosen)
        matches = [
            row
            for row in rows
            if any(row.get(key) == wanted and _positive_int(row.get(key)) for key in ID_KEYS)
        ]
        if len(matches) == 1:
            return matches[0], "the owner-designated workflow"
        return None, (
            "no row carries the owner-designated id"
            if not matches
            else "more than one row carries the owner-designated id"
        )
    if len(rows) == 1:
        return rows[0], "the only workflow the collection holds"
    return None, (
        f"{bucket(len(rows))} workflows and no P2_PROBE_WORKFLOW_ID: an explicit research "
        "workflow selector is required"
    )


def documented_properties(rec: Recorder) -> set[str]:
    """The WorkflowDTO property names the committed R1 and R2 fixtures record."""
    definition = _fixture(rec, "doc_swagger_workflows").get("definitions", {}).get(DTO, {})
    names = set(definition.get("properties", {}))
    names |= set(_fixture(rec, f"doc_type_{DTO}").get("properties", {}))
    return {n for n in names if _IDENT.match(str(n))}


def xml_property(content: Mapping[str, Any]) -> tuple[str | None, bool, str]:
    """``(property name, is a string, size bucket)`` of the first XML-like value."""
    for key in sorted(content, key=str):
        value = content[key]
        if isinstance(value, str) and value.lstrip().startswith("<"):
            name = str(key) if SCHEMA_KEY.match(str(key)) else "<key>"
            return name, True, _size_bucket(len(value))
    return None, False, "n/a"


def _size_bucket(n: int) -> str:
    for limit, label in ((0, "0"), (1_000, "<1KB"), (10_000, "<10KB"), (100_000, "<100KB")):
        if n <= limit:
            return label
    return "<1MB" if n <= 1_000_000 else ">=1MB"


def workflows(rec: Recorder) -> int:
    """R3: the collection, once. Then the selected row's XML is analysed in memory."""
    r = rec.send("workflows", "05§2", "GET", rec.org + WORKFLOWS, ORG + WORKFLOWS)
    problem = collection_problem(r)
    if problem is not None:
        rec.say(f"STOPPED: {problem}; nothing written about the answer, nothing more sent")
        return EXIT_STOP
    rows: list[Mapping[str, Any]] = list(r.json[COLLECTION_WRAPPER])
    observed = sorted({str(k) for row in rows for k in row if _IDENT.match(str(k))})
    documented = documented_properties(rec)
    facts: Facts = {
        "rows": bucket(len(rows)),
        "row_keys": observed,
        "documented_and_observed": sorted(set(observed) & documented),
        "documented_only": sorted(documented - set(observed)) if rows else [],
        "observed_only": sorted(set(observed) - documented),
    }
    write(
        rec, "workflows", "05§2", r, facts,
        note="observed, read-only: the workflow collection; key names, types and allow-listed "
        "tokens of its rows, never a value; the row keys against the documented WorkflowDTO",
        shape_source=r.json,
    )  # fmt: skip
    rec.say("05§2   workflows: " + json.dumps(facts, sort_keys=True))
    if not rows:
        rec.say("R5 NOT RUN: the collection holds no workflow")
        return 0
    row, why = select_row(rows, rec.env.workflow_id)
    if row is None:
        rec.say(f"STOPPED: {why}; no row was analysed")
        return EXIT_STOP
    rec.say(f"selected {why}")
    content = row.get("content") if isinstance(row.get("content"), Mapping) else {}
    name, is_string, size = xml_property(content)
    xml_facts = {
        "content_keys": safe_keys(content),
        "xml_bearing_property": name,
        "xml_bearing_property_in_content": name is not None,
        "xml_is_string": is_string,
        "xml_size": size,
    }
    if name is None:
        write(
            rec, "workflow_xml", "05§2", r, {**xml_facts, "parsed": False},
            note="observed: the selected row carries no XML-like string under content",
        )  # fmt: skip
        rec.say("R5 NOT RUN: no XML-bearing string property under content")
        return 0
    analysis = analyse_xml(content[name])
    write(
        rec, "workflow_xml", "05§2", r, {**xml_facts, **analysis},
        note="observed, offline: structural facts of one workflow's XML, taken from its "
        "collection row and analysed in memory; no text body, value, name, id, uuid or "
        "script was kept and the XML was never written",
    )  # fmt: skip
    rec.say("05§2   workflow xml: " + json.dumps({**xml_facts, **analysis}, sort_keys=True))
    return 0


# ------------------------------------------------------------ R5: XML analysis
def classify_namespace(uri: str) -> str:
    """A class, never the URI. Exact allow-list, then the vendor host class, then other."""
    if uri in KNOWN_NAMESPACES:
        return KNOWN_NAMESPACES[uri]
    try:
        host = urlsplit(uri).hostname or ""
    except ValueError:
        host = ""
    if host == VENDOR_HOST_SUFFIX.lstrip(".") or host.endswith(VENDOR_HOST_SUFFIX):
        return "vendor_ibm"
    return "other"


def _split(tag: str) -> tuple[str, str]:
    """``(namespace class, local name)`` of an ElementTree tag. ``none`` for no namespace."""
    if tag.startswith("{"):
        uri, _, local = tag[1:].partition("}")
        return classify_namespace(uri), local
    return "none", tag


def _safe_name(name: str) -> str:
    return name if SCHEMA_KEY.match(name) and not _generic_violations(name) else "<name>"


def _names(names: set[str]) -> list[str]:
    return sorted(names)[:MAX_NAMES]


def _json_shape(value: Any, depth: int, strings: set[str], key: str | None = None) -> Any:
    """Key names and JSON types of an embedded payload. Collapsed to ``<name>``: a key that
    is also a name or an identifier somewhere in the document (the value of a name-, id-,
    uuid- or label-like attribute or key), because such a key is a name, not a schema key;
    every key of an object under
    one of the name-keyed containers (``properties``, ``fields``, ``inputs``, ...); and an
    object with more than ``MAX_KEYS_PER_OBJECT`` keys. Anything deeper than
    ``MAX_JSON_DEPTH`` is ``<deep>``. Values never survive: only their JSON type does."""
    if isinstance(value, bool):
        return "bool"
    if value is None:
        return "null"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if depth >= MAX_JSON_DEPTH:
        return "<deep>"
    if isinstance(value, list):
        shapes = [_json_shape(v, depth + 1, strings) for v in value[:50]]
        merged: list[Any] = []
        for s in shapes:
            if s not in merged:
                merged.append(s)
        return merged[:8]
    if isinstance(value, Mapping):
        if len(value) > MAX_KEYS_PER_OBJECT or key in NAME_KEYED_JSON_CONTAINERS:
            inner: list[Any] = []
            for v in list(value.values())[:8]:
                shaped = _json_shape(v, depth + 1, strings)
                if shaped not in inner:
                    inner.append(shaped)
            return {"<name>": inner[0] if len(inner) == 1 else inner} if inner else {}
        out: dict[str, Any] = {}
        for k in sorted(value, key=str):
            name = str(k)
            safe = "<name>" if name in strings else _safe_name(name)
            shaped = _json_shape(value[k], depth + 1, strings, name)
            out[safe] = shaped if safe not in out else [out[safe], shaped]
        return out
    return "unknown"


def _identity_values(value: Any, out: set[str], key: str | None = None, depth: int = 0) -> None:
    """Every string that is the value of a name-, id-, uuid- or label-like key: what an
    administrator or an app named something. A JSON key equal to one of them is a name."""
    if depth > MAX_JSON_DEPTH:
        return
    if isinstance(value, str):
        if key is not None and _IDENTITY_VALUE_KEY.search(key):
            out.add(value)
    elif isinstance(value, list):
        for v in value[:200]:
            _identity_values(v, out, key, depth + 1)
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _identity_values(v, out, str(k), depth + 1)


def _walk_keys(shape: Any, path: str, found: dict[str, Any], rx: re.Pattern[str]) -> None:
    if isinstance(shape, Mapping):
        for k, v in shape.items():
            here = f"{path}.{k}" if path else str(k)
            if not str(k).startswith("<") and rx.search(str(k)):
                found[here] = v if not isinstance(v, Mapping) else sorted(map(str, v))
            _walk_keys(v, here, found, rx)
    elif isinstance(shape, list):
        for v in shape:
            _walk_keys(v, path + "[]", found, rx)


_ID_ATTRIBUTE = re.compile(r"^id$|_?id$|^uuid$", re.I)
_UUID_SHAPED = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _form_of(value: Any) -> str:
    """The form of a reference value: never the value."""
    if isinstance(value, bool):
        return "bool"
    if value is None:
        return "null"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        if _UUID_SHAPED.match(value):
            return "uuid_shaped_string"
        if value.isdigit():
            return "digits_string"
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    return "other"


def _reference_forms(value: Any, path: str, depth: int = 0) -> list[tuple[str, str]]:
    """``(path, form)`` for every value under a key that names a function, walking the
    payload in memory. Within an object under such a key, each identity-like key is
    reported with its own form (``function.uuid: uuid_shaped_string``)."""
    out: list[tuple[str, str]] = []
    if depth > MAX_JSON_DEPTH:
        return out
    if isinstance(value, Mapping):
        for k, v in value.items():
            name = str(k)
            safe = _safe_name(name)
            here = f"{path}.{safe}"
            if _FUNCTION_KEY.search(name) and safe != "<name>":
                out.append((here, _form_of(v)))
                if isinstance(v, Mapping):
                    for k2, v2 in v.items():
                        inner = _safe_name(str(k2))
                        if inner != "<name>" and _REFERENCE_KEY.search(inner):
                            out.append((f"{here}.{inner}", _form_of(v2)))
            out.extend(_reference_forms(v, here, depth + 1))
    elif isinstance(value, list):
        for v in value[:50]:
            out.extend(_reference_forms(v, path + "[]", depth + 1))
    return out


def analyse_xml(text: str) -> Facts:
    """Structural facts of an untrusted XML document, and nothing of its content.

    Refused unparsed: more than ``MAX_XML_CHARS`` characters; a ``DOCTYPE`` or ``ENTITY``
    declaration; a reference to an entity XML does not predefine. The parser is the
    standard library's expat-backed one with nothing configured to resolve anything: it
    is given text, not a URL, it fetches no DTD, schema or external entity, and with the
    two refusals above there is no declaration for it to expand. More than
    ``MAX_XML_NODES`` elements stops the analysis with that fact recorded.
    """
    if len(text) > MAX_XML_CHARS:
        return {"parsed": False, "refused": "document larger than the bound"}
    if _DTD_OR_ENTITY.search(text):
        return {"parsed": False, "refused": "a DOCTYPE or ENTITY declaration is present"}
    if _UNDEFINED_ENTITY.search(text):
        return {"parsed": False, "refused": "a reference to an entity XML does not predefine"}
    parser = ET.XMLPullParser(events=("start",))
    elements: list[ET.Element] = []
    root: ET.Element | None = None
    try:
        parser.feed(text)
        for _, element in parser.read_events():
            if root is None:
                root = element
            elements.append(element)
            if len(elements) > MAX_XML_NODES:
                return {"parsed": False, "refused": "more elements than the bound"}
        parser.close()
    except ET.ParseError:
        return {"parsed": False, "refused": "malformed XML"}
    if root is None:
        return {"parsed": False, "refused": "no root element"}

    # Pass one: every string the document uses as a name or an identifier (the value of a
    # name-, id-, uuid- or label-like attribute or JSON key), so that a JSON key equal to
    # one of them is treated as a name in pass two, and its type is kept under ``<name>``.
    strings: set[str] = set()
    payloads: list[tuple[str, Any]] = []
    json_failures = 0
    for element in elements:
        cls, local = _split(element.tag)
        for raw, value in element.attrib.items():
            if _IDENTITY_VALUE_KEY.search(_split(raw)[1]):
                strings.add(value)
        body = (element.text or "").strip()
        if cls not in STANDARD_CLASSES and body[:1] in ("{", "[") and len(body) <= MAX_JSON_CHARS:
            try:
                payload = json.loads(body)
            except ValueError:
                json_failures += 1
            else:
                _identity_values(payload, strings)
                payloads.append((f"{cls}:{_safe_name(local)}", payload))

    by_class: dict[str, set[str]] = {}
    attributes: dict[str, set[str]] = {}
    source_target: dict[str, set[str]] = {}
    with_text: dict[str, int] = {}
    json_payloads: dict[str, list[Any]] = {}
    referenced: set[str] = set()
    edge_elements = 0
    for element in elements:
        cls, local = _split(element.tag)
        local = _safe_name(local)
        by_class.setdefault(cls, set()).add(local)
        label = f"{cls}:{local}"
        for raw in element.attrib:
            _, attr = _split(raw)
            attr = _safe_name(attr)
            attributes.setdefault(label, set()).add(attr)
            if _SOURCE_TARGET.search(attr):
                source_target.setdefault(label, set()).add(attr)
                referenced.add(element.attrib[raw])
        names = source_target.get(label, set())
        if any("source" in n.lower() for n in names) and any("target" in n.lower() for n in names):
            edge_elements += 1
        if (element.text or "").strip():
            with_text[label] = with_text.get(label, 0) + 1
    for label, payload in payloads:
        json_payloads.setdefault(label, []).append(_json_shape(payload, 0, strings))
    referenced_locals: set[str] = set()
    identifiers: set[str] = set()  # the values of id-named attributes, in memory only
    identifier_attributes: dict[str, set[str]] = {}
    for element in elements:
        cls, local = _split(element.tag)
        label = f"{cls}:{_safe_name(local)}"
        for raw, value in element.attrib.items():
            attr = _split(raw)[1]
            if _ID_ATTRIBUTE.match(attr):
                identifiers.add(value)
                identifier_attributes.setdefault(label, set()).add(_safe_name(attr))
                if value in referenced:
                    referenced_locals.add(label)
    resolved = sum(1 for value in referenced if value in identifiers)
    payload_shapes: dict[str, Any] = {}
    for label, shapes in sorted(json_payloads.items()):
        unique: list[Any] = []
        for s in shapes:
            if s not in unique:
                unique.append(s)
        payload_shapes[label] = unique[0] if len(unique) == 1 else unique[:8]
    function_keys: dict[str, Any] = {}
    reference_keys: dict[str, Any] = {}
    for label, shape in payload_shapes.items():
        _walk_keys(shape, label, function_keys, _FUNCTION_KEY)
    for path, shape in list(function_keys.items()):
        if isinstance(shape, list):  # an object: which of its keys look like an identity
            reference_keys[path] = [k for k in shape if _REFERENCE_KEY.search(k)]
    # The form of every function-candidate value, from the payloads in memory: what the
    # reference *is* (an integer, a uuid-shaped string, an object with these keys), never
    # what it says.
    reference_forms: dict[str, list[str]] = {}
    for label, payload in payloads:
        for path, form in _reference_forms(payload, label):
            forms = reference_forms.setdefault(path, [])
            if form not in forms:
                forms.append(form)
    root_class, root_local = _split(root.tag)
    return {
        "parsed": True,
        "root": {"namespace_class": root_class, "local_name": _safe_name(root_local),
                 "attribute_names": _names({_safe_name(_split(a)[1]) for a in root.attrib})},
        "namespace_classes": {cls: _names(names) for cls, names in sorted(by_class.items())},
        "elements": bucket(len(elements)),
        "attribute_names_by_element": {k: _names(v) for k, v in sorted(attributes.items())},
        "source_target_attribute_names_by_element": {
            k: _names(v) for k, v in sorted(source_target.items())
        },
        "elements_with_both_a_source_and_a_target_attribute": bucket(edge_elements),
        "identifier_attribute_names_by_element": {
            k: _names(v) for k, v in sorted(identifier_attributes.items())
        },
        "elements_referenced_by_a_source_or_target_attribute": _names(referenced_locals),
        "referenced_values": bucket(len(referenced)),
        "referenced_values_that_are_element_identifiers": bucket(resolved),
        "every_referenced_value_is_an_element_identifier": bool(referenced)
        and resolved == len(referenced),
        "elements_with_text_by_element": {k: bucket(n) for k, n in sorted(with_text.items())},
        "json_payload_shapes_by_element": payload_shapes,
        "json_payloads_that_did_not_parse": bucket(json_failures),
        "function_candidate_keys": function_keys,
        "identity_like_keys_under_function_candidates": reference_keys,
        "function_candidate_value_forms": reference_forms,
    }  # fmt: skip


# --------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    step = parser.add_mutually_exclusive_group(required=True)
    step.add_argument("--swagger", action="store_true", help="R1: one static GET")
    step.add_argument("--doc-pages", action="store_true", help="R2: two static GETs")
    step.add_argument(
        "--workflows", action="store_true", help="R3: the collection; R4 and R5 only if allowed"
    )
    parser.add_argument("--context", type=int, default=6, help="lines around a match (R2)")
    parser.add_argument("--max-lines", type=int, default=160, help="lines shown at most (R2)")
    args = parser.parse_args(argv)
    try:
        env = load_env()
    except ProbeEnvError as exc:
        print(f"cannot run: {exc} (values come from the environment or a git-ignored .env)")
        return 2
    context, label = verified_context(env)
    print(f"TLS: verified ({label}); chain and host name are checked; no unverified connection")
    client = ReadOnlyClient(env, context)
    rec = Recorder(env, client, OUT_DIR)
    try:
        if args.swagger:
            code = swagger(rec)
        elif args.doc_pages:
            code = doc_pages(rec, args.context, args.max_lines)
        else:
            code = workflows(rec)
        finish(rec)
        return code
    except (httpx.HTTPError, OSError) as exc:  # never let a message with a URL escape
        print(f"probe aborted: {type(exc).__name__}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
