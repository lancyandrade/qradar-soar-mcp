"""P2-00: probe a QRadar SOAR appliance read-only and record what exists.

    uv run python scripts/probe/probe.py --smoke         # ONE authenticated read, no files
    uv run python scripts/probe/probe.py                 # the plan (GET + 2 read-only queries)
    uv run python scripts/probe/probe.py --with-export   # + POST /configurations/exports (once)
    uv run python scripts/probe/probe.py --tls-mode lab-pinned   # LAB ONLY, explicit opt-in

Safety properties (see README.md):

* every request goes through ``safe_http.ReadOnlyClient`` (GET, plus the three
  approved read-only POSTs); a refused request is recorded, never sent;
* response bodies exist in memory only; what is written is a *shape* (keys and
  types) plus booleans/counts, and every file passes ``sanitise.verify_clean``
  against the live connection values before it touches the disk;
* object ids discovered along the way are used to build the next request and
  are never printed or stored; paths are recorded as templates;
* the terminal shows templates, status codes, key names and booleans.

This script is research tooling. It is not part of the installed package.
"""

from __future__ import annotations

import argparse
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
from probe_env import ROOT, ProbeEnv, ProbeEnvError, load_env
from safe_http import ProbePolicyError, ReadOnlyClient, Result
from sanitise import (
    EnumCollector,
    UnsafeArtefactError,
    dump_verified,
    safe_keys,
    safe_keys_matching,
    safe_text,
    shape_of,
)
from tls_check import LAB_WARNING, TlsReport, inspect, pinned_context

EXPECTED_VERSION = "51.0.9.0.20848"
OUT_DIR = ROOT / "tests" / "fixtures" / "soar" / "verified"
EXPORT_BODY = {"layouts": True, "actions": True, "phases_and_tasks": True}
# The smallest read-only query: one row, no criteria. Nothing else is ever sent.
SINGLE_ROW_QUERY = {"filters": [], "start": 0, "length": 1}
PAGED_PARAMS = {"return_level": "normal"}
DOC_KEYWORDS = (
    "playbook", "configuration", "function", "attachment", "history", "newsfeed", "timeline",
    "type", "table", "apikey", "api_key", "session", "workflow", "script", "action", "artifact",
    "task", "group", "phase", "messagedestination", "message_destination", "incident", "org",
)  # fmt: skip

Facts = dict[str, Any]


@dataclass(slots=True)
class Ctx:
    """Everything discovered during a run. Lives in memory; never printed."""

    ids: dict[str, str] = field(default_factory=dict)
    function_field_uuids: set[str] = field(default_factory=set)
    documented: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)  # compared, never recorded


@dataclass(slots=True)
class Step:
    key: str
    question: str
    method: str
    template: str
    params: dict[str, str] = field(default_factory=dict)
    needs: tuple[str, ...] = ()
    discover: Callable[[Ctx, Any], None] | None = None
    analyse: Callable[[Ctx, Result], Facts] | None = None
    headers_only: bool = False
    name_keyed: bool = False
    bare_params: bool = False  # send no default query parameters
    custom: Callable[[ProbeEnv, ReadOnlyClient, Ctx], tuple[Result | None, Facts]] | None = None
    json_body: Any = None
    max_bytes: int = 8_000_000
    note: str = ""


# ------------------------------------------------------------------- helpers
def rows_of(payload: Any) -> list[Any]:
    """The element list of a collection response, whatever wrapper it uses."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, Mapping):
        for key in ("entities", "data", "results", "items"):
            if isinstance(payload.get(key), list):
                return list(payload[key])
    return []


def first_id(payload: Any, *keys: str) -> str | None:
    for row in rows_of(payload):
        if isinstance(row, Mapping):
            for key in keys or ("id",):
                if isinstance(row.get(key), int | str) and not isinstance(row.get(key), bool):
                    return str(row[key])
    return None


def remember(name: str, *keys: str) -> Callable[[Ctx, Any], None]:
    def _discover(ctx: Ctx, payload: Any) -> None:
        found = first_id(payload, *keys)
        if found is not None and name not in ctx.ids:
            ctx.ids[name] = found

    return _discover


def bucket(n: int) -> str:
    return "0" if n == 0 else "1-9" if n < 10 else "10-99" if n < 100 else "100+"


# ------------------------------------------------------------------ analyses
def a_collection(_: Ctx, r: Result) -> Facts:
    rows = rows_of(r.json)
    wrapper = safe_keys(r.json) if isinstance(r.json, Mapping) else []
    return {
        "is_list": isinstance(r.json, list),
        "wrapper_keys": wrapper,
        "rows": bucket(len(rows)),
        "paging_keys": [
            k for k in wrapper if re.search(r"total|start|length|page|cursor|next", k, re.I)
        ],
        "row_keys": safe_keys(rows[0]) if rows else [],
    }


def a_const(_: Ctx, r: Result) -> Facts:
    version = (r.json or {}).get("server_version") if isinstance(r.json, Mapping) else None
    text = version.get("version") if isinstance(version, Mapping) else None
    return {
        "top_level_keys": bucket(len(safe_keys(r.json))),
        "server_version_keys": safe_keys(version),
        "matches_expected_version": text == EXPECTED_VERSION,
    }


def _perm_counts(node: Any, depth: int = 0) -> tuple[int, int, bool]:
    """(true, false, seen) over every ``perms`` map. Counts only: never a name."""
    true = false = 0
    seen = False
    if depth > 4:
        return true, false, seen
    if isinstance(node, Mapping):
        for key, value in node.items():
            if key == "perms" and isinstance(value, Mapping):
                seen = True
                true += sum(1 for v in value.values() if v is True)
                false += sum(1 for v in value.values() if v is False)
            else:
                t, f, s = _perm_counts(value, depth + 1)
                true, false, seen = true + t, false + f, seen or s
    elif isinstance(node, list):
        for item in node[:20]:
            t, f, s = _perm_counts(item, depth + 1)
            true, false, seen = true + t, false + f, seen or s
    return true, false, seen


def a_permissions(_: Ctx, r: Result) -> Facts:
    true, false, seen = _perm_counts(r.json)
    return {
        "top_level_keys": safe_keys(r.json),
        "permission_like_keys": safe_keys_matching(r.json, r"perm|role|privilege|scope|capabilit"),
        "perms_map_present": seen,
        "perms_true": bucket(true),
        "perms_false": bucket(false),
        "rows": bucket(len(rows_of(r.json))),
    }


# Generic categories, decided by the verb a permission identifier starts with. The
# identifiers themselves are privilege detail of one deployment and are never recorded.
PERMISSION_CATEGORIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("read", re.compile(r"^(read|view|download|list|get)[_.:-]", re.I)),
    ("create", re.compile(r"^(create|add)[_.:-]", re.I)),
    ("edit", re.compile(r"^(edit|update|change|modify|assign|close|move)[_.:-]", re.I)),
    ("delete", re.compile(r"^(delete|remove|purge)[_.:-]", re.I)),
    ("administer", re.compile(r"^(admin|manage|master)", re.I)),
    ("run", re.compile(r"^(run|invoke|execute)[_.:-]", re.I)),
)
MUTATING = ("create", "edit", "delete", "administer", "run")


def categorise_permissions(names: list[str]) -> dict[str, int]:
    counts = {category: 0 for category, _ in PERMISSION_CATEGORIES}
    counts["uncategorised"] = 0
    for name in names:
        for category, pattern in PERMISSION_CATEGORIES:
            if pattern.search(name):
                counts[category] += 1
                break
        else:
            counts["uncategorised"] += 1
    return counts


def own_key_permissions(key_id: str) -> Callable[[Ctx, Result], Facts]:
    """Is the probing key's own permission set readable, and is it read-only?

    The key's entry is matched in memory by key id. Only generic categories and size
    buckets are reported: no permission identifier and no id is ever written or printed.
    Capability is inferred from this metadata alone; nothing is attempted to see whether
    it would be allowed.
    """

    def _analyse(ctx: Ctx, r: Result) -> Facts:
        mine = [
            row for row in rows_of(r.json)
            if isinstance(row, Mapping) and str(row.get("apikey_id")) == key_id
        ]  # fmt: skip
        facts = a_permissions(ctx, r)
        facts["own_key_found"] = len(mine) == 1
        if len(mine) == 1:
            raw = mine[0].get("permissions")
            names = [p for p in raw if isinstance(p, str)] if isinstance(raw, list) else []
            counts = categorise_permissions(names)
            ctx.counts["own_mutating_permissions"] = sum(counts[c] for c in MUTATING)
            facts.update(
                {
                    "own_permissions_listed": isinstance(raw, list),
                    "own_permission_total": bucket(len(names)),
                    "own_permission_categories": {k: bucket(v) for k, v in counts.items()},
                    "own_key_has_mutating_permissions": any(counts[c] for c in MUTATING),
                    "own_key_enabled": mine[0].get("enabled") is True,
                }
            )
        return facts

    return _analyse


def a_export(_: Ctx, r: Result) -> Facts:
    doc = r.json if isinstance(r.json, Mapping) else {}
    wanted = (
        "playbooks", "functions", "scripts", "workflows", "actions", "message_destinations",
        "incident_types", "fields", "types",
    )  # fmt: skip
    sections = {
        k: (bucket(len(v)) if isinstance(v, list | Mapping) else type(v).__name__)
        for k, v in doc.items()
        if SCHEMA_KEY_OK(k)
    }
    playbooks = doc.get("playbooks") if isinstance(doc.get("playbooks"), list) else []
    types = doc.get("types") if isinstance(doc.get("types"), list) else []
    return {
        "is_json_document": bool(doc),
        "sections": sections,
        "contains": {k: k in doc and bool(doc[k]) for k in wanted},
        "playbook_keys": safe_keys(playbooks[0]) if playbooks else [],
        "playbook_xml_like_keys": safe_keys_matching(playbooks[:3], r"xml|content|bpmn"),
        "type_id_distribution": _distribution(types, "type_id"),
        "export_format_version_present": "export_format_version" in doc,
    }


def SCHEMA_KEY_OK(key: object) -> bool:  # noqa: N802 - reads as a predicate constant
    return isinstance(key, str) and re.fullmatch(r"[a-z_][a-z0-9_]{0,63}", key) is not None


def _distribution(rows: Any, key: str) -> dict[str, str]:
    counts: dict[str, int] = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, Mapping) and isinstance(row.get(key), int):
            counts[str(row[key])] = counts.get(str(row[key]), 0) + 1
    return {k: bucket(v) for k, v in sorted(counts.items())}


def a_types(ctx: Ctx, r: Result) -> Facts:
    doc = r.json
    rows = list(doc.values()) if isinstance(doc, Mapping) else rows_of(doc)
    rows = [x for x in rows if isinstance(x, Mapping)]
    by_type_id: dict[str, set[str]] = {}
    flags: set[str] = set()
    for row in rows:
        schema_keys = set(safe_keys(row))
        by_type_id.setdefault(str(row.get("type_id")), set()).update(schema_keys)
        flags.update(k for k in schema_keys if isinstance(row.get(k), bool))
    common = set.intersection(*by_type_id.values()) if by_type_id else set()
    per_type: dict[str, dict[str, Any]] = {}
    for row in rows:
        info = per_type.setdefault(str(row.get("type_id")), {"n": 0, "with_parent": 0})
        info["n"] += 1
        info["with_parent"] += 1 if row.get("parent_types") else 0
    many = {k: v for k, v in per_type.items() if v["n"] > 1}
    if isinstance(doc, Mapping):
        for name, row in doc.items():
            if isinstance(row, Mapping) and row.get("type_id") == 8:
                ctx.ids.setdefault("datatable_type", str(name))
                break
    return {
        "type_ids_with_more_than_one_type": sorted(many),
        "all_of_those_have_parent_types": bool(many)
        and all(v["with_parent"] == v["n"] for v in many.values()),
        "response_is_name_keyed_map": isinstance(doc, Mapping),
        "types": bucket(len(rows)),
        "type_id_distribution": _distribution(rows, "type_id"),
        "keys_common_to_all": sorted(common),
        "keys_only_in_some_type_ids": {
            k: sorted(v - common) for k, v in sorted(by_type_id.items())
        },
        "flag_keys": sorted(flags),
        "has_parent_types_key": any("parent_types" in row for row in rows),
    }


def a_function_fields(ctx: Ctx, r: Result) -> Facts:
    rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)]
    ctx.function_field_uuids = {str(x["uuid"]) for x in rows if "uuid" in x}
    return {
        "fields": bucket(len(rows)),
        "field_keys": safe_keys(rows[0]) if rows else [],
        "has_name": all("name" in x for x in rows) and bool(rows),
        "has_input_type": all("input_type" in x for x in rows) and bool(rows),
        "has_required": any("required" in x for x in rows),
    }


def a_function(ctx: Ctx, r: Result) -> Facts:
    doc = r.json if isinstance(r.json, Mapping) else {}
    items = doc.get("view_items") if isinstance(doc.get("view_items"), list) else []
    refs = [str(i.get("content")) for i in items if isinstance(i, Mapping) and i.get("content")]
    resolved = sum(1 for ref in refs if ref in ctx.function_field_uuids)
    return {
        "keys": safe_keys(doc),
        "has_view_items": bool(items),
        "view_item_keys": safe_keys(items[0]) if items else [],
        "input_like_keys": safe_keys_matching(doc, r"input|param|view_item|field"),
        "view_items_resolving_to_function_fields": f"{resolved}/{len(refs)}" if refs else "n/a",
    }


def a_workflow(_: Ctx, r: Result) -> Facts:
    doc = r.json if isinstance(r.json, Mapping) else {}
    content = doc.get("content") if isinstance(doc.get("content"), Mapping) else {}
    xml = content.get("xml") if isinstance(content, Mapping) else None
    return {
        "keys": safe_keys(doc),
        "content_keys": safe_keys(content),
        "content_xml_is_string": isinstance(xml, str),
        "content_xml_looks_like_bpmn": isinstance(xml, str) and "definitions" in xml[:400],
    }


def a_playbook(_: Ctx, r: Result) -> Facts:
    doc = r.json if isinstance(r.json, Mapping) else {}
    return {
        "keys": safe_keys(doc),
        "xml_like_keys": safe_keys_matching(doc, r"xml|bpmn|content"),
        "status_like_keys": safe_keys_matching(doc, r"status|enabled|activ|deploy"),
        "function_like_keys": safe_keys_matching(doc, r"function|script|step|node"),
    }


def a_tasks(_: Ctx, r: Result) -> Facts:
    rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)]
    return {
        "rows": bucket(len(rows)),
        "every_task_has_vers": bool(rows) and all("vers" in x for x in rows),
        "version_like_keys": safe_keys_matching(rows[:3], r"^vers$|version"),
    }


def a_comments(_: Ctx, r: Result) -> Facts:
    rows = [x for x in rows_of(r.json) if isinstance(x, Mapping)]
    return {
        "rows": bucket(len(rows)),
        "has_children_key": any("children" in x for x in rows),
        "has_parent_id_key": any("parent_id" in x for x in rows),
        "text_type": sorted({type(x.get("text")).__name__ for x in rows}),
    }


# The Phase-1 incident projection (08 §7): every one of these must exist on the DTO.
PROJECTION_FIELDS = (
    "id", "name", "description", "plan_status", "phase_id", "severity_code", "incident_type_ids",
    "owner_id", "discovered_date", "create_date", "start_date", "due_date",
    "inc_last_modified_date", "resolution_id", "resolution_summary", "vers",
)  # fmt: skip


def _type_name(value: object) -> str:
    if isinstance(value, list):
        return "list[" + "|".join(sorted({type(v).__name__ for v in value})) + "]"
    return type(value).__name__


def a_incident(_: Ctx, r: Result) -> Facts:
    doc = r.json if isinstance(r.json, Mapping) else {}
    select_keys = ("severity_code", "plan_status", "phase_id", "owner_id", "incident_type_ids",
                   "resolution_id")  # fmt: skip
    return {
        "key_count": bucket(len(doc)),
        "select_value_types": {k: _type_name(doc[k]) for k in select_keys if k in doc},
        "has_properties": isinstance(doc.get("properties"), Mapping),
        "description_type": _type_name(doc.get("description")),
        "projection_fields_missing": [k for k in PROJECTION_FIELDS if k not in doc],
    }


def counted(name: str) -> Callable[[Ctx, Result], Facts]:
    """Keep recordsFiltered in memory under ``name``; report only that the keys exist."""

    def _analyse(ctx: Ctx, r: Result) -> Facts:
        doc = r.json if isinstance(r.json, Mapping) else {}
        if isinstance(doc.get("recordsFiltered"), int):
            ctx.counts[name] = doc["recordsFiltered"]
        if isinstance(doc.get("recordsTotal"), int):
            ctx.counts["total"] = doc["recordsTotal"]
        return {**a_collection(ctx, r), "rows_returned_at_most_one": len(rows_of(doc)) <= 1}

    return _analyse


def a_filter_semantics(ctx: Ctx, r: Result) -> Facts:
    facts = counted("or")(ctx, r)
    c = ctx.counts
    if all(k in c for k in ("active", "closed", "and", "or", "total")):
        facts.update(
            {
                "and_within_one_filter_is_intersection": c["and"] == 0,
                "or_across_filters_is_union": c["or"] == c["active"] + c["closed"],
                "active_plus_closed_equals_total": c["active"] + c["closed"] == c["total"],
                "both_filters_matched_something": c["active"] > 0 and c["closed"] > 0,
            }
        )
    return facts


def a_history_before(ctx: Ctx, r: Result) -> Facts:
    ctx.counts["export_history_before"] = len(rows_of(r.json))
    return a_collection(ctx, r)


def a_history_after(ctx: Ctx, r: Result) -> Facts:
    before = ctx.counts.get("export_history_before")
    after = len(rows_of(r.json))
    return {
        **a_collection(ctx, r),
        "compared_with_history_before_the_export": before is not None,
        "export_added_a_history_entry": None if before is None else after > before,
    }


def a_history(_: Ctx, r: Result) -> Facts:
    return {
        "top_level_keys": safe_keys(r.json) if isinstance(r.json, Mapping) else [],
        "rows": bucket(len(rows_of(r.json))),
        "row_keys": safe_keys(rows_of(r.json)[0]) if rows_of(r.json) else [],
        "result_like_keys": safe_keys_matching(r.json, r"result|output|function|workflow|playbook"),
    }


_DIGITS = re.compile(r"\d+")


def error_facts(r: Result, literals: Mapping[str, str]) -> Facts:
    """What the server said about a failure: its error code and a masked message.

    Every digit run becomes ``#`` (ids, org numbers), the text is cut short and it is
    shown only if it passes the same verifier as everything else.
    """
    doc = r.json if isinstance(r.json, Mapping) else {}
    code = doc.get("error_code")
    message = doc.get("message")
    facts: Facts = {"error_code": code if isinstance(code, str) and len(code) < 60 else None}
    if isinstance(message, str):
        masked = _DIGITS.sub("#", message)[:200]
        facts["message_masked"] = safe_text(masked, literals)
    return facts


ATTACHMENT_SCAN_LIMIT = 10  # owner-approved ceiling; metadata only; stop at the first hit


def scan_for_attachment(
    env: ProbeEnv, client: ReadOnlyClient, ctx: Ctx
) -> tuple[Result | None, Facts]:
    """Find ONE incident that carries an attachment, reading attachment metadata only.

    An owner-chosen incident (``P2_PROBE_INCIDENT_ID``) is used if given. Otherwise at
    most ``ATTACHMENT_SCAN_LIMIT`` incidents are looked at, via a single read-only query
    that asks for the default (partial) rows because only ids are needed. The scan stops
    at the first attachment. Ids stay in memory.
    """
    org = ORG.format(org_id=env.org_id)
    template = INC + "/attachments"
    if env.incident_id:
        candidates, source = [env.incident_id], "owner-chosen incident"
    else:
        query = client.request(
            "POST", org + "/incidents/query_paged", ORG + "/incidents/query_paged",
            json_body={"filters": [], "start": 0, "length": ATTACHMENT_SCAN_LIMIT},
        )  # fmt: skip
        rows = rows_of(query.json) if query.ok else []
        candidates = [
            str(row["id"]) for row in rows
            if isinstance(row, Mapping) and isinstance(row.get("id"), int)
        ][:ATTACHMENT_SCAN_LIMIT]  # fmt: skip
        source = "bounded scan"
    last: Result | None = None
    scanned, found_keys = 0, []
    for incident_id in candidates:
        scanned += 1
        last = client.request("GET", f"{org}/incidents/{incident_id}/attachments", template)
        attachments = [a for a in rows_of(last.json) if isinstance(a, Mapping)] if last.ok else []
        if attachments and isinstance(attachments[0].get("id"), int | str):
            ctx.ids["attachment_incident_id"] = incident_id
            ctx.ids["attachment_id"] = str(attachments[0]["id"])
            found_keys = safe_keys(attachments[0])
            break
    return last, {
        "source": source,
        "limit": ATTACHMENT_SCAN_LIMIT,
        "incidents_looked_at": scanned,
        "stopped_at_first_attachment": bool(found_keys),
        "attachment_found": bool(found_keys),
        "attachment_metadata_keys": found_keys,
    }


def a_headers(_: Ctx, r: Result) -> Facts:
    return {
        "content_type": r.content_type,
        "declared_size": r.size_bucket,
        "has_content_disposition": r.has_content_disposition,
        "body_was_not_read": True,
    }


# ---------------------------------------------------------------------- plan
ORG = "/rest/orgs/{org_id}"
INC = ORG + "/incidents/{incident_id}"
ATT = ORG + "/incidents/{attachment_incident_id}/attachments/{attachment_id}"


def _cond(value: str) -> dict[str, str]:
    return {"field_name": "plan_status", "method": "equals", "value": value}


def _query(groups: list[list[dict[str, str]]]) -> dict[str, Any]:
    return {"filters": [{"conditions": g} for g in groups], "start": 0, "length": 1}


def build_plan(with_export: bool, key_id: str = "") -> list[Step]:
    s = Step
    plan = [
        s("const", "version", "GET", "/rest/const", analyse=a_const),
        s("session", "Q6", "GET", "/rest/session", analyse=a_permissions),
        s("org", "Q6", "GET", ORG, analyse=a_permissions),
        s("session_acl", "Q6", "GET", "/rest/session/{org_id}/acl", analyse=a_permissions),
        s("permissions", "Q6", "GET", ORG + "/permissions", analyse=a_permissions),
        s("apikeys", "Q6", "GET", ORG + "/apikeys", analyse=own_key_permissions(key_id),
          note="listing API keys is an administrator read; a denial is itself evidence"),
        # Q1 playbooks
        s("playbooks", "Q1", "GET", ORG + "/playbooks", analyse=a_collection,
          discover=remember("playbook_id")),
        s("playbooks_query_paged", "Q1", "POST", ORG + "/playbooks/query_paged",
          params=PAGED_PARAMS, json_body=SINGLE_ROW_QUERY, analyse=a_collection,
          discover=remember("playbook_id"),
          note="read-only query, one row, no criteria (owner-approved for P2-00)"),
        s("playbook", "Q1", "GET", ORG + "/playbooks/{playbook_id}", needs=("playbook_id",),
          analyse=a_playbook),
        s("playbooks_query_paged_via_get", "Q1", "GET", ORG + "/playbooks/query_paged",
          note="which verbs the route accepts: 405 + Allow is evidence the route exists"),
        # Q3 single-playbook export, GET candidates only
        s("playbook_schema", "Q1", "GET", ORG + "/playbooks/{playbook_id}/schema",
          needs=("playbook_id",)),
        s("playbook_inputs_schema", "Q1", "GET", ORG + "/playbooks/{playbook_id}/inputs/schema",
          needs=("playbook_id",)),
        s("playbook_manual_input_form", "Q1", "GET",
          ORG + "/playbooks/{playbook_id}/manual_input_form", needs=("playbook_id",)),
        s("playbook_utility_functions", "Q1", "GET", ORG + "/playbooks/utility_functions",
          analyse=a_collection),
        s("playbook_execution_statistics", "Q8", "GET", ORG + "/playbooks/execution/statistics"),
        # Q2 configuration export
        s("export_history", "Q2", "GET", ORG + "/configurations/exports/history",
          analyse=a_history_before, discover=remember("export_id")),
        # Q4 data tables
        s("types", "Q4", "GET", ORG + "/types", analyse=a_types, name_keyed=True),
        s("datatable_type", "Q4", "GET", ORG + "/types/{datatable_type}",
          needs=("datatable_type",)),
        s("datatable_fields", "Q4", "GET", ORG + "/types/{datatable_type}/fields",
          needs=("datatable_type",), analyse=a_collection),
        s("datatable_schema", "Q4", "GET", ORG + "/types/{datatable_type}/schema",
          needs=("datatable_type",)),
        # Q5 functions
        s("function_fields", "Q5", "GET", ORG + "/types/__function/fields",
          analyse=a_function_fields),
        s("functions", "Q5", "GET", ORG + "/functions", analyse=a_collection,
          discover=remember("function_id")),
        s("function", "Q5", "GET", ORG + "/functions/{function_id}", needs=("function_id",),
          analyse=a_function),
        # 05 §2 discovery collections
        s("actions", "05§2", "GET", ORG + "/actions", analyse=a_collection,
          discover=remember("action_id")),
        s("action", "05§2", "GET", ORG + "/actions/{action_id}", needs=("action_id",)),
        s("action_view", "05§2", "GET", ORG + "/actions/{action_id}/view",
          needs=("action_id",)),
        s("workflows", "05§2", "GET", ORG + "/workflows", analyse=a_collection,
          discover=remember("workflow_id", "workflow_id", "id")),
        s("workflow", "05§2", "GET", ORG + "/workflows/{workflow_id}", needs=("workflow_id",),
          analyse=a_workflow),
        s("scripts", "05§2", "GET", ORG + "/scripts", analyse=a_collection,
          discover=remember("script_id")),
        s("script", "05§2", "GET", ORG + "/scripts/{script_id}", needs=("script_id",)),
        s("message_destinations", "05§2", "GET", ORG + "/message_destinations",
          analyse=a_collection),
        s("incident_types", "05§2", "GET", ORG + "/incident_types", analyse=a_collection),
        s("phases", "05§2", "GET", ORG + "/phases", analyse=a_collection),
        s("groups", "05§2", "GET", ORG + "/groups", analyse=a_collection),
        s("users", "OQ11", "GET", ORG + "/users", analyse=a_collection),
        s("fields_incident", "05§2", "GET", ORG + "/types/incident/fields", analyse=a_collection),
        s("fields_task", "05§2", "GET", ORG + "/types/task/fields", analyse=a_collection),
        s("fields_artifact", "05§2", "GET", ORG + "/types/artifact/fields", analyse=a_collection),
        # incident-scoped reads need an id; only GET may be used to find one
        s("incidents_query_paged", "Q7/Q8", "POST", ORG + "/incidents/query_paged",
          params=PAGED_PARAMS, json_body=SINGLE_ROW_QUERY, analyse=a_collection,
          discover=remember("incident_id"),
          note="read-only query for ONE row; the id stays in memory and is never recorded"),
        s("incident", "OQ12", "GET", INC, needs=("incident_id",), analyse=a_incident),
        s("incident_handle_format_ids", "P1", "GET", INC, needs=("incident_id",),
          params={"handle_format": "ids"}, analyse=a_incident,
          note="same incident with handle_format=ids: do select values change type?"),
        s("incident_no_params", "P1", "GET", INC, needs=("incident_id",), bare_params=True,
          analyse=a_incident, note="no handle_format / text_content_output_format at all"),
        # Phase-1 query semantics, one row each; only counts are compared, in memory
        s("query_no_return_level", "P1", "POST", ORG + "/incidents/query_paged",
          json_body=SINGLE_ROW_QUERY, analyse=counted("plain"),
          note="is return_level required?"),
        s("query_active", "P1", "POST", ORG + "/incidents/query_paged", params=PAGED_PARAMS,
          json_body=_query([[_cond("A")]]), analyse=counted("active")),
        s("query_closed", "P1", "POST", ORG + "/incidents/query_paged", params=PAGED_PARAMS,
          json_body=_query([[_cond("C")]]), analyse=counted("closed")),
        s("query_and", "P1", "POST", ORG + "/incidents/query_paged", params=PAGED_PARAMS,
          json_body=_query([[_cond("A"), _cond("C")]]), analyse=counted("and"),
          note="two conditions in ONE filter"),
        s("query_or", "P1", "POST", ORG + "/incidents/query_paged", params=PAGED_PARAMS,
          json_body=_query([[_cond("A")], [_cond("C")]]), analyse=a_filter_semantics,
          note="one condition in each of TWO filters"),
        s("query_sorted", "OQ3", "POST", ORG + "/incidents/query_paged", params=PAGED_PARAMS,
          json_body={**SINGLE_ROW_QUERY, "sorts": [{"field_name": "create_date",
                                                   "type": "desc"}]},
          analyse=counted("sorted"), note="is create_date accepted as a sort field?"),
        s("tasks", "OQ1", "GET", INC + "/tasks", needs=("incident_id",), analyse=a_tasks,
          discover=remember("task_id")),
        s("task", "OQ1", "GET", ORG + "/tasks/{task_id}", needs=("task_id",)),
        s("comments", "OQ10", "GET", INC + "/comments", needs=("incident_id",),
          analyse=a_comments),
        s("artifacts", "05§1.2", "GET", INC + "/artifacts", needs=("incident_id",),
          analyse=a_collection, discover=remember("artifact_id")),
        s("artifact_history", "05§1.2", "GET", ORG + "/artifacts/{artifact_id}/history",
          needs=("artifact_id",), analyse=a_history),
        s("incident_actions", "P1", "GET", INC + "/actions", needs=("incident_id",),
          analyse=a_collection,
          note="Phase-1 assumes this lists the manual actions of an incident"),
        s("incident_action_invocations", "P1", "GET", INC + "/action_invocations",
          needs=("incident_id",), analyse=a_collection,
          note="read-only look at the route Phase-1 POSTs to; nothing is invoked"),
        s("table_data", "Q4", "GET", INC + "/table_data", needs=("incident_id",)),
        # Q8 history candidates
        s("history", "Q8", "GET", INC + "/history", needs=("incident_id",), analyse=a_history),
        s("newsfeed", "Q8", "GET", INC + "/newsfeed", needs=("incident_id",), analyse=a_history),
        s("workflow_instances", "Q8", "GET", INC + "/workflow_instances",
          needs=("incident_id",), analyse=a_history),
        s("task_attachments", "Q7", "GET", ORG + "/tasks/{task_id}/attachments",
          needs=("task_id",), analyse=a_collection, discover=remember("task_attachment_id")),
        s("task_attachment_contents", "Q7", "GET",
          ORG + "/tasks/{task_id}/attachments/{task_attachment_id}/contents",
          needs=("task_id", "task_attachment_id"), headers_only=True, analyse=a_headers),
        # Q7 attachments: metadata, then HEADERS ONLY of the content endpoint
        s("attachment_scan", "Q7", "GET", INC + "/attachments", custom=scan_for_attachment,
          note="at most 10 incidents, attachment metadata only, stops at the first hit"),
        s("attachment_metadata", "Q7", "GET", ATT, needs=("attachment_incident_id",
                                                         "attachment_id")),
        s("attachment_contents", "Q7", "GET", ATT + "/contents",
          needs=("attachment_incident_id", "attachment_id"), headers_only=True,
          analyse=a_headers, note="status and headers only; the body is never read"),
    ]  # fmt: skip
    if with_export:
        plan += [
            s("export", "Q2", "POST", ORG + "/configurations/exports", json_body=EXPORT_BODY,
              analyse=a_export, max_bytes=200_000_000,
              note="owner-approved for P2-00; read-only in effect"),
            s("export_history_after", "Q2", "GET", ORG + "/configurations/exports/history",
              analyse=a_history_after, discover=remember("export_id"),
              note="side-effect check: did the export add a history entry?"),
            s("export_by_id", "Q2", "GET", ORG + "/configurations/exports/{export_id}",
              needs=("export_id",), analyse=a_export, max_bytes=200_000_000),
        ]  # fmt: skip
    return plan


# -------------------------------------------------------------- on-box docs
DOC_INDEX_CANDIDATES = (
    "/docs/rest-api/index.html",
    "/docs/rest-api/",
    "/docs/rest-api/resources.html",
)
_TAG = re.compile(r"<[^>]+>")
_ENDPOINT = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/[A-Za-z0-9_{}/.\-]{2,160})")
_GENERIC_PATH = re.compile(r"^/[A-Za-z_{}/.\-]*$")  # no digits: nothing appliance-specific


def documented_endpoints(client: ReadOnlyClient, ctx: Ctx, ledger: list[Result]) -> None:
    index: Result | None = None
    for candidate in DOC_INDEX_CANDIDATES:
        r = client.request("GET", candidate, candidate, default_params=False)
        ledger.append(r)
        if r.ok and r.body:
            index = r
            break
    if index is None:
        return
    base = index.template.rsplit("/", 1)[0] + "/"
    text = index.body.decode("utf-8", "replace")
    pages = sorted(set(re.findall(r'href="(resource_[A-Za-z0-9_]+\.html)"', text)))
    wanted = [p for p in pages if any(k in p.lower() for k in DOC_KEYWORDS)][:120]
    for page in wanted:
        r = client.request(
            "GET", base + page, "/docs/rest-api/resource_*.html", default_params=False
        )
        if not r.ok:
            continue
        plain = html.unescape(_TAG.sub(" ", r.body.decode("utf-8", "replace")))
        pairs = {(m, p) for m, p in _ENDPOINT.findall(plain) if _GENERIC_PATH.match(p)}
        if pairs:
            ctx.documented[page.removeprefix("resource_").removesuffix(".html")] = sorted(pairs)


# -------------------------------------------------------------------- runner
def choose_tls(
    env: ProbeEnv, mode: str
) -> tuple[ssl.SSLContext | bool, str | None, str, TlsReport]:
    if env.scheme != "https":
        raise SystemExit("SOAR_BASE_URL must be https for the probe")
    bundle = env.ca_bundle or (
        env.verify_ssl if env.verify_ssl.lower() not in ("true", "false", "") else ""
    )
    report = inspect(env.host, env.port, ca_bundle=bundle, timeout=env.timeout)
    if not report.reachable:
        raise SystemExit(f"appliance not reachable: {report.connect_error}")
    if mode in ("auto", "system") and report.verifies_with_certifi:
        return True, None, "system (certifi, the package default)", report
    if mode in ("auto", "system") and report.verifies_with_os_store:
        return ssl.create_default_context(), None, "system (operating-system store)", report
    if mode in ("auto", "ca-bundle") and report.verifies_with_ca_bundle:
        return ssl.create_default_context(cafile=bundle), None, "ca-bundle", report
    if mode in ("auto", "san-hostname") and report.verifies_with_san_hostname:
        ctx = (
            ssl.create_default_context(cafile=bundle)
            if report.san_trust == "bundle"
            else (ssl.create_default_context() if report.san_trust == "os" else True)
        )
        return ctx, report.san_hostname, "san-hostname", report
    if mode == "lab-pinned":
        return pinned_context(report.leaf_pem), None, "lab-pinned", report
    raise SystemExit(
        "no TLS mode verifies. Findings:\n  "
        + "\n  ".join(report.lines())
        + "\nRe-run with --tls-mode lab-pinned to opt in to the LAB-ONLY pinned mode."
    )


def run(
    env: ProbeEnv,
    client: ReadOnlyClient,
    out_dir: Path,
    *,
    with_export: bool,
    with_docs: bool = True,
    only: frozenset[str] | None = None,
    echo: Callable[[str], None] = print,
) -> list[dict[str, Any]]:
    literals = env.literals()
    ctx = Ctx(ids={"org_id": env.org_id})
    if env.incident_id:
        ctx.ids["incident_id"] = env.incident_id
    ledger: list[Result] = []
    step_rows: dict[str, dict[str, Any]] = {}
    written: list[str] = []

    def say(line: str) -> None:
        echo(safe_text(line, literals))

    if with_docs:
        documented_endpoints(client, ctx, ledger)
        say(f"on-box API docs: {len(ctx.documented)} resource page(s) parsed")

    for step in build_plan(with_export, env.key_id):
        if only is not None and step.key not in only:
            continue
        if any(n not in ctx.ids for n in step.needs):
            missing = ", ".join(n for n in step.needs if n not in ctx.ids)
            say(f"{step.question:8} {step.method:4} {step.template}  -> skipped (no {missing})")
            skipped = Result(step.method, step.template, (), error=f"skipped: no {missing}")
            step_rows[step.key] = {"step": step.key, "question": step.question}
            step_rows[step.key].update(skipped.ledger_row())
            continue
        if step.custom is not None:
            try:
                found, custom_facts = step.custom(env, client, ctx)
            except ProbePolicyError as exc:
                say(f"{step.question:8} REFUSED BY POLICY: {exc}")
                continue
            r = found or Result(step.method, step.template, (), error="nothing to look at")
            r.json = None  # facts only: no row of any incident is shaped or stored
            step_rows[step.key] = {"step": step.key, "question": step.question}
            step_rows[step.key].update(r.ledger_row())
            document = {
                "_fixture": "verified-shape",
                "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
                "_question": step.question,
                "_request": {
                    "method": r.method,
                    "path": r.template,
                    "query_keys": list(r.query_keys),
                },
                "_status": r.status,
                "_note": step.note,
                "_facts": custom_facts,
                "shape": None,
            }
            try:
                dump_verified(out_dir / f"{step.key}.json", document, literals)
                written.append(step.key)
            except UnsafeArtefactError as exc:
                say(f"{step.key} NOT WRITTEN: {exc}")
            say(
                f"{step.question:8} {r.method:4} {r.template}  -> {r.status or r.error} "
                f"looked_at={custom_facts.get('incidents_looked_at')} "
                f"found={custom_facts.get('attachment_found')}"
            )
            continue
        path = step.template.format(**ctx.ids)
        try:
            r = client.request(
                step.method,
                path,
                step.template,
                params=step.params,
                json_body=step.json_body,
                headers_only=step.headers_only,
                max_bytes=step.max_bytes,
                default_params=not step.bare_params,
            )
        except ProbePolicyError as exc:
            say(f"{step.question:8} REFUSED BY POLICY: {exc}")
            continue
        step_rows[step.key] = {"step": step.key, "question": step.question, **r.ledger_row()}
        if r.ok and step.discover and r.json is not None:
            step.discover(ctx, r.json)
        facts = step.analyse(ctx, r) if (step.analyse and (r.ok or step.headers_only)) else {}
        if not r.ok and r.json is not None:
            facts = {**facts, "server_error": error_facts(r, literals)}
        enums = EnumCollector()
        shape = (
            shape_of(r.json, enums=enums, name_keyed=step.name_keyed)
            if r.json is not None
            else None
        )
        document = {
            "_fixture": "verified-shape",
            "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
            "_question": step.question,
            "_request": {"method": r.method, "path": r.template, "query_keys": list(r.query_keys)},
            "_status": r.status,
            "_content_type": r.content_type,
            "_allow": r.allow,
            "_size": r.size_bucket,
            "_truncated": r.truncated,
            "_error": r.error,
            "_note": step.note,
            "_facts": facts,
            "_enums": enums.to_json(),
            "shape": shape,
        }
        try:
            dump_verified(out_dir / f"{step.key}.json", document, literals)
            written.append(step.key)
            verdict = ""
        except UnsafeArtefactError as exc:
            verdict = f"  [NOT WRITTEN: {exc}]"
        top = safe_keys(r.json)[:12] if isinstance(r.json, Mapping) else ""
        say(
            f"{step.question:8} {r.method:4} {r.template}  -> {r.status or r.error} "
            f"{r.content_type or ''} {r.size_bucket} {top}{verdict}"
        )

    # Merge with an earlier run so that a partial (--only) run adds to the record.
    previous: dict[str, Any] = {}
    ledger_path = out_dir / "_ledger.json"
    if ledger_path.is_file():
        previous = json.loads(ledger_path.read_text(encoding="utf-8"))
    merged = {row["step"]: row for row in previous.get("requests", []) if "step" in row}
    merged.update(step_rows)
    rows = list(merged.values())
    documented = {k: [list(p) for p in v] for k, v in sorted(ctx.documented.items())}
    summary = {
        "_fixture": "verified-ledger",
        "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
        "requests": rows,
        "documentation_requests": [r.ledger_row() for r in ledger]
        or previous.get("documentation_requests", []),
        "refused_by_policy": client.refused,
        "documented_endpoints": documented or previous.get("documented_endpoints", {}),
    }
    try:
        dump_verified(out_dir / "_ledger.json", summary, literals)
    except UnsafeArtefactError as exc:
        say(f"ledger NOT WRITTEN: {exc}")
    say(
        f"{client.requests_sent} request(s) sent; {len(written)} fixture(s) written to "
        f"{out_dir.relative_to(ROOT).as_posix()}; refused by policy: {len(client.refused)}"
    )
    return rows


def smoke(env: ProbeEnv, client: ReadOnlyClient, echo: Callable[[str], None] = print) -> int:
    """ONE harmless authenticated read; a second only if the first is an expected denial.

    Emits status and shape metadata, nothing else, and writes no file.
    """
    literals = env.literals()

    def report(r: Result, what: str) -> None:
        keys = safe_keys(r.json) if isinstance(r.json, Mapping) else []
        rows = rows_of(r.json)
        line = (
            f"{what}: {r.method} {r.template} -> status={r.status} error={r.error} "
            f"content_type={r.content_type} size={r.size_bucket} top_level_keys={keys} "
            f"rows={bucket(len(rows))} row_key_count={len(safe_keys(rows[0])) if rows else 0}"
        )
        echo(safe_text(line, literals))

    first = client.request("GET", "/rest/session", "/rest/session")
    report(first, "smoke 1/1")
    if first.status in (401, 403):
        echo("the session endpoint denied this API key (expected for API keys); one query follows")
        path = ORG.format(org_id=env.org_id) + "/incidents/query_paged"
        second = client.request(
            "POST", path, ORG + "/incidents/query_paged",
            params=PAGED_PARAMS, json_body=SINGLE_ROW_QUERY,
        )  # fmt: skip
        report(second, "smoke 2/2")
    echo(
        f"requests sent: {client.requests_sent}; refused by policy: {len(client.refused)}; files: 0"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--with-export",
        action="store_true",
        help="also issue the one approved POST /configurations/exports",
    )
    parser.add_argument("--no-docs", action="store_true", help="skip the on-box API documentation")
    parser.add_argument(
        "--only",
        default="",
        metavar="STEP[,STEP]",
        help="run only these plan steps (include their prerequisites yourself)",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="one authenticated read, status/shape only, writes nothing",
    )
    parser.add_argument(
        "--tls-mode",
        default=None,
        choices=["auto", "system", "ca-bundle", "san-hostname", "lab-pinned"],
    )
    args = parser.parse_args(argv)
    try:
        env = load_env()
    except ProbeEnvError as exc:
        print(f"cannot run: {exc} (values come from the environment or a git-ignored .env)")
        return 2
    try:
        context, sni, mode, report = choose_tls(env, args.tls_mode or env.tls_mode)
        print(f"TLS mode: {mode}")
        if mode == "lab-pinned":
            print(LAB_WARNING)
        client = ReadOnlyClient(env, context, sni_hostname=sni)
        try:
            if args.smoke:
                return smoke(env, client)
            only = frozenset(k for k in args.only.split(",") if k) or None
            run(
                env,
                client,
                OUT_DIR,
                with_export=args.with_export,
                with_docs=not args.no_docs,
                only=only,
            )
        finally:
            client.close()
        dump_verified(
            OUT_DIR / "_tls.json",
            {
                "_fixture": "verified-tls",
                "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
                "mode_used": mode,
                "findings": dict(line.split(": ", 1) for line in report.lines()),
            },
            env.literals(),
        )
    except (httpx.HTTPError, OSError) as exc:  # never let a message with a URL escape
        print(f"probe aborted: {type(exc).__name__}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
