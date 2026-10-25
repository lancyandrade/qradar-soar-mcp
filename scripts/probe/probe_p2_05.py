"""P2-05 research addendum: what is a playbook, and how does it refer to a function?

    uv run python scripts/probe/guarded.py probe_p2_05.py --playbook
    uv run python scripts/probe/guarded.py probe_p2_05.py --diagnose   # after a 403, see D

Owner-approved, read-only, one run, and nothing else can be sent from this file
(``--diagnose`` is the separately approved refusal diagnostic, documented at ``diagnose``):

* R1: ``GET /rest/orgs/{org_id}/playbooks/{playbook_id}`` with the two parameters P2-00
  verified it with, **once**, for the one disposable playbook the owner built for this
  research and designated with ``P2_PROBE_PLAYBOOK_ID`` (in memory, never written or
  printed). There is no listing and no fallback: without a designated id nothing is sent.
  The answer is analysed only when it *is* the research playbook: its ``name`` or
  ``display_name`` equals the agreed research name exactly. Any other playbook stops the
  run and nothing about the answer is written, so no unrelated playbook content can be
  recorded. Kept: key names, JSON types and allow-listed enum tokens of the object; of the
  activation conditions, their count, key names, operator tokens and the *form* of each
  compared value (null, string, integer, list...), never the value or the field name.
* R2, offline: the playbook's ``content.xml`` through the P2-04 analyser
  (:func:`probe_p2_04.analyse_xml`): DTD and entity refusals before parsing, bounded size,
  structure only (namespace classes, element and attribute names, edges by attribute name,
  embedded JSON as key names and types, function-candidate keys and value forms).
* R3: ``GET /rest/orgs/{org_id}/functions``, the call the catalog already makes, **once**,
  and only when R2 parsed the document. Then, in memory: where in the XML a value occurs
  that equals, exactly as written, the ``uuid``, ``name`` or ``display_name`` of a
  function in that list (and, at a function-like location only, its integer ``id``).
  Kept: the *location* (element class and local name, attribute name or JSON key path,
  with administrator-chosen keys collapsed to ``<name>``), which function property it
  matched, count buckets, and whether a value matched more than one function. Never the
  value, the function, or its name.

Every request goes through ``safe_http.ReadOnlyClient``, which refuses every other method.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator, Mapping
from typing import Any
from xml.etree import ElementTree as ET  # only after analyse_xml's refusals have passed

import httpx
import probe_p2_04 as wf
from probe import EXPECTED_VERSION, ORG, OUT_DIR, Facts, bucket
from probe_00b import Recorder, verified_context
from probe_env import ProbeEnvError, load_env
from safe_http import ReadOnlyClient, Result
from sanitise import (
    ENUM_TOKEN,
    EnumCollector,
    UnsafeArtefactError,
    _generic_violations,
    dump_verified,
    safe_keys,
    shape_of,
)

TICKET = "P2-05"
PREFIX = "p2_05_"
LEDGER = "_ledger_p2_05.json"
EXIT_STOP = 5
PLAYBOOKS = "/playbooks"
FUNCTIONS = "/functions"
# The agreed identity of the disposable research playbook. Both are synthetic and are the
# only playbook content this probe ever compares against.
RESEARCH_NAME = "mcp_research_p2_05_disposable"
RESEARCH_DISPLAY_NAME = "MCP research P2-05 disposable"
FUNCTION_WRAPPER = "entities"  # verified by P2-00 (tests/fixtures/soar/verified/functions.json)
MAX_TEXT_MATCH = 300  # element text longer than this is never compared
MAX_LOCATIONS = 60


# ------------------------------------------------------------------ recording
def write(
    rec: Recorder, key: str, question: str, r: Result | None, facts: Facts, *,
    note: str, shape_source: Any = None,
) -> None:  # fmt: skip
    enums = EnumCollector()
    shape = shape_of(shape_source, enums=enums) if shape_source is not None else None
    kept = enums.to_json()
    if "object_type" in kept:
        kept["object_type"] = [v for v in kept["object_type"] if str(v) in wf.BUILTIN_OBJECT_TYPES]
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
        "refused_by_policy": rec.client.refused,
    }
    try:
        dump_verified(path, summary, rec.literals)
    except UnsafeArtefactError as exc:
        rec.say(f"ledger NOT WRITTEN: {exc}")
    rec.say(f"{rec.client.requests_sent} request(s) sent; {len(rec.written)} fixture(s) written")


# ------------------------------------------------------------ R1: the object
def designated_id(raw: str) -> int | None:
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def object_problem(r: Result, wanted: int) -> str | None:
    """Why this answer is not the research playbook, or None. Never quotes a value."""
    if r.status != 200:
        return f"status {r.status or r.error}"
    if not isinstance(r.json, Mapping):
        return "the answer is not a JSON object"
    if r.json.get("id") != wanted or isinstance(r.json.get("id"), bool):
        return "the object's id is not the designated id"
    if r.json.get("name") != RESEARCH_NAME and r.json.get("display_name") != RESEARCH_DISPLAY_NAME:
        return "the object is not the agreed research playbook (name and display name differ)"
    return None


def _token(value: object) -> str | None:
    if isinstance(value, str) and ENUM_TOKEN.match(value) and not _generic_violations(value):
        return value
    return None


def activation_facts(obj: Mapping[str, Any]) -> Facts:
    """Shape of the activation conditions: counts, key names, operator tokens and the form of
    each compared value. Never a value, never a field name."""
    details = obj.get("activation_details")
    if not isinstance(details, Mapping):
        return {"activation_details_present": False}
    ac = details.get("activation_conditions")
    facts: Facts = {
        "activation_details_present": True,
        "activation_details_keys": safe_keys(details),
        "activation_conditions_is_object": isinstance(ac, Mapping),
    }
    if not isinstance(ac, Mapping):
        return facts
    conditions = ac.get("conditions")
    rows = [c for c in conditions if isinstance(c, Mapping)] if isinstance(conditions, list) else []
    object_type = obj.get("object_type") if isinstance(obj.get("object_type"), str) else ""
    facts.update(
        {
            "activation_conditions_keys": safe_keys(ac),
            "logic_type": _token(ac.get("logic_type")),
            "conditions_is_list": isinstance(conditions, list),
            "conditions": bucket(len(rows)),
            "condition_keys": sorted({k for c in rows for k in safe_keys(c)}),
            "methods": sorted({t for c in rows if (t := _token(c.get("method")))}),
            "value_forms": sorted({wf._form_of(c.get("value")) for c in rows}),
            "type_forms": sorted({wf._form_of(c.get("type")) for c in rows}),
            "evaluation_id_forms": sorted({wf._form_of(c.get("evaluation_id")) for c in rows}),
            # The field name's form only: does it carry the object type as a dotted prefix?
            "field_name_forms": sorted(
                {
                    "object_type_dotted"
                    if object_type
                    and isinstance(c.get("field_name"), str)
                    and c["field_name"].startswith(object_type + ".")
                    else wf._form_of(c.get("field_name"))
                    for c in rows
                }
            ),
        }
    )
    return facts


# ------------------------------------------------- R3: where functions are referenced
def function_index(
    rows: list[Mapping[str, Any]],
) -> tuple[dict[str, list[tuple[str, int]]], dict[int, int]]:
    """``value -> [(property, row index)]`` for uuid, name and display_name; ``id -> row``."""
    by_value: dict[str, list[tuple[str, int]]] = {}
    by_id: dict[int, int] = {}
    for i, row in enumerate(rows):
        for prop in ("uuid", "name", "display_name"):
            value = row.get(prop)
            if isinstance(value, str) and value:
                by_value.setdefault(value, []).append((prop, i))
        fid = row.get("id")
        if isinstance(fid, int) and not isinstance(fid, bool):
            by_id[fid] = i
    return by_value, by_id


def _key_label(key: str, collapse: set[str], parent: str | None) -> str:
    if key in collapse or parent in wf.NAME_KEYED_JSON_CONTAINERS:
        return "<name>"
    return wf._safe_name(key)


def _json_scalars(
    value: Any, path: str, collapse: set[str], parent: str | None = None, depth: int = 0
) -> Iterator[tuple[str, str | None, Any]]:
    """``(path, raw key, scalar)`` for every scalar of an embedded payload, in memory."""
    if depth > wf.MAX_JSON_DEPTH:
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            name = str(k)
            here = f"{path}.{_key_label(name, collapse, parent)}"
            if isinstance(v, Mapping | list):
                yield from _json_scalars(v, here, collapse, name, depth + 1)
            else:
                yield here, name, v
    elif isinstance(value, list):
        for v in value[:200]:
            if isinstance(v, Mapping | list):
                yield from _json_scalars(v, path + "[]", collapse, parent, depth + 1)
            else:
                yield path + "[]", parent, v


def reference_facts(text: str, functions: list[Mapping[str, Any]]) -> Facts:
    """Where values equal to a listed function's uuid, name or display name occur in the
    XML, by location; never which function or what value. Call only after
    ``analyse_xml(text)`` parsed it: its refusals are what make this parse safe."""
    by_value, by_id = function_index(functions)
    collapse = set(by_value)
    parser = ET.XMLPullParser(events=("start",))
    parser.feed(text)
    elements = [e for _, e in parser.read_events()]
    parser.close()
    payload_strings: set[str] = set()
    matches: dict[str, dict[str, Any]] = {}
    unmatched_function_like: dict[str, int] = {}

    def hit(location: str, value: Any, function_like: bool) -> None:
        found: list[tuple[str, int]] = []
        if isinstance(value, str):
            found = list(by_value.get(value, []))
            if function_like and value.isdigit() and int(value) in by_id:
                found.append(("id", by_id[int(value)]))
        elif isinstance(value, int) and not isinstance(value, bool) and function_like:
            if value in by_id:
                found.append(("id", by_id[value]))
        if not found:
            if function_like and isinstance(value, str | int) and not isinstance(value, bool):
                unmatched_function_like[location] = unmatched_function_like.get(location, 0) + 1
            return
        entry = matches.setdefault(
            location,
            {"properties": set(), "occurrences": 0, "functions": set(), "ambiguous": False},
        )
        entry["occurrences"] += 1
        entry["properties"].update(p for p, _ in found)
        rows = {i for _, i in found}
        entry["functions"].update(rows)
        if len(rows) > 1:
            entry["ambiguous"] = True

    for element in elements:
        cls, local = wf._split(element.tag)
        label = f"{cls}:{wf._safe_name(local)}"
        element_function_like = "function" in local.lower()
        for raw, value in element.attrib.items():
            attr = wf._split(raw)[1]
            function_like = element_function_like or "function" in attr.lower()
            hit(f"{label}@{wf._safe_name(attr)}", value, function_like)
        body = (element.text or "").strip()
        if not body:
            continue
        if (
            cls not in wf.STANDARD_CLASSES
            and body[:1] in ("{", "[")
            and len(body) <= wf.MAX_JSON_CHARS
        ):
            try:
                payload = json.loads(body)
            except ValueError:
                continue
            wf._identity_values(payload, payload_strings)
            for path, key, value in _json_scalars(payload, label, collapse | payload_strings):
                # By the payload's own key path, not the element that carries it: a script
                # or an input under a function element is not itself a reference.
                function_like = "function" in path[len(label) :].lower() or (
                    key is not None and "function" in key.lower()
                )
                hit(path, value, function_like)
        elif len(body) <= MAX_TEXT_MATCH:
            hit(f"{label}#text", body, element_function_like)

    # The question P2-05 needs answered, stated directly: does each vendor function element's
    # ``uuid`` attribute equal, exactly as written, the ``uuid`` of exactly one listed function?
    uuid_owners: dict[str, int] = {}
    for row in functions:
        u = row.get("uuid")
        if isinstance(u, str) and u:
            uuid_owners[u] = uuid_owners.get(u, 0) + 1
    outcomes: dict[str, int] = {}
    uuid_forms: set[str] = set()
    for element in elements:
        cls, local = wf._split(element.tag)
        if cls in wf.STANDARD_CLASSES or local != "function":
            continue
        value = next((v for k, v in element.attrib.items() if wf._split(k)[1] == "uuid"), None)
        uuid_forms.add(wf._form_of(value))
        owners = uuid_owners.get(value, 0) if isinstance(value, str) else 0
        outcome = (
            "no_uuid" if value is None
            else "matched_exactly_one" if owners == 1
            else "ambiguous" if owners > 1
            else "no_match"
        )  # fmt: skip
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    calls = sum(outcomes.values())
    verdict = (
        "unverified: no vendor function element"
        if calls == 0
        else "succeeded"
        if outcomes.get("matched_exactly_one", 0) == calls
        else "failed"
    )
    referenced = set().union(*(m["functions"] for m in matches.values())) if matches else set()
    locations = {
        loc: {
            "matched_properties": sorted(m["properties"]),
            "occurrences": bucket(m["occurrences"]),
            "distinct_functions": bucket(len(m["functions"])),
            "a_value_matched_more_than_one_function": m["ambiguous"],
        }
        for loc, m in sorted(matches.items())[:MAX_LOCATIONS]
    }
    return {
        "uuid_attribute_match": verdict,
        "uuid_attribute_outcomes": {k: bucket(n) for k, n in sorted(outcomes.items())},
        "uuid_attribute_value_forms": sorted(uuid_forms),
        "functions_listed": bucket(len(functions)),
        "function_row_keys": sorted({k for row in functions for k in safe_keys(row)}),
        "locations_holding_a_function_identity": locations,
        "distinct_functions_referenced": bucket(len(referenced)),
        "function_like_values_matching_no_function": {
            loc: bucket(n) for loc, n in sorted(unmatched_function_like.items())[:MAX_LOCATIONS]
        },
    }


# --------------------------------------------------------------------- the run
def playbook(rec: Recorder) -> int:
    wanted = designated_id(rec.env.playbook_id)
    if wanted is None:
        rec.say("STOPPED: P2_PROBE_PLAYBOOK_ID is not set to a positive integer; nothing sent")
        return EXIT_STOP
    path = rec.org + f"{PLAYBOOKS}/{wanted}"
    r = rec.send("playbook", "P2-05", "GET", path, ORG + PLAYBOOKS + "/{playbook_id}")
    problem = object_problem(r, wanted)
    if problem is not None:
        rec.say(f"STOPPED: {problem}; nothing written about the answer, nothing more sent")
        return EXIT_STOP
    obj: Mapping[str, Any] = r.json
    status = _token(obj.get("status"))
    if status == "enabled":
        rec.say("WARNING: the research playbook reports status 'enabled'; it should be inactive")
    content = obj.get("content") if isinstance(obj.get("content"), Mapping) else {}
    name, is_string, size = wf.xml_property(content)
    facts: Facts = {
        "object_keys": safe_keys(obj),
        "research_identity": "name" if obj.get("name") == RESEARCH_NAME else "display_name",
        "content_keys": safe_keys(content),
        "xml_bearing_property": name,
        "xml_is_string": is_string,
        "xml_size": size,
        **activation_facts(obj),
    }
    write(
        rec, "playbook", "P2-05", r, facts,
        note="observed, read-only: the owner's disposable research playbook; key names, "
        "types and allow-listed tokens; activation conditions as counts, keys, operators "
        "and value forms only",
        shape_source=obj,
    )  # fmt: skip
    rec.say("P2-05  playbook: " + json.dumps(facts, sort_keys=True))
    if name is None:
        rec.say("R2 NOT RUN: no XML-bearing string property under content")
        return 0
    text = content[name]
    analysis = wf.analyse_xml(text)
    if not analysis.get("parsed"):
        write(
            rec, "playbook_xml", "P2-05", r, analysis,
            note="observed, offline: the playbook XML was refused before or while parsing",
        )  # fmt: skip
        rec.say("P2-05  playbook xml: " + json.dumps(analysis, sort_keys=True))
        rec.say("R3 NOT RUN: the XML was not parsed")
        return 0
    f = rec.send("functions", "P2-05", "GET", rec.org + FUNCTIONS, ORG + FUNCTIONS)
    rows = f.json.get(FUNCTION_WRAPPER) if f.status == 200 and isinstance(f.json, Mapping) else None
    if not isinstance(rows, list) or not all(isinstance(x, Mapping) for x in rows):
        refs: Facts = {"function_matching": f"not run: functions answered {f.status or f.error}"}
    else:
        refs = {"function_matching": "run", **reference_facts(text, rows)}
    write(
        rec, "playbook_xml", "P2-05", r, {**analysis, **refs},
        note="observed, offline: structural facts of the research playbook's XML, and the "
        "locations where a listed function's uuid, name or display name occurs; no text, "
        "value, name, id or uuid was kept and the XML was never written",
    )  # fmt: skip
    rec.say("P2-05  playbook xml: " + json.dumps({**analysis, **refs}, sort_keys=True))
    return 0


# ------------------------------------------------------- D: why was it refused?
# Owner-approved diagnostic after two 403 answers to R1. Exactly two requests, in this order:
# the paged query with the one criteria-only body below (can this key see playbooks at all?),
# then R1's GET (is it this playbook?). Of each answer only fixed facts are kept: the status,
# for a refusal the key names of its body and three booleans about what its text mentions,
# for a query that succeeds count buckets. No text, value, id or name is kept; a GET that
# now succeeds is not analysed (that is the ordinary --playbook run, approved separately).
DIAGNOSTIC_QUERY_BODY = {"filters": [], "start": 0, "length": 1}
_MENTIONS = {
    "mentions_permission": re.compile(
        r"permission|forbidden|not authori[sz]ed|access|denied", re.I
    ),
    "mentions_not_found": re.compile(r"not found|unable to find|does not exist|no such", re.I),
    "mentions_draft": re.compile(r"draft", re.I),
}


def _strings(value: Any, depth: int = 0) -> Iterator[str]:
    if depth > 3:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _strings(v, depth + 1)
    elif isinstance(value, list):
        for v in value[:20]:
            yield from _strings(v, depth + 1)


def refusal_facts(r: Result) -> Facts:
    """Fixed facts about an answer that is not a 2xx: never its text."""
    body = r.json
    text = " ".join(_strings(body))[:20_000] if body is not None else ""
    return {
        "status": r.status,
        "error": r.error,
        "content_type": r.content_type,
        "body_is_json_object": isinstance(body, Mapping),
        "body_keys": safe_keys(body) if isinstance(body, Mapping) else [],
        **{name: bool(rx.search(text)) for name, rx in _MENTIONS.items()},
    }


def diagnose(rec: Recorder) -> int:
    wanted = designated_id(rec.env.playbook_id)
    if wanted is None:
        rec.say("STOPPED: P2_PROBE_PLAYBOOK_ID is not set to a positive integer; nothing sent")
        return EXIT_STOP
    q = rec.send(
        "diagnose_query", "P2-05D", "POST", rec.org + PLAYBOOKS + "/query_paged",
        ORG + PLAYBOOKS + "/query_paged", params={"return_level": "normal"},
        json_body=DIAGNOSTIC_QUERY_BODY,
    )  # fmt: skip
    if q.ok and isinstance(q.json, Mapping):
        rows = q.json.get("data")
        total = q.json.get("recordsTotal")
        query: Facts = {
            "status": q.status,
            "wrapper_keys": safe_keys(q.json),
            "rows_returned": bucket(len(rows)) if isinstance(rows, list) else None,
            "records_total": bucket(total)
            if isinstance(total, int) and not isinstance(total, bool)
            else None,
        }
    else:
        query = refusal_facts(q)
    g = rec.send("diagnose_playbook", "P2-05D", "GET", rec.org + f"{PLAYBOOKS}/{wanted}",
                 ORG + PLAYBOOKS + "/{playbook_id}")  # fmt: skip
    detail: Facts = (
        {"status": g.status, "analysed": False, "note": "readable now; run --playbook"}
        if g.ok
        else refusal_facts(g)
    )
    facts = {"query_paged_length_1": query, "designated_playbook_get": detail}
    write(
        rec, "diagnose", "P2-05D", None, facts,
        note="owner-approved diagnostic of the 403 to GET /playbooks/{playbook_id}: status, "
        "body key names and fixed booleans about what a refusal mentions; no text kept",
    )  # fmt: skip
    rec.say("P2-05D diagnose: " + json.dumps(facts, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    step = parser.add_mutually_exclusive_group(required=True)
    step.add_argument("--playbook", action="store_true", help="R1-R3, once")
    step.add_argument("--diagnose", action="store_true", help="D: the query, then R1's GET")
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
        code = diagnose(rec) if args.diagnose else playbook(rec)
        finish(rec)
        return code
    except (httpx.HTTPError, OSError) as exc:  # never let a message with a URL escape
        print(f"probe aborted: {type(exc).__name__}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
