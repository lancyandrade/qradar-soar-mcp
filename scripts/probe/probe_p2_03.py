"""P2-03 research addendum: what is the ``required`` property of a field definition?

    uv run python scripts/probe/guarded.py probe_p2_03.py --swagger
    uv run python scripts/probe/guarded.py probe_p2_03.py --fields

Four owner-approved GETs, and nothing else can be sent from this file:

* ``--swagger``: ``GET /docs/rest-api/ui/swagger.json``, the description published next
  to the on-box reference (static IBM documentation, not appliance data). Kept: for every
  data type whose ``required`` property is not a plain boolean, the property's type, its
  enum tokens and whether its description mentions closing. The description itself is
  printed for a human to paraphrase and is never stored. This is *documented* evidence.
* ``--fields``: ``GET types/{incident,task,artifact}/fields`` with the parameters P2-00
  verified them with. Kept: the distinct ``required`` tokens per object type and counts as
  buckets. No field name, label or other value is kept. This is *observed* evidence: the
  tokens in use on this appliance, not every token SOAR knows.

Neither says what SOAR does when an incident is closed. That needs a write, and no write
can be sent from here: every request goes through ``safe_http.ReadOnlyClient``.

A field list that does not look like the one P2-00 recorded (status, container, key set)
stops the run before anything is written or another request is sent.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from typing import Any

import httpx
from probe import EXPECTED_VERSION, ORG, OUT_DIR, Facts, bucket
from probe_00b import _IDENT, _TOKEN, DOC_BASE, SWAGGER, Recorder, _ref, verified_context
from probe_env import ProbeEnvError, load_env
from safe_http import ReadOnlyClient, Result
from sanitise import (
    ENUM_TOKEN,
    UnsafeArtefactError,
    _generic_violations,
    dump_verified,
    safe_keys,
)

TICKET = "P2-03"
PREFIX = "p2_03_"
LEDGER = "_ledger_p2_03.json"
FIELD_TYPES = ("incident", "task", "artifact")  # a closed list: nothing else is read
PROPERTIES_PREFIX = "properties"
MAX_TOKENS = 12  # as sanitise.MAX_ENUM_VALUES: more distinct values is not an enum
EXIT_STOP = 5
CLOSE_WORDS = ("close", "closing", "closed")


def safe_token(value: object) -> str | None:
    """A value that is one schema token and nothing else, by the rule every recorded enum
    passes (``sanitise.EnumCollector``)."""
    if isinstance(value, str) and ENUM_TOKEN.match(value) and not _generic_violations(value):
        return value
    return None


# ------------------------------------------------------------------ documented
def _enum_of(node: Mapping[str, Any]) -> list[str]:
    values = node.get("enum") if isinstance(node.get("enum"), list) else []
    return sorted({t for t in map(safe_token, values) if t is not None})[:MAX_TOKENS]


def _said(node: Mapping[str, Any]) -> str:
    text = node.get("description")
    return " ".join(text.split())[:420] if isinstance(text, str) else ""


def required_property_facts(definitions: Mapping[str, Any]) -> tuple[Facts, dict[str, str]]:
    """(what is kept, {data type: description to print}) for every data type whose
    ``required`` property is something other than a plain boolean."""
    kept: Facts = {}
    prose: dict[str, str] = {}
    booleans = 0
    for name, node in definitions.items():
        props = node.get("properties") if isinstance(node, Mapping) else None
        prop = props.get("required") if isinstance(props, Mapping) else None
        if not isinstance(prop, Mapping) or not _IDENT.match(str(name)):
            continue
        kind = prop.get("type")
        target = _ref(prop)
        if kind == "boolean" and target is None and "enum" not in prop:
            booleans += 1
            continue
        referred = definitions.get(target) if target else None
        referred = referred if isinstance(referred, Mapping) else {}
        said = " ".join(filter(None, (_said(prop), _said(referred))))
        kept[str(name)] = {
            "type": kind if isinstance(kind, str) and _TOKEN.match(kind) else None,
            "ref": target,
            "enum": _enum_of(prop),
            "ref_type": referred.get("type") if isinstance(referred.get("type"), str) else None,
            "ref_enum": _enum_of(referred),
            "read_only": prop.get("readOnly") is True,
            "description_present": bool(said),
            "description_mentions_closing": any(w in said.lower() for w in CLOSE_WORDS),
        }
        prose[str(name)] = said
    return {"data_types": kept, "data_types_with_a_boolean_required": bucket(booleans)}, prose


def swagger_required(rec: Recorder) -> int:
    r = rec.send(
        f"doc:{SWAGGER}", "docs", "GET", DOC_BASE + SWAGGER, DOC_BASE + SWAGGER,
        default_params=False, max_bytes=60_000_000,
    )  # fmt: skip
    spec = r.json if isinstance(r.json, Mapping) else {}
    definitions = spec.get("definitions") if isinstance(spec.get("definitions"), Mapping) else {}
    if r.status != 200 or not definitions:
        rec.say(f"STOPPED: {SWAGGER} -> {r.status or r.error}, no data types; nothing written")
        return EXIT_STOP
    facts, prose = required_property_facts(definitions)
    version = spec.get("swagger") or spec.get("openapi")
    facts["spec_version"] = safe_token(f"v{version}") and str(version)
    facts["data_type_count"] = bucket(len(definitions))
    write(
        rec, "doc_swagger_required", "docs", r, facts, enums={},
        note="documented, not live: schema facts of the `required` property from the "
        "description published next to the reference; descriptions are paraphrased in "
        "docs/soar-api-verified.md, never stored",
    )  # fmt: skip
    rec.say("swagger: " + json.dumps(facts, sort_keys=True))
    for name, said in sorted(prose.items()):
        rec.say(f"  {name}.required: {said or '(no description)'}")
    return 0


# -------------------------------------------------------------------- observed
def _recorded_keys(type_name: str) -> tuple[set[str], set[str]]:
    """(keys every row had, every key any row had) in the committed P2-00 shape."""
    path = OUT_DIR / f"fields_{type_name}.json"
    shape = json.loads(path.read_text(encoding="utf-8"))["shape"][0]
    return {k for k in shape if not k.endswith("?")}, {k.rstrip("?") for k in shape}


def differs_from_record(type_name: str, r: Result) -> str | None:
    """Why this answer is not the surface P2-00 verified, or None. Key names only."""
    if r.status != 200:
        return f"status {r.status or r.error}"
    if not isinstance(r.json, list) or not all(isinstance(row, Mapping) for row in r.json):
        return "the answer is not a list of objects"
    if not r.json:
        return "the list is empty"
    always, known = _recorded_keys(type_name)
    seen: set[str] = set().union(*(map(str, row) for row in r.json))
    missing = sorted(always - set.intersection(*(set(map(str, row)) for row in r.json)))
    if missing:
        return f"a recorded key is absent from a row: {safe_keys(dict.fromkeys(missing))}"
    if seen - known:
        return f"{len(seen - known)} key(s) the record does not have"
    return None


def required_token_facts(rows: list[Mapping[str, Any]]) -> tuple[Facts, list[str]]:
    counts: dict[str, dict[str, int]] = {}
    other = {"absent": 0, "null": 0, "not_a_string": 0, "not_a_token": 0}
    for row in rows:
        origin = "custom" if row.get("prefix") == PROPERTIES_PREFIX else "builtin"
        if "required" not in row:
            other["absent"] += 1
        elif row["required"] is None:
            other["null"] += 1
        elif not isinstance(row["required"], str):
            other["not_a_string"] += 1
        elif (token := safe_token(row["required"])) is None:
            other["not_a_token"] += 1
        else:
            cell = counts.setdefault(token, {"rows": 0, "custom": 0, "builtin": 0})
            cell["rows"] += 1
            cell[origin] += 1
    if len(counts) > MAX_TOKENS:  # names or free text, not an enum: keep nothing
        return {"tokens": None, "too_many_distinct_values": True}, []
    tokens = sorted(counts)
    return {
        "rows": bucket(len(rows)),
        "tokens": tokens,
        "rows_by_token": {t: {k: bucket(n) for k, n in sorted(counts[t].items())} for t in tokens},
        "rows_without_a_token": {k: bucket(n) for k, n in sorted(other.items())},
    }, tokens


def field_tokens(rec: Recorder) -> int:
    for type_name in FIELD_TYPES:
        template = ORG + f"/types/{type_name}/fields"
        r = rec.send(
            f"fields_{type_name}", "P2-03", "GET",
            rec.org + f"/types/{type_name}/fields", template,
        )  # fmt: skip
        problem = differs_from_record(type_name, r)
        if problem is not None:
            rec.say(f"STOPPED at {type_name}: {problem}; nothing written, nothing more sent")
            return EXIT_STOP
        facts, tokens = required_token_facts(r.json)
        write(
            rec, f"fields_{type_name}_required", "P2-03", r, {"required": facts},
            enums={"required": tokens},
            note="observed, read-only: the distinct `required` tokens of this object type's "
            "field definitions on this appliance, counts as buckets. Not every token SOAR "
            "knows, and nothing about what closing an incident enforces",
        )  # fmt: skip
        rec.say(f"{type_name}: " + json.dumps(facts, sort_keys=True))
    return 0


# ------------------------------------------------------------------- recording
def write(
    rec: Recorder, key: str, question: str, r: Result, facts: Facts, *,
    enums: Mapping[str, list[str]], note: str,
) -> None:  # fmt: skip
    document = {
        "_fixture": "verified-shape",
        # As P2-00b's preflight established it. Not re-read here: this addendum is four
        # GETs, and the version read is not one of them.
        "_appliance": f"QRadar SOAR {EXPECTED_VERSION}",
        "_ticket": TICKET,
        "_question": question,
        "_request": {"method": r.method, "path": r.template, "query_keys": list(r.query_keys)},
        "_status": r.status,
        "_content_type": r.content_type,
        "_error": r.error,
        "_note": note,
        "_facts": facts,
        "_enums": dict(enums),
        "shape": None,
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
    merged.update(rec.rows)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    step = parser.add_mutually_exclusive_group(required=True)
    step.add_argument("--swagger", action="store_true", help="one static GET: the description")
    step.add_argument("--fields", action="store_true", help="three GETs: the field lists")
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
        code = swagger_required(rec) if args.swagger else field_tokens(rec)
        finish(rec)
        return code
    except (httpx.HTTPError, OSError) as exc:  # never let a message with a URL escape
        print(f"probe aborted: {type(exc).__name__}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
