"""P2-00b: reduce a request the SOAR web UI sent to its *structure*. Offline; sends nothing.

The owner watches the browser's Network panel while the UI changes a disposable task,
copies ONLY the request payload (the JSON body) and pipes it in. PowerShell:

    Get-Clipboard | uv run python scripts/probe/guarded.py shape_request.py --label close `
        --method PUT --path-template "/rest/orgs/{org_id}/tasks/{task_id}" `
        --query handle_format=names --query text_content_output_format=always_text

Run it from PowerShell: Git Bash rewrites an argument that starts with ``/`` into a Windows
path, and the template is then (correctly) refused.

What this tool guarantees:

* **It never sees session material.** It takes a JSON body on standard input and nothing
  else from the browser. A HAR, a "copy as cURL" or a "copy as fetch" is refused unread
  (they carry cookies and tokens). Headers are accepted by NAME from a closed list of
  four, with a value only when it is one of IBM's documented enum tokens.
* **It never sees a host or an id.** The path is a template you type; one digit in it is
  refused. Query values are kept only when they are documented enum tokens or booleans.
* **The body lives in memory.** What is printed and written is key names, JSON types and
  booleans, through the same verifier as every probe fixture. No value, no task text.

Output: ``tests/fixtures/soar/verified/p2_00b_ui_request_<label>.json``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from probe_env import ROOT, load_env
from sanitise import (
    EnumCollector,
    UnsafeArtefactError,
    dump_verified,
    safe_keys,
    safe_keys_matching,
    safe_text,
    shape_of,
)

OUT_DIR = ROOT / "tests" / "fixtures" / "soar" / "verified"
PREFIX = "p2_00b_ui_request_"
MAX_BODY_BYTES = 5_000_000
METHODS = ("GET", "PUT", "POST", "PATCH", "DELETE")
LIVE_ONLY_TASK_KEYS = ("auto_deactivate", "form", "task_layout", "user_notes")
# The appliance's documented enum tokens (json_ObjectHandleFormat, json_TextContentOutputFormat).
ENUM_VALUES: dict[str, frozenset[str]] = {
    "handle_format": frozenset({"default", "ids", "names", "objects"}),
    "text_content_output_format": frozenset(
        {"default", "objects_convert", "objects_no_convert", "objects_convert_html",
         "objects_convert_text", "always_text"}
    ),
    "content-type": frozenset({"application/json"}),
    "accept": frozenset({"application/json"}),
}  # fmt: skip
HEADER_NAMES = frozenset(ENUM_VALUES)  # nothing that can carry a session, a token or a host
WITHHELD = "<value withheld>"
_TEMPLATE = re.compile(r"^/[A-Za-z_{}/.-]{1,160}$")  # no digit: every id is a {placeholder}
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
_LABEL = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
_NOT_A_BODY = re.compile(r"^\s*(curl\s|fetch\(|GET\s|PUT\s|POST\s|PATCH\s|HTTP/|\$\s)", re.I)
# A label that names a state change must carry that state: the two were mixed up once.
LABEL_STATUS = {"close": "C", "reopen": "O"}
STATE_FACTS = ("status_value", "closed_date_is_null", "active", "required")
REQUEST_FACTS = ("method", "path_template", "query", "headers_named_by_the_owner")
HANDLE_KEYS = ("phase_id", "owner_id", "at_id", "category_id", "inc_owner_id")


class RefusedInputError(ValueError):
    """The input is not something this tool may read. The message is a fixed sentence."""


def parse_pairs(items: list[str], *, headers: bool) -> dict[str, str]:
    """``NAME`` or ``NAME=VALUE``. A value survives only if it is a documented enum token."""
    out: dict[str, str] = {}
    for item in items:
        name, _, value = item.partition("=")
        name = name.strip().lower() if headers else name.strip()
        if not _NAME.match(name):
            raise RefusedInputError("a parameter or header is given by its plain name")
        if headers and name not in HEADER_NAMES:
            raise RefusedInputError(
                "only these header names are accepted: " + ", ".join(sorted(HEADER_NAMES))
            )
        known = ENUM_VALUES.get(name.lower(), frozenset({"true", "false"}))
        out[name] = value if value in known else (WITHHELD if value else "<no value given>")
    return out


def decode_body(raw: bytes) -> Any:
    """The JSON body, or a refusal. Nothing from ``raw`` is ever echoed."""
    if len(raw) > MAX_BODY_BYTES:
        raise RefusedInputError("the input is larger than any request body; nothing was read")
    boms = (bytes([0xFF, 0xFE]), bytes([0xFE, 0xFF]))
    text = raw.decode("utf-16" if raw[:2] in boms else "utf-8-sig", errors="replace").strip()
    if not text:
        raise RefusedInputError("no body on standard input (use --no-body for a bodiless request)")
    if _NOT_A_BODY.match(text):
        raise RefusedInputError(
            "that is a copied command or a raw HTTP message, which carries session material; "
            "pipe in the JSON request payload only"
        )
    try:
        body = json.loads(text)
    except ValueError:
        raise RefusedInputError("the input is not JSON; pipe in the request payload only") from None
    if isinstance(body, Mapping) and isinstance(body.get("log"), Mapping):
        raise RefusedInputError("that is a HAR export, which carries cookies and tokens; refused")
    if isinstance(body, Mapping) and {"headers", "cookies"} & {str(k).lower() for k in body}:
        raise RefusedInputError("the input carries headers or cookies; pipe in the payload only")
    return body


def _form(value: object) -> str:
    """How a handle or a text field is written: by JSON type, or as a known object form."""
    if isinstance(value, Mapping):
        keys = set(map(str, value))
        if keys == {"id", "name"}:
            return "object{id,name}"
        if keys == {"format", "content"}:
            return "object{format,content}"
        return "object"
    if isinstance(value, bool):
        return "bool"
    return {type(None): "null", int: "int", str: "str", list: "list"}.get(type(value), "other")


def _value_class(value: object) -> str:
    """null, an empty list, a non-empty list, or another JSON type. Never the value."""
    if isinstance(value, list):
        return "empty list" if not value else "non-empty list"
    return _form(value)


def _reference(name: str) -> Mapping[str, Any]:
    path = OUT_DIR / f"p2_00b_{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def reduce_request(
    body: Any,
    *,
    label: str,
    method: str,
    path_template: str,
    query: Mapping[str, str],
    headers: Mapping[str, str],
    designated_task_id: str = "",
    designated_incident_id: str = "",
) -> tuple[dict[str, Any], Any]:
    """``(facts, shape)`` for one observed UI request. Values never leave this function.

    The two designated ids are compared with the body in memory and become booleans.
    """
    if method not in METHODS:
        raise RefusedInputError("method must be one of " + ", ".join(METHODS))
    if not _TEMPLATE.match(path_template) or "//" in path_template or ".." in path_template:
        raise RefusedInputError(
            "type the path as a template with every id replaced, for example "
            "/rest/orgs/{org_id}/tasks/{task_id}; a digit is refused"
        )
    if not _LABEL.match(label):
        raise RefusedInputError("label is a short lower-case word, for example close or reopen")
    facts: dict[str, Any] = {
        "label": label,
        "method": method,
        "path_template": path_template,
        "query": dict(query),
        "headers_named_by_the_owner": dict(headers),
        "body_present": body is not None,
        "body_is_json_object": isinstance(body, Mapping),
    }  # fmt: skip
    if not isinstance(body, Mapping):
        return facts, shape_of(body) if body is not None else None
    keys = safe_keys(body)
    documented = _reference("doc_type_TaskDTO").get("_facts", {}).get("properties", {})
    live = _reference("task").get("shape")
    live_keys = sorted(k.rstrip("?") for k in live) if isinstance(live, Mapping) else []
    status = body.get("status")
    looks = (
        "patch (changes + version)" if {"changes", "version"} <= set(keys)
        else "task object" if {"status", "name"} <= set(keys) else "other"
    )  # fmt: skip
    facts.update(
        {
            "looks_like": looks,
            "top_level_keys": keys,
            "top_level_key_count": len(keys),
            "keys_masked_as_not_schema_names": len(body) - len(keys),
            "status_value": status if status in ("O", "C") else "absent" if status is None
            else "other",
            "version_like_keys": safe_keys_matching(
                body, r"^vers$|version|etag|revision|^lock|token|csrf|nonce"
            ),
            # State, as far as it is safe to keep it: two letters, nullness and booleans.
            "closed_date_is_null": body["closed_date"] is None if "closed_date" in body
            else "absent",
            "active": body["active"] if isinstance(body.get("active"), bool) else None,
            "required": body["required"] if isinstance(body.get("required"), bool) else None,
            "body_is_the_designated_task": str(body.get("id")) == designated_task_id
            if designated_task_id else None,
            "body_is_in_the_designated_incident": str(body.get("inc_id")) == designated_incident_id
            if designated_incident_id else None,
            "task_layout_class": _value_class(body["task_layout"]) if "task_layout" in body
            else "absent",
            "live_only_keys_present": {k: k in body for k in LIVE_ONLY_TASK_KEYS},
            "handle_forms": {k: _form(body[k]) for k in HANDLE_KEYS if k in body},
            "instructions_form": _form(body["instructions"]) if "instructions" in body
            else "absent",
        }
    )  # fmt: skip
    expected = LABEL_STATUS.get(label)
    if expected and facts["status_value"] != expected:
        raise RefusedInputError(
            f"--label {label} is for the request that sets status {expected}; the payload on "
            "standard input sets a different status, so nothing was written. Copy the payload "
            "of the right request and run again"
        )
    if documented:
        facts["documented_taskdto_properties_present"] = sorted(k for k in documented if k in body)
        facts["documented_taskdto_properties_absent"] = sorted(
            k for k in documented if k not in body
        )
        facts["documented_read_only_properties_present"] = sorted(
            k for k, v in documented.items() if v.get("documented_read_only") and k in body
        )
        facts["documented_create_only_properties_present"] = sorted(
            k for k, v in documented.items() if v.get("documented_create_only") and k in body
        )
        facts["keys_not_in_documented_taskdto"] = sorted(k for k in keys if k not in documented)
    if live_keys:
        facts["keys_of_the_live_get_that_are_absent"] = sorted(
            k for k in live_keys if k not in body
        )
        facts["keys_not_in_the_live_get"] = sorted(k for k in keys if k not in live_keys)
        facts["full_object"] = all(k in body for k in live_keys)
    return facts, shape_of(body, enums=EnumCollector())


def _top_type(shape: object) -> str:
    """The JSON type of a recorded shape, without its inner structure."""
    if isinstance(shape, Mapping):
        return "object"
    return "list" if isinstance(shape, list) else str(shape)


def compare_pair(first: str, second: str) -> dict[str, Any]:
    """Two recorded observations side by side. Reads fixtures only; no value exists in them."""
    docs = {label: _reference(f"ui_request_{label}") for label in (first, second)}
    facts = {label: doc.get("_facts", {}) for label, doc in docs.items()}
    shapes = {
        label: doc["shape"] if isinstance(doc.get("shape"), Mapping) else {}
        for label, doc in docs.items()
    }
    problems: list[str] = []
    for label, fact in facts.items():
        if not fact:
            problems.append(f"{label}: no fixture")
            continue
        if fact.get("label") != label:
            problems.append(f"{label}: the fixture carries another label")
        if label in LABEL_STATUS and fact.get("status_value") != LABEL_STATUS[label]:
            problems.append(f"{label}: status_value is not {LABEL_STATUS[label]}")
        if any(k not in fact for k in STATE_FACTS):
            problems.append(f"{label}: recorded before the state facts existed; capture it again")
        if fact.get("body_is_the_designated_task") is not True:
            problems.append(f"{label}: not shown to be the designated task")
        if fact.get("body_is_in_the_designated_incident") is not True:
            problems.append(f"{label}: not shown to be in the designated incident")
    one, two = facts[first], facts[second]
    keys_one, keys_two = set(one.get("top_level_keys", [])), set(two.get("top_level_keys", []))
    if one and two:
        if any(one.get(k) != two.get(k) for k in REQUEST_FACTS):
            problems.append("the two requests differ in method, path, query or headers")
        if keys_one != keys_two:
            problems.append("the two bodies do not have the same key set")
    return {
        "pair": [first, second],
        "valid_pair": not problems,
        "problems": problems,
        "request": {k: one.get(k) for k in REQUEST_FACTS},
        "state": {label: {k: facts[label].get(k) for k in STATE_FACTS} for label in facts},
        "state_facts_that_differ": sorted(k for k in STATE_FACTS if one.get(k) != two.get(k)),
        "same_key_set": bool(keys_one) and keys_one == keys_two,
        "key_count": {first: len(keys_one), second: len(keys_two)},
        "keys_only_in": {first: sorted(keys_one - keys_two), second: sorted(keys_two - keys_one)},
        "keys_whose_json_type_differs": {
            k: {first: _top_type(shapes[first][k]), second: _top_type(shapes[second][k])}
            for k in sorted(keys_one & keys_two)
            if k in shapes[first] and k in shapes[second]
            and _top_type(shapes[first][k]) != _top_type(shapes[second][k])
        },
        "same_in_both": {
            k: one.get(k) == two.get(k)
            for k in ("handle_forms", "instructions_form", "live_only_keys_present",
                      "version_like_keys", "full_object")
        },
        "handle_forms": {label: facts[label].get("handle_forms") for label in facts},
        "instructions_form": {label: facts[label].get("instructions_form") for label in facts},
        "live_only_keys_present": {
            label: facts[label].get("live_only_keys_present") for label in facts
        },
        "version_like_keys": {label: facts[label].get("version_like_keys") for label in facts},
    }  # fmt: skip


def _compare_main(labels: list[str], literals: Mapping[str, str]) -> int:
    if any(not _LABEL.match(label) for label in labels):
        print("refused: --compare takes two labels, for example close reopen")
        return 2
    result = compare_pair(labels[0], labels[1])
    document = {
        "_fixture": "observed-ui-request-pair",
        "_ticket": "P2-00b",
        "_source": "an offline comparison of two observed-ui-request-shape fixtures",
        "_facts": result,
    }
    try:
        dump_verified(OUT_DIR / f"{PREFIX}pair.json", document, literals)
    except UnsafeArtefactError as exc:
        print(f"NOT WRITTEN: {exc}")
        return 3
    for key, value in result.items():
        print(safe_text(f"{key}: {json.dumps(value, sort_keys=True)}", literals))
    return 0 if result["valid_pair"] else 4


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--label", default="", help="close (status C), reopen (status O), ...")
    parser.add_argument("--method", default="", type=str.upper, choices=("", *METHODS))
    parser.add_argument("--path-template", default="")
    parser.add_argument(
        "--compare", nargs=2, metavar="LABEL",
        help="offline: compare two recorded observations, for example close reopen",
    )  # fmt: skip
    parser.add_argument("--query", action="append", default=[], metavar="NAME[=VALUE]")
    parser.add_argument("--header", action="append", default=[], metavar="NAME[=VALUE]")
    parser.add_argument("--no-body", action="store_true", help="the request carried no body")
    args = parser.parse_args(argv)
    env = load_env(required=False)
    literals = env.literals()
    if args.compare:
        return _compare_main(args.compare, literals)
    if not (args.label and args.method and args.path_template):
        print("refused: --label, --method and --path-template are all needed")
        return 2
    try:
        body = None if args.no_body else decode_body(sys.stdin.buffer.read(MAX_BODY_BYTES + 1))
        facts, shape = reduce_request(
            body,
            label=args.label,
            method=args.method,
            path_template=args.path_template,
            query=parse_pairs(args.query, headers=False),
            headers=parse_pairs(args.header, headers=True),
            designated_task_id=env.task_id,
            designated_incident_id=env.incident_id,
        )
    except RefusedInputError as exc:
        print(f"refused: {exc}")
        return 2
    document = {
        "_fixture": "observed-ui-request-shape",
        "_ticket": "P2-00b",
        "_source": "a request the web UI sent, observed by the owner in the browser and reduced "
        "offline by scripts/probe/shape_request.py; the probe sent nothing",
        "_facts": facts,
        "shape": shape,
    }
    target = OUT_DIR / f"{PREFIX}{args.label}.json"
    try:
        dump_verified(target, document, literals)
    except UnsafeArtefactError as exc:
        print(f"NOT WRITTEN: {exc}")
        return 3
    for key, value in facts.items():
        print(safe_text(f"{key}: {json.dumps(value, sort_keys=True)}", literals))
    print(f"written: {Path(target).relative_to(ROOT).as_posix()} (key names and JSON types only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
