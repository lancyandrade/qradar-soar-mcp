"""Synthetic discovery payloads with the shapes P2-00 verified (P2-01).

``tests/fixtures/soar/verified/*.json`` record what QRadar SOAR 51.0.9.0.20848 answered
as *shapes*: key names and JSON types, never a value. This module turns each shape back
into a payload by filling it with obviously made-up values (``name-1``, a counter,
``uuid-1``), so the offline fake serves objects that have every key, wrapper and type
the appliance was seen to return, and nothing from it. The only values taken from the
record are the enumerations it kept on purpose (input types, object types, statuses) and
the appliance version. A field definition's ``required`` is one of them: the P2-03
addendum recorded its tokens for ``incident``, ``task`` and ``artifact`` fields, and for
nothing else, so a function input (a ``__function`` field) carries no ``required`` here
rather than a made-up one.

The payloads feed ``FakeSoar`` and, through the real collections backend, the committed
``tests/fixtures/catalog/lab-v51.json``.

``build_payloads(minimal=True)`` is the other end of every recorded shape: each optional
key (``key?``) absent and each nullable value null. A loader that needs more than the
appliance guarantees fails on it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERIFIED = Path(__file__).parent / "fixtures" / "soar" / "verified"
APPLIANCE_PREFIX = "QRadar SOAR "
ROWS = 2  # per collection
DATATABLE_TYPE_ID = 8
# Fields whose values are people and groups; their recorded values carry principal_type.
PRINCIPAL_INPUT_TYPES = ("select_owner", "multiselect_members")


def verified(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((VERIFIED / f"{name}.json").read_text(encoding="utf-8"))
    assert doc["_fixture"] == "verified-shape" and doc["_status"] == 200, name
    return doc


def uuid(n: int) -> str:
    """Opaque to the catalog, and deliberately not uuid-shaped: the probe's sanitiser
    treats anything that looks like a real identifier as a finding."""
    return f"uuid-{n}"


def fill(shape: Any, key: str, n: int, minimal: bool = False) -> Any:
    """A value of the recorded shape. ``a|b`` takes the first non-null alternative, or
    null when ``minimal``; a ``key?`` is dropped when ``minimal``."""
    if isinstance(shape, str):
        kinds = [k for k in shape.split("|") if k != "null"]
        kind = "null" if not kinds or (minimal and "null" in shape.split("|")) else kinds[0]
        if kind == "str":
            return uuid(n) if key == "uuid" else f"{key}-{n}"
        if kind == "int":
            return n
        if kind == "bool":
            return True
        assert kind == "null", f"unknown recorded type {shape!r}"
        return None
    if isinstance(shape, list):
        return [fill(shape[0], key, n, minimal)] if shape else []
    assert isinstance(shape, dict)
    if "<anyOf>" in shape:
        options = shape["<anyOf>"]
        return fill("null" if minimal and "null" in options else options[0], key, n, minimal)
    out: dict[str, Any] = {}
    for raw_key, sub in shape.items():
        if minimal and raw_key.endswith("?"):
            continue
        name = raw_key.rstrip("?")
        out[f"{key}_{n}" if name == "<name>" else name] = fill(sub, name, n, minimal)
    return out


def _rows(
    name: str,
    shape: Any,
    prefix: str,
    enums: dict[str, list[Any]],
    start: int,
    minimal: bool = False,
) -> list[Any]:
    rows = []
    for i in range(ROWS):
        n = start + i
        row = fill(shape, prefix, n, minimal)
        row["id"] = n
        if "name" in row:
            row["name"] = f"{prefix}_{n}"
        for key, values in enums.items():
            if key in row:
                row[key] = values[i % len(values)]
        rows.append(row)
    assert rows, name
    return rows


def build_payloads(minimal: bool = False) -> dict[str, Any]:
    """Route key -> response body, for ``FakeSoar``."""
    out: dict[str, Any] = {}

    const = verified("const")
    body = fill(const["shape"], "const", 1, minimal)
    body["server_version"]["version"] = const["_appliance"].removeprefix(APPLIANCE_PREFIX)
    out["const"] = body

    for name, prefix, start in (
        ("actions", "rule", 300),
        ("scripts", "script", 400),
        ("message_destinations", "destination", 500),
        ("phases", "phase", 600),
    ):
        doc = verified(name)
        assert list(doc["shape"]) == ["entities"], name
        out[name] = {
            "entities": _rows(
                name, doc["shape"]["entities"][0], prefix, doc["_enums"], start, minimal
            )
        }
    # P2-02: the single script, which is the list row plus ``script_text`` (the body).
    script_doc = verified("script")
    assert script_doc["shape"]["script_text"] == "str"
    assert set(script_doc["shape"]) - set(verified("scripts")["shape"]["entities"][0]) == {
        "script_text"
    }
    for row in out["scripts"]["entities"]:
        detail = fill(script_doc["shape"], "script", row["id"], minimal)
        detail.update(row)
        detail["script_text"] = f"# synthetic body of {row['name']}\nresult = {row['id']}\n"
        out[f"script:{row['id']}"] = detail
    assert verified("workflows")["shape"] == {"entities": []}  # the org had none
    out["workflows"] = {"entities": []}

    groups = verified("groups")
    out["groups"] = _rows("groups", groups["shape"][0], "group", groups["_enums"], 700, minimal)

    # Functions: list rows without view_items, single objects with them, and the
    # __function fields those view_items point at, joined by uuid (Q5).
    field_doc = verified("function_fields")
    inputs = _rows("function_fields", field_doc["shape"][0], "input", {}, 100, minimal)
    for i, row in enumerate(inputs):
        row.pop("required", None)  # an optional key whose values were never recorded
        row["uuid"] = uuid(row["id"])
        row["input_type"] = field_doc["_enums"]["input_type"][i * 3 % 6]  # boolean, select
        row["type_id"] = field_doc["_enums"]["type_id"][0]
    out["function_fields"] = inputs
    list_doc, single_doc = verified("functions"), verified("function")
    listing = _rows("functions", list_doc["shape"]["entities"][0], "function", {}, 200, minimal)
    out["functions"] = {"entities": listing}
    for row in listing:
        detail = fill(single_doc["shape"], "function", row["id"], minimal)
        detail.update(id=row["id"], name=row["name"], uuid=row["uuid"])
        item = detail["view_items"][0]
        detail["view_items"] = [{**item, "content": field["uuid"]} for field in inputs]
        out[f"function:{row['id']}"] = detail

    # The fake serves types/incident/fields from its Phase-1 fixture; ``fields:incident``
    # is the recorded shape of that call, for the tests that want it instead.
    for type_name in ("incident", "task", "artifact"):
        doc = verified(f"fields_{type_name}")
        rows = _rows(type_name, doc["shape"][0], f"{type_name}_field", {}, 800, minimal)
        for i, row in enumerate(rows):
            kinds = [k for k in doc["_enums"]["input_type"] if k not in PRINCIPAL_INPUT_TYPES]
            row["input_type"] = kinds[i % len(kinds)]
            row["prefix"] = "properties" if i else None  # one built-in and one custom field
            # As observed (P2-03): tokens on built-in fields only, the key absent elsewhere.
            tokens = verified(f"p2_03_fields_{type_name}_required")["_enums"]["required"]
            row.pop("required", None)
            if not i and tokens and not minimal:
                row["required"] = tokens[0]
            for value in row["values"]:
                value.pop("principal_type", None)  # an ordinary select value, not a person
        out[f"fields:{type_name}"] = rows

    type_shape = verified("types")["shape"]["<name>"]
    table_field = verified("datatable_type")["shape"]["fields"]["<name>"]
    types: dict[str, Any] = {}
    for n, (type_name, type_id) in enumerate(
        (("incident", 0), ("table_1", DATATABLE_TYPE_ID), ("table_2", DATATABLE_TYPE_ID)), 900
    ):
        row = fill({k: v for k, v in type_shape.items() if k != "fields"}, "type", n, minimal)
        row.update(id=n, type_name=type_name, type_id=type_id, fields={})
        if type_id == DATATABLE_TYPE_ID:
            row["parent_types"] = ["incident"]
            for order, column in enumerate(("column_a", "column_b")):
                cell = fill(table_field, "column", n, minimal)
                cell.update(name=column, order=order, input_type="text")
                row["fields"][column] = cell
        else:
            row["parent_types"] = []
        types[type_name] = row
    out["types"] = types

    incident_type = verified("incident_types")["shape"]["<name>"]
    out["incident_types"] = {
        row["name"]: row
        for row in _rows("incident_types", incident_type, "incident_type", {}, 950, minimal)
    }

    playbooks = verified("playbooks_query_paged")
    assert set(playbooks["shape"]) == {"data", "recordsFiltered", "recordsTotal"}
    out["playbooks"] = _rows(
        "playbooks", playbooks["shape"]["data"][0], "playbook", playbooks["_enums"], 1000, minimal
    )
    return out
