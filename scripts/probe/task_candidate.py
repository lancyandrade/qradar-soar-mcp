"""P2-00b: how a candidate task PUT body WOULD be built. Pure functions; nothing is sent.

This module has no HTTP client and imports none: it cannot send a request. It exists so
that the body-construction algorithm the owner reviewed is the code that runs, and so that
it can be tested offline. Sending the result is ``task_experiment.py``'s job, under its
own, separately approved limits.

The rule (owner, P2-00b): start from a FRESH read of the designated task in the output
formats the web UI uses, deep-copy it, and change ONLY ``status``. The captured browser
JSON is never replayed and no value is taken from a fixture. Anything unsettled is a stop:
there is no fallback branch.

``closed_date`` is server state that is passed through, never synthesised (owner ruling on
the approved observation pair): the UI's close request carries ``closed_date`` null and its
reopen request carries the existing non-null integer. So it is a PREREQUISITE, not an edit:

========  ====================  ==========================  =========================
target    fresh ``status``      fresh ``closed_date``       candidate
========  ====================  ==========================  =========================
``C``     must be ``O``         must be null                status -> C; nothing else
``O``     must be ``C``         must be non-null            status -> O; nothing else
========  ====================  ==========================  =========================

A prerequisite that is not met stops the construction. ``closed_date`` is never cleared and
never invented.

``task_layout`` is never normalised either. The read names its ``source``: the task tree
(what the web UI reads; undocumented) must show what the UI was observed to send, null; the
documented ``GET /tasks/{task_id}`` must show the empty list it returns. Whatever the read
shows is sent back untouched, and a representation other than the expected one is a stop.
Both sources were exercised live; the documented one is the recommended one.

Whether the UI also changes some other VALUE is not known and is not
assumed either way: every other key is passed through from the fresh GET untouched.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

TARGETS = {"C": "close", "O": "reopen"}  # target status -> the observation that proves it
OPPOSITE = {"C": "O", "O": "C"}
# What the approved observation for each target shows about closed_date, and therefore what
# the fresh task must look like BEFORE that change. True = null.
CLOSED_DATE_IS_NULL = {"C": True, "O": False}
SOURCES = ("tasktree", "documented")
CHANGED_KEYS = ("status",)  # the only key a candidate may differ in from the fresh task
UI_FORMAT_PARAMS = {"handle_format": "ids", "text_content_output_format": "objects_convert"}
# Baseline (2 GET) + close PUT + verification (2 GET) + fresh GET + reopen PUT +
# restoration (2 GET). An absolute ceiling for the whole experiment: never retried.
MAX_EXPERIMENT_REQUESTS = 9


@dataclass(frozen=True, slots=True)
class Candidate:
    """The outcome. ``body`` is None whenever ``stops`` is not empty; it is never printed."""

    target: str
    stops: tuple[str, ...]
    changed_keys: tuple[str, ...] = ()
    body: dict[str, Any] | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return not self.stops and self.body is not None


def json_type(value: object) -> str:
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
    return "list" if isinstance(value, list) else "object" if isinstance(value, Mapping) else "?"


def observed_type(shape: object) -> str:
    """The JSON type a recorded shape stands for, without its inner structure."""
    if isinstance(shape, Mapping):
        return "object"
    return "list" if isinstance(shape, list) else str(shape)


def value_class(value: object) -> str:
    """null / empty list / non-empty list / another JSON type. Never the value."""
    if isinstance(value, list):
        return "empty list" if not value else "non-empty list"
    return json_type(value)


def observed_class(shape: object) -> str:
    """The same classes, read back from a recorded shape."""
    if isinstance(shape, list):
        return "empty list" if not shape else "non-empty list"
    return observed_type(shape)


def baseline_stops(
    fresh: object, *, expect_status: str, task_id: str, incident_id: str
) -> list[str]:
    """Why a fresh GET may NOT be used as the start of a mutation. Empty means it may."""
    if not isinstance(fresh, Mapping):
        return ["the task is not readable as a JSON object"]
    stops = []
    if str(fresh.get("id")) != task_id:
        stops.append("the object read is not the designated task")
    if str(fresh.get("inc_id")) != incident_id:
        stops.append("the task no longer belongs to the designated incident")
    if fresh.get("status") != expect_status:
        stops.append(f"the task status is not {expect_status}")
    if fresh.get("active") is not True:
        stops.append("the task is not active")
    if fresh.get("frozen") is not False:
        stops.append("the task is frozen (or does not say)")
    if fresh.get("custom") is not True:
        stops.append("the task is not a custom task")
    return stops


def build_candidate(
    fresh: object,
    *,
    target: str,
    observation: Mapping[str, Any],
    task_id: str,
    incident_id: str,
    source: str = "tasktree",
) -> Candidate:
    """The body a PUT to ``target`` would carry, or the reasons there is none.

    ``source`` names the read ``fresh`` came from. ``tasktree`` (the default) must be in the
    very representation the UI was observed to send, ``task_layout`` included. ``documented``
    is the documented single-task GET, whose ``task_layout`` is known to differ (an empty
    list where the UI sent null): there ``task_layout`` is a prerequisite on the fresh task
    instead, and it is passed through UNCHANGED, never normalised.

    ``fresh`` is the task exactly as a GET in ``UI_FORMAT_PARAMS`` just returned it.
    ``observation`` is the recorded browser observation for ``target`` (facts and shape).
    """
    if target not in TARGETS:
        return Candidate(target, ("the target status must be C or O",))
    facts = observation.get("_facts") if isinstance(observation.get("_facts"), Mapping) else {}
    shape = observation.get("shape") if isinstance(observation.get("shape"), Mapping) else {}
    stops = baseline_stops(
        fresh, expect_status=OPPOSITE[target], task_id=task_id, incident_id=incident_id
    )
    # The observation must be the right one, of the right object, complete, and must show
    # what the approved pair showed about closed_date.
    if facts.get("label") != TARGETS[target] or facts.get("status_value") != target:
        stops.append(f"there is no valid '{TARGETS[target]}' observation with status {target}")
    if facts.get("body_is_the_designated_task") is not True:
        stops.append("the observation is not shown to be of the designated task")
    if facts.get("method") != "PUT" or facts.get("full_object") is not True:
        stops.append("the observation is not a full-object PUT")
    if facts.get("closed_date_is_null") is not CLOSED_DATE_IS_NULL[target]:
        stops.append("the observation's closed_date is not what the approved pair showed")
    if stops or not isinstance(fresh, Mapping):
        return Candidate(target, tuple(stops))

    # closed_date is a prerequisite on the FRESH task. It is never cleared, never invented.
    fresh_is_null = "closed_date" in fresh and fresh["closed_date"] is None
    if "closed_date" not in fresh:
        stops.append("the fresh task carries no closed_date key")
    elif target == "C" and not fresh_is_null:
        stops.append("an open task must have a null closed_date before it is closed")
    elif target == "O" and fresh_is_null:
        stops.append("a closed task must have a non-null closed_date before it is reopened")

    if set(map(str, fresh)) != set(facts.get("top_level_keys", [])):
        stops.append("the fresh task's key set is not the key set the UI was observed to send")
    for key in ("active", "required"):  # never changed here: a difference is a stop
        if isinstance(facts.get(key), bool) and facts[key] != fresh.get(key):
            stops.append(f"'{key}' differs between the observation and the fresh task")
    if source not in SOURCES:
        stops.append("the source must be 'tasktree' or 'documented'")
    exempt = {"task_layout"} if source == "documented" else set()
    mismatched = sorted(
        k for k in fresh
        if k in shape and k not in exempt and json_type(fresh[k]) != observed_type(shape[k])
    )  # fmt: skip
    if mismatched:
        stops.append("JSON type differs from the observed request for: " + ", ".join(mismatched))
    # task_layout: the source representation must BE the representation the UI was seen to
    # send (a direct task GET returns an empty list where the task tree returns null). It is
    # never normalised here: a different representation is a stop.
    if "task_layout" not in fresh or "task_layout" not in shape:
        stops.append("task_layout is missing from the fresh task or from the observation")
    elif source == "documented":
        # The question under test: is the documented representation round-trippable as it
        # is? An open task must show the empty list; a closed one whatever the server now
        # returns, as long as it is empty. Either way it is sent back untouched.
        allowed = ("empty list",) if target == "C" else ("empty list", "null")
        if value_class(fresh["task_layout"]) not in allowed:
            stops.append("the documented read does not carry the expected empty task_layout")
    elif value_class(fresh["task_layout"]) != observed_class(shape["task_layout"]):
        stops.append("task_layout is not in the representation the UI was observed to send")
    if stops:
        return Candidate(target, tuple(stops))

    body = copy.deepcopy(dict(fresh))
    body["status"] = target  # the ONLY change; closed_date and every other key pass through
    changed = tuple(sorted(k for k in body if body[k] != fresh[k]))
    if changed != CHANGED_KEYS:  # cannot happen; asserted so that a future edit cannot widen it
        return Candidate(target, ("the candidate would differ in more than status",))
    return Candidate(target, (), changed, body)


def rollback_stops(
    *,
    close_succeeded: bool,
    phase_unchanged: bool,
    requests_sent: int,
    reopen_candidate: Candidate,
) -> list[str]:
    """Why the pre-approved reopen PUT may NOT be sent. Empty means it may.

    A phase change after the close is a HARD STOP: no API rollback is sent, because nothing
    shows that reopening the task reverses a phase transition.
    """
    stops = []
    if not close_succeeded:
        stops.append("the close did not verifiably succeed")
    if not phase_unchanged:
        stops.append("the incident phase changed after the close: no API rollback is sent")
    if requests_sent + 3 > MAX_EXPERIMENT_REQUESTS:  # the reopen PUT and two verifying GETs
        stops.append("the request ceiling would be exceeded")
    if reopen_candidate.target != "O" or not reopen_candidate.ok:
        stops.extend(reopen_candidate.stops or ("there is no reopen candidate",))
    return stops


def restoration_report(baseline: Mapping[str, Any], restored: Mapping[str, Any]) -> dict[str, Any]:
    """Baseline against the task after rollback: key NAMES and booleans only."""
    keys = sorted(set(map(str, baseline)) | set(map(str, restored)))
    return {
        "same_key_set": set(map(str, baseline)) == set(map(str, restored)),
        "status_restored": restored.get("status") == baseline.get("status"),
        "closed_date_nullness_restored": (restored.get("closed_date") is None)
        == (baseline.get("closed_date") is None),
        "keys_whose_value_differs_from_the_baseline": [
            k for k in keys if baseline.get(k) != restored.get(k)
        ],
    }
