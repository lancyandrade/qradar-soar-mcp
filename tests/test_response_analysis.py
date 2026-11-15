"""P2-07: ``soar_analyse_incident_response`` (06 P2-07; 08 §35).

AC: a comparative summary for at least five incidents within the token budget; graceful
degradation when the history endpoints are unavailable.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from qradar_soar_mcp.client.history import (
    HISTORY_KEYS,
    MAX_DETAIL_ROWS,
    parse_history,
    parse_workflow_instances,
)
from qradar_soar_mcp.tools import TOOL_REGISTRY, run_pipeline
from qradar_soar_mcp.tools.response_analysis import (
    ANALYSIS_BUDGET_CHARS,
    MAX_INCIDENTS,
    NOT_OBSERVABLE,
)
from tests.conftest import SENTINEL
from tests.fake_soar import FakeSoar, empty_history, synthetic_history
from tests.tool_harness import build_runtime

TOOL = "soar_analyse_incident_response"
USER_MARK = "analyst@soar.example.internal"  # the synthetic history's user: never returned
VALUE_MARK = "Respond"  # a synthetic new_val: never returned from history


def add_incidents(fake: FakeSoar, count: int, *, tasks_each: int = 2) -> list[int]:
    """Copies of incident 42 with ids 43.., closed, with their own tasks and history."""
    ids = [42]
    template = fake.incident
    for n in range(1, count):
        inc_id = 42 + n
        inc = copy.deepcopy(template)
        inc.update(
            id=inc_id,
            name=f"Incident {inc_id}",
            plan_status="C",
            resolution_id="Resolved" if n % 2 else "Duplicate",
            severity_code="High" if n % 3 == 0 else "Medium",
            create_date=1_700_000_000_000,
            end_date=1_700_000_000_000 + n * 3_600_000,
        )
        fake.incidents[inc_id] = inc
        for t in range(tasks_each):
            task_id = 1_000_000 + inc_id * 1_000 + t
            fake.tasks[task_id] = {
                "id": task_id,
                "inc_id": inc_id,
                "name": "Confirm with user" if t == 0 else f"Task {t} of {inc_id}",
                "status": "C",
                "phase_id": "Respond",
                "required": t == 0,
            }
        fake.history[inc_id] = synthetic_history()
        ids.append(inc_id)
    return ids


async def analyse(fake: FakeSoar, tmp_path: Path, ids: Any) -> dict[str, Any]:
    rt = build_runtime(fake, tmp_path)
    try:
        return await run_pipeline(TOOL_REGISTRY[TOOL], rt, {"incident_ids": ids})
    finally:
        await rt.aclose()


def calls(fake: FakeSoar) -> list[tuple[str, str]]:
    return [(r.method, r.path.split("/rest/orgs/201", 1)[-1]) for r in fake.requests]


# ------------------------------------------------------------------- the AC


async def test_five_incidents_are_compared_within_the_budget(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 5)
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is True, out
    data = out["data"]
    assert data["incident_ids"] == ids
    assert [i["id"] for i in data["incidents"]] == ids
    comparison = data["comparison"]
    assert comparison["incidents"] == 5
    assert comparison["resolution_id"] == {"Resolved": 2, "Duplicate": 2, "(none)": 1}
    assert comparison["plan_status"] == {"C": 4, "A": 1}
    assert comparison["tasks_in_incidents"][0] == {"name": "Confirm with user", "incidents": 5}
    assert comparison["changed_fields_in_incidents"] == {
        "phase_id": 5,
        "plan_status": 5,
        "resolution_id": 5,
        "severity_code": 5,
    }
    durations = comparison["end_minus_create_ms"]
    assert durations == {"n": 4, "min": 3_600_000, "median": 9_000_000, "max": 14_400_000}
    assert comparison["history_states"] == {"loaded": 5}
    assert comparison["workflow_instance_states"] == {"loaded": 5}
    budget = data["budget"]
    assert budget["chars"] <= budget["limit_chars"] == ANALYSIS_BUDGET_CHARS
    assert budget["reductions"] == 0
    assert data["not_observable"] == NOT_OBSERVABLE


async def test_ten_incidents_with_many_tasks_are_cut_to_the_budget(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, MAX_INCIDENTS, tasks_each=200)
    for inc in fake.incidents.values():
        inc["name"] = "N" * 400
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is True, out
    data = out["data"]
    assert data["budget"]["chars"] <= ANALYSIS_BUDGET_CHARS
    assert data["budget"]["reductions"] >= 1
    assert len(json.dumps(data)) <= ANALYSIS_BUDGET_CHARS
    for view in data["incidents"][1:]:
        assert view["omitted"]["tasks"] == 200 - len(view["tasks"]) > 0
    # The comparison is computed over every task, not the cut lists.
    assert data["comparison"]["tasks_in_incidents"][0]["incidents"] == MAX_INCIDENTS


@pytest.mark.parametrize("status", [403, 404, 500])
async def test_history_endpoints_unavailable_degrade_per_incident(
    fake: FakeSoar, tmp_path: Path, status: int
):
    ids = add_incidents(fake, 5)
    fake.fault("GET", r"/incidents/4[34]/history$", status=status)
    fake.fault("GET", r"/incidents/\d+/workflow_instances$", status=status)
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is True, out
    views = {v["id"]: v for v in out["data"]["incidents"]}
    for inc_id in (43, 44):
        assert views[inc_id]["history"]["state"] == "unavailable"
        assert isinstance(views[inc_id]["history"]["error"], str)
    assert views[45]["history"]["state"] == "loaded"
    assert all(v["workflow_instances"]["state"] == "unavailable" for v in views.values())
    comparison = out["data"]["comparison"]
    assert comparison["history_states"] == {"loaded": 3, "unavailable": 2}
    assert comparison["changed_fields_in_incidents"]["phase_id"] == 3
    assert comparison["resolution_id"]  # the rest of the answer stands


async def test_a_timeout_on_history_degrades_too(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 2)
    fake.fault("GET", r"/incidents/43/history$", exc=httpx.ReadTimeout)
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is True, out
    view = out["data"]["incidents"][1]
    assert view["history"] == {"state": "unavailable", "error": "timeout"}


async def test_an_incident_that_cannot_be_read_fails_the_call(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 3)
    out = await analyse(fake, tmp_path, [*ids[:2], 999])
    assert out["ok"] is False and out["error"]["code"] == "not_found"


# ------------------------------------------------------- what is (not) returned


async def test_history_values_and_users_are_never_returned(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 3)
    for inc_id in ids:
        rows = fake.history[inc_id]["incident_detail_history"]
        rows[0]["diffs"][0]["new_val"] = {"format": "text", "content": SENTINEL}
        rows[0]["user"] = SENTINEL
    fake.incident["description"] = SENTINEL
    fake.incident["resolution_summary"] = SENTINEL
    out = await analyse(fake, tmp_path, ids)
    text = json.dumps(out)
    assert out["ok"] is True
    assert SENTINEL not in text and USER_MARK not in text
    assert all(VALUE_MARK not in json.dumps(v["history"]) for v in out["data"]["incidents"])
    assert "description" not in text and "resolution_summary" not in text


async def test_only_verified_reads_are_sent(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 2)
    await analyse(fake, tmp_path, ids)
    sent = calls(fake)
    assert all(method == "GET" for method, _ in sent)
    assert {path for _, path in sent} == {
        f"/incidents/{i}{suffix}"
        for i in ids
        for suffix in ("", "/tasks", "/history", "/workflow_instances")
    }


async def test_workflow_instance_rows_are_counted_not_read(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 2)
    fake.workflow_instances[43] = {"entities": [{"name": SENTINEL}, {"x": 1}]}
    out = await analyse(fake, tmp_path, ids)
    view = out["data"]["incidents"][1]
    assert view["workflow_instances"] == {
        "state": "unverified",
        "count": 2,
        "reason": "rows not read",
    }
    assert SENTINEL not in json.dumps(out)
    assert "rules_and_playbooks_fired" in out["data"]["not_observable"]


async def test_a_history_object_in_another_shape_is_reported_unverified(
    fake: FakeSoar, tmp_path: Path
):
    ids = add_incidents(fake, 2)
    fake.history[43] = {"histories": [SENTINEL]}
    out = await analyse(fake, tmp_path, ids)
    view = out["data"]["incidents"][1]
    assert view["history"]["state"] == "unverified"
    assert SENTINEL not in json.dumps(out)


# -------------------------------------------------------------------- inputs


@pytest.mark.parametrize(
    "ids",
    [
        [],
        list(range(1, MAX_INCIDENTS + 2)),
        [42, 42],
        [42, 0],
        [42, -1],
        [42, True],
        "42",
        [42, "43"],
    ],
)
async def test_bad_incident_ids_are_refused_before_any_request(
    fake: FakeSoar, tmp_path: Path, ids: Any
):
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is False and out["error"]["code"] == "validation"
    assert fake.requests == []


# ------------------------------------------------------------------ parsing


def test_parse_history_keeps_names_dates_and_revisions_only():
    parsed = parse_history(synthetic_history())
    assert parsed.shape_verified
    assert [(r.revision_number, r.date) for r in parsed.revisions] == [
        (1, 1_700_000_000_000),
        (2, 1_700_000_360_000),
    ]
    assert parsed.revisions[0].changed_fields == ("severity_code", "phase_id")
    assert parsed.other_sections_with_data == ()


def test_parse_history_counts_rows_it_cannot_read_and_other_sections():
    body = synthetic_history()
    body["incident_detail_history"] += [{"diffs": "x"}, {"diffs": [{"name": 3}]}, "row", {}]
    body["task_history"] = [{"anything": SENTINEL}]
    parsed = parse_history(body)
    assert parsed.unparsed_rows == 4 and len(parsed.revisions) == 2
    assert parsed.other_sections_with_data == ("task_history",)


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "x",
        {"incident_detail_history": []},
        {**empty_history(), "incident_detail_history": "x"},
    ],
)
def test_parse_history_refuses_another_shape(body: Any):
    assert parse_history(body).shape_verified is False


def test_parse_history_bounds_rows_and_field_names():
    body = empty_history()
    row = {"date": 1, "revision_number": 1, "diffs": [{"name": "f"}]}
    body["incident_detail_history"] = [row] * (MAX_DETAIL_ROWS + 5)
    parsed = parse_history(body)
    assert len(parsed.revisions) == MAX_DETAIL_ROWS and parsed.rows_cut
    body["incident_detail_history"] = [{"diffs": [{"name": "n" * 201}]}]
    assert parse_history(body).unparsed_rows == 1
    assert set(HISTORY_KEYS) == set(empty_history())


@pytest.mark.parametrize(
    ("body", "verified", "count"),
    [({"entities": []}, True, 0), ({"entities": [{}]}, False, 1), ({}, False, 0), ([], False, 0)],
)
def test_parse_workflow_instances(body: Any, verified: bool, count: int):
    parsed = parse_workflow_instances(body)
    assert (parsed.shape_verified, parsed.count) == (verified, count)


# ------------------------------------------------------- review hardening


async def test_an_auth_failure_on_history_fails_the_call(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 2)
    fake.fault("GET", r"/incidents/43/history$", status=401)
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is False and out["error"]["code"] == "auth_failed"


async def test_a_huge_id_list_is_refused_before_it_is_scanned(fake: FakeSoar, tmp_path: Path):
    out = await analyse(fake, tmp_path, list(range(1, 200_001)))
    assert out["ok"] is False and out["error"]["code"] == "validation"
    assert fake.requests == []


async def test_the_answer_is_refused_when_nothing_fits(fake: FakeSoar, tmp_path: Path, monkeypatch):
    from qradar_soar_mcp.tools import response_analysis

    monkeypatch.setattr(response_analysis, "ANALYSIS_BUDGET_CHARS", 500)
    out = await analyse(fake, tmp_path, add_incidents(fake, 3))
    assert out["ok"] is False and out["error"]["code"] == "response_too_large"


async def test_odd_incident_bodies_stay_bounded(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 3)
    odd = fake.incidents[43]
    odd["id"] = {"nested": SENTINEL}
    odd["incident_type_ids"] = [f"type {n} {'t' * 400}" for n in range(100)]
    odd["severity_code"] = 1.5
    odd["resolution_id"] = {"name": SENTINEL}
    for task in fake.tasks.values():
        if task["inc_id"] == 43:
            task["status"] = "S" * 1000
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is True, out
    view = out["data"]["incidents"][1]
    assert view["id"] == 43
    assert len(view["incident_type_ids"]) == 25
    assert view["severity_code"] is None and view["resolution_id"] is None
    assert all(t["status"] is None for t in view["tasks"])
    assert SENTINEL not in json.dumps(out)
    for key in out["data"]["comparison"]["incident_type_ids"]:
        assert len(key) <= 130  # 100 characters plus the truncation marker


async def test_an_auth_failure_on_workflow_instances_fails_the_call(fake: FakeSoar, tmp_path: Path):
    ids = add_incidents(fake, 2)
    fake.fault("GET", r"/incidents/43/workflow_instances$", status=401)
    out = await analyse(fake, tmp_path, ids)
    assert out["ok"] is False and out["error"]["code"] == "auth_failed"


async def test_odd_types_and_workflow_bodies_are_reported_not_parsed(
    fake: FakeSoar, tmp_path: Path
):
    ids = add_incidents(fake, 2)
    fake.incidents[43]["incident_type_ids"] = "not a list"
    fake.workflow_instances[43] = {"rows": []}
    out = await analyse(fake, tmp_path, ids)
    view = out["data"]["incidents"][1]
    assert view["incident_type_ids"] == []
    assert view["workflow_instances"]["state"] == "unverified"
    assert "count" not in view["workflow_instances"]
