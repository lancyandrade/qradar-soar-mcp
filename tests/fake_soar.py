"""An in-process model of the Phase-1 QRadar SOAR REST semantics.

``FakeSoar`` is the state and response engine; ``respx`` (see ``conftest.py``)
is the HTTP interception layer that routes every request under the fake base
URL to :meth:`FakeSoar.handler`. Together they are the T2 contract fixture of
docs/design/07-TEST-STRATEGY.md.

What is modelled is exactly the known-good surface of
docs/design/05-SOAR-API-SURFACE.md §1 and §1.1 (see 08 §4): Basic auth, the two
required query parameters, ``return_level=normal`` on ``query_paged``, AND-within
/ OR-across filters, PATCH optimistic concurrency with ``success:false``, custom
fields under ``properties``, close semantics, incident-scoped manual actions and
the exact invocation body. Nothing outside that list has a route.

All state comes from synthetic fixtures in ``tests/fixtures/soar``.
"""

from __future__ import annotations

import base64
import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

FIXTURES = Path(__file__).parent / "fixtures" / "soar"

ORG_ID = 201
API_KEY_ID = "fake-key-id"
API_KEY_SECRET = "SENTINEL-SECRET-DO-NOT-LEAK-7f3a"
BASE_URL = "https://soar.example.internal"

REQUIRED_PARAMS = {"handle_format": "names", "text_content_output_format": "always_text"}
CLOSE_FIELDS = ("plan_status", "resolution_id", "resolution_summary")


def load_fixture(name: str) -> Any:
    doc = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    assert doc["_fixture"] == "synthetic", f"{name}: fixtures must be labelled synthetic"
    return copy.deepcopy(doc["data"])


@dataclass
class Fault:
    """What to do instead of the normal response for a matching request."""

    status: int | None = None
    body: Any = None
    raw_body: bytes | None = None
    exc: type[httpx.HTTPError] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    times: int | None = None  # None = every time
    chunked: bool = False  # stream raw_body without a Content-Length header


@dataclass
class Recorded:
    method: str
    path: str
    params: dict[str, str]
    headers: dict[str, str]
    json: Any


class FakeSoar:
    def __init__(self, *, session_status: int = 403) -> None:
        self.org_id = ORG_ID
        self.incident: dict[str, Any] = load_fixture("incident_42")
        self.incidents: dict[int, dict[str, Any]] = {42: self.incident}
        self.fields: list[dict[str, Any]] = load_fixture("incident_fields")
        cols = load_fixture("collections")
        self.comments: dict[int, list[dict[str, Any]]] = {
            int(k): v for k, v in cols["comments"].items()
        }
        self.artifacts: dict[int, list[dict[str, Any]]] = {
            int(k): v for k, v in cols["artifacts"].items()
        }
        self.tasks: dict[int, dict[str, Any]] = {
            t["id"]: t for rows in cols["tasks"].values() for t in rows
        }
        self.attachments: dict[int, list[dict[str, Any]]] = {
            int(k): v for k, v in cols["attachments"].items()
        }
        self.incident_actions: dict[int, list[dict[str, Any]]] = {
            int(k): v for k, v in cols["incident_actions"].items()
        }
        self.users: list[dict[str, Any]] = cols["users"]
        self.action_invocations: list[dict[str, Any]] = []
        self.session_status = session_status
        self.faults: list[tuple[str, re.Pattern[str], Fault]] = []
        self.requests: list[Recorded] = []
        self._next_id = 10_000

    # ------------------------------------------------------------------ setup
    def fault(self, method: str, path_regex: str, **kwargs: Any) -> Fault:
        f = Fault(**kwargs)
        self.faults.append((method.upper(), re.compile(path_regex), f))
        return f

    def next_id(self) -> int:
        self._next_id += 1
        return self._next_id

    @property
    def mutating_requests(self) -> list[Recorded]:
        return [r for r in self.requests if r.method != "GET"]

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _json(
        status: int, body: Any = None, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        if body is None:
            return httpx.Response(status, headers=headers)
        return httpx.Response(status, json=body, headers=headers)

    @staticmethod
    def _error(status: int, message: str) -> httpx.Response:
        return httpx.Response(
            status,
            json={
                "success": False,
                "title": None,
                "message": message,
                "hints": [],
                "error_code": "generic",
            },
        )

    @staticmethod
    def _patch_failure(message: str, failures: list[dict[str, Any]]) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": False,
                "title": None,
                "message": message,
                "hints": [],
                "field_failures": failures,
            },
        )

    def _field_def(self, name: str) -> dict[str, Any] | None:
        for f in self.fields:
            if f["name"] == name:
                return f
        return None

    def _get_value(self, inc: dict[str, Any], name: str) -> Any:
        fdef = self._field_def(name)
        if fdef and fdef.get("prefix") == "properties":
            return inc.get("properties", {}).get(name)
        return inc.get(name)

    def _set_value(self, inc: dict[str, Any], name: str, value: Any) -> None:
        fdef = self._field_def(name)
        if fdef and fdef.get("prefix") == "properties":
            inc.setdefault("properties", {})[name] = value
        else:
            inc[name] = value

    # ---------------------------------------------------------------- handler
    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.method.upper()
        path = request.url.path
        params = dict(request.url.params)
        body: Any = None
        content = request.read()
        if content:
            try:
                body = json.loads(content)
            except ValueError:
                body = content
        self.requests.append(Recorded(method, path, params, dict(request.headers), body))

        # Newest fault wins so a test can override an earlier one.
        for fmethod, pattern, fault in reversed(self.faults):
            if fmethod == method and pattern.search(path):
                if fault.times is not None:
                    if fault.times <= 0:
                        continue
                    fault.times -= 1
                if fault.exc is not None:
                    # Note: respx rewrites __cause__ on the way out; a TLS cause cannot be
                    # modelled here (see test_client_base.test_tls_failure_is_reported_as_tls).
                    raise fault.exc("injected", request=request)
                if fault.raw_body is not None:
                    if fault.chunked:
                        return httpx.Response(
                            fault.status or 200,
                            stream=httpx.ByteStream(fault.raw_body),
                            headers={"Transfer-Encoding": "chunked", **fault.headers},
                        )
                    return httpx.Response(
                        fault.status or 200, content=fault.raw_body, headers=fault.headers
                    )
                return self._json(fault.status or 500, fault.body, fault.headers)

        expected = "Basic " + base64.b64encode(f"{API_KEY_ID}:{API_KEY_SECRET}".encode()).decode()
        if request.headers.get("Authorization") != expected:
            return self._error(401, "Unauthorized")

        for key, value in REQUIRED_PARAMS.items():
            if params.get(key) != value:
                return self._error(400, f"fake_soar: missing required query param {key}={value}")

        if path == "/rest/session":
            if self.session_status != 200:
                return self._error(self.session_status, "session not available to API keys")
            return self._json(
                200,
                {
                    "user_id": 7,
                    "user_email": "api-key@soar.example.internal",
                    "user_display_name": "MCP API key",
                    "orgs": [{"id": self.org_id, "name": "Example Org"}],
                },
            )

        org_prefix = f"/rest/orgs/{self.org_id}"
        if not path.startswith(org_prefix + "/"):
            return self._error(404, "fake_soar: no route")
        rest = path[len(org_prefix) :]

        if rest == "/incidents/query_paged" and method == "POST":
            if params.get("return_level") != "normal":
                return self._error(400, "fake_soar: query_paged requires return_level=normal")
            return self._query_paged(body)

        if rest == "/incidents" and method == "POST":
            return self._create_incident(body)

        m = re.fullmatch(r"/incidents/(\d+)", rest)
        if m:
            inc = self.incidents.get(int(m.group(1)))
            if inc is None:
                return self._error(404, "incident not found")
            if method == "GET":
                return self._json(200, inc)
            if method == "PATCH":
                return self._patch_incident(inc, body)
            return self._error(405, "method not allowed")

        m = re.fullmatch(r"/incidents/(\d+)/(comments|artifacts|tasks|attachments|actions)", rest)
        if m:
            inc_id, coll = int(m.group(1)), m.group(2)
            if inc_id not in self.incidents:
                return self._error(404, "incident not found")
            if coll == "tasks":
                if method != "GET":
                    return self._error(405, "method not allowed")
                return self._json(200, [t for t in self.tasks.values() if t["inc_id"] == inc_id])
            if coll == "actions":
                if method != "GET":
                    return self._error(405, "method not allowed")
                return self._json(200, self.incident_actions.get(inc_id, []))
            if coll == "attachments":
                if method != "GET":
                    return self._error(405, "method not allowed")
                return self._json(200, self.attachments.get(inc_id, []))
            store = getattr(self, coll).setdefault(inc_id, [])
            if method == "GET":
                return self._json(200, store)
            if method == "POST" and coll == "comments":
                text = body.get("text") if isinstance(body, dict) else None
                if not isinstance(text, dict) or "content" not in text or "format" not in text:
                    return self._error(400, "comment text must be a TextContentDTO")
                created = {
                    "id": self.next_id(),
                    "parent_id": body.get("parent_id"),
                    "text": text["content"],
                    "create_date": 1758010000000,
                    "user_name": "MCP API key",
                    "children": [],
                }
                store.append(created)
                return self._json(200, created)
            if method == "POST" and coll == "artifacts":
                if not isinstance(body, dict) or "type" not in body or "value" not in body:
                    return self._error(400, "artifact requires type and value")
                desc = body.get("description")
                created = {
                    "id": self.next_id(),
                    "type": body["type"],
                    "value": body["value"],
                    "description": desc["content"] if isinstance(desc, dict) else desc,
                    "created": 1758010000000,
                    "hits": [],
                }
                store.append(created)
                return self._json(200, created)
            return self._error(405, "method not allowed")

        m = re.fullmatch(r"/incidents/(\d+)/action_invocations", rest)
        if m and method == "POST":
            inc_id = int(m.group(1))
            if inc_id not in self.incidents:
                return self._error(404, "incident not found")
            if not isinstance(body, dict) or set(body) != {"action_id"}:
                return self._error(400, 'fake_soar: body must be exactly {"action_id": N}')
            if not isinstance(body["action_id"], int):
                return self._error(400, "action_id must be an integer")
            known = {a["id"] for a in self.incident_actions.get(inc_id, [])}
            if body["action_id"] not in known:
                return self._error(404, "action not available on this incident")
            self.action_invocations.append({"incident_id": inc_id, "action_id": body["action_id"]})
            return httpx.Response(200)

        m = re.fullmatch(r"/tasks/(\d+)", rest)
        if m and method == "PATCH":
            task = self.tasks.get(int(m.group(1)))
            if task is None:
                return self._error(404, "task not found")
            return self._patch_task(task, body)

        if rest == "/users" and method == "GET":
            return self._json(200, self.users)
        if rest == "/types/incident/fields" and method == "GET":
            return self._json(200, self.fields)

        return self._error(404, "fake_soar: no route")

    # ------------------------------------------------------------- incidents
    def _create_incident(self, body: Any) -> httpx.Response:
        if not isinstance(body, dict):
            return self._error(400, "body must be an object")
        if not body.get("name"):
            return self._error(400, "name is required")
        if "discovered_date" not in body:
            return self._error(400, "discovered_date is required")
        new_id = self.next_id()
        inc: dict[str, Any] = {
            "id": new_id,
            "vers": 1,
            "plan_status": "A",
            "severity_code": "Low",
            "incident_type_ids": [],
            "owner_id": None,
            "phase_id": "Initial",
            "properties": {},
            "create_date": 1758010000000,
            "start_date": None,
            "due_date": None,
            "end_date": None,
            "inc_last_modified_date": 1758010000000,
            "resolution_id": None,
            "resolution_summary": None,
        }
        for key, value in body.items():
            if key == "properties" and isinstance(value, dict):
                inc["properties"].update(value)
            elif key == "description" and isinstance(value, dict):
                inc["description"] = value.get("content")
            else:
                inc[key] = value
        self.incidents[new_id] = inc
        return self._json(200, inc)

    def _patch_incident(self, inc: dict[str, Any], body: Any) -> httpx.Response:
        if not isinstance(body, dict) or "version" not in body or "changes" not in body:
            return self._error(400, "PATCH requires version and changes")
        if body["version"] != inc["vers"]:
            return self._patch_failure("Incident has been modified by another user", [])
        failures: list[dict[str, Any]] = []
        for change in body["changes"]:
            name = change["field"]["name"]
            if self._field_def(name) is None:
                return self._error(400, f"unknown field {name}")
            current = self._get_value(inc, name)
            old = change["old_value"].get("object")
            if current != old:
                failures.append(
                    {"field": name, "your_original_value": old, "actual_current_value": current}
                )
        if failures:
            return self._patch_failure("Field values have changed", failures)

        # Compute the would-be state to enforce close semantics before applying.
        candidate = copy.deepcopy(inc)
        for change in body["changes"]:
            self._set_value(candidate, change["field"]["name"], change["new_value"].get("object"))
        if candidate.get("plan_status") == "C" and inc.get("plan_status") != "C":
            missing = [f for f in CLOSE_FIELDS[1:] if not candidate.get(f)]
            for fdef in self.fields:
                close_required_custom = (
                    fdef.get("required") == "close" and fdef.get("prefix") == "properties"
                )
                if close_required_custom and not candidate.get("properties", {}).get(fdef["name"]):
                    missing.append(f"properties.{fdef['name']}")
            if missing:
                return self._patch_failure(
                    "Closing requires: " + ", ".join(missing),
                    [
                        {"field": m, "your_original_value": None, "actual_current_value": None}
                        for m in missing
                    ],
                )
            candidate["end_date"] = 1758020000000
        candidate["vers"] += 1
        candidate["inc_last_modified_date"] = 1758020000000
        inc.clear()
        inc.update(candidate)
        return self._json(
            200,
            {"success": True, "title": None, "message": None, "hints": [], "field_failures": []},
        )

    def _patch_task(self, task: dict[str, Any], body: Any) -> httpx.Response:
        if not isinstance(body, dict) or "version" not in body or "changes" not in body:
            return self._error(400, "PATCH requires version and changes")
        if body["version"] != task["vers"]:
            return self._patch_failure("Task has been modified by another user", [])
        for change in body["changes"]:
            name = change["field"]["name"]
            if name not in task:
                return self._error(400, f"unknown task field {name}")
            if task[name] != change["old_value"].get("object"):
                return self._patch_failure(
                    "Field values have changed",
                    [
                        {
                            "field": name,
                            "your_original_value": change["old_value"].get("object"),
                            "actual_current_value": task[name],
                        }
                    ],
                )
        for change in body["changes"]:
            task[change["field"]["name"]] = change["new_value"].get("object")
        task["vers"] += 1
        return self._json(
            200,
            {"success": True, "title": None, "message": None, "hints": [], "field_failures": []},
        )

    # ---------------------------------------------------------------- search
    def _query_paged(self, body: Any) -> httpx.Response:
        if not isinstance(body, dict):
            return self._error(400, "body must be an object")
        rows = list(self.incidents.values())
        filters = body.get("filters") or []
        if filters:
            # Conditions within a filter are ANDed; separate filters are ORed.
            rows = [
                r
                for r in rows
                if any(
                    all(self._matches(r, cond) for cond in (flt.get("conditions") or []))
                    for flt in filters
                )
            ]
        for sort in reversed(body.get("sorts") or []):
            rows.sort(
                key=lambda r: (
                    self._get_path(r, sort["field_name"]) is None,
                    self._get_path(r, sort["field_name"]) or 0,
                ),
                reverse=sort.get("type") == "desc",
            )
        start = int(body.get("start", 0))
        length = int(body.get("length", 50))
        return self._json(
            200,
            {
                "recordsTotal": len(self.incidents),
                "recordsFiltered": len(rows),
                "data": rows[start : start + length],
            },
        )

    def _get_path(self, row: dict[str, Any], name: str) -> Any:
        if name.startswith("properties."):
            return row.get("properties", {}).get(name.split(".", 1)[1])
        return row.get(name)

    def _matches(self, row: dict[str, Any], cond: dict[str, Any]) -> bool:
        value = self._get_path(row, cond["field_name"])
        method = cond["method"]
        target = cond.get("value")
        if method == "equals":
            return value == target
        if method == "not_equals":
            return value != target
        if method == "in":
            return value in (target or [])
        if method == "not_in":
            return value not in (target or [])
        if method == "contains":
            if isinstance(value, list):
                return target in value
            return isinstance(value, str) and str(target).lower() in value.lower()
        if method == "not_contains":
            return not self._matches(row, {**cond, "method": "contains"})
        if method == "gte":
            return value is not None and value >= target
        if method == "gt":
            return value is not None and value > target
        if method == "lte":
            return value is not None and value <= target
        if method == "lt":
            return value is not None and value < target
        if method == "has_a_value":
            return value not in (None, "", [])
        if method == "does_not_have_a_value":
            return value in (None, "", [])
        raise AssertionError(f"fake_soar: unsupported filter method {method}")
