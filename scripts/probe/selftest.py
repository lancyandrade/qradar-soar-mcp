"""Offline self-test of the P2-00 probe tooling. No network, no appliance.

    uv run python scripts/probe/selftest.py

It proves, against an in-process fake appliance that stuffs every response with
environment-like values:

1. the HTTP policy refuses every write, every POST outside the approved read-only
   ones (three from P2-00, one exact-body, once-only query from P2-00b), and every
   query body that is not pure paging/sorting/search criteria, before anything is
   sent;
2. the verifier rejects each category of environment-specific text and the
   writer refuses to put a rejected artefact on disk;
3. shapes never carry administrator-chosen names or appliance values;
4. a full run of the probe plan leaves none of the connection values, fake
   private addresses, e-mail addresses, host names, UUIDs or object ids in any
   fixture, in the ledger, or in what is printed;
5. a transport failure is reported as a category, never with the URL.
"""

from __future__ import annotations

import html
import json
import ssl
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import probe_00b
import probe_p2_03
import probe_p2_04
import shape_request
import task_candidate
import task_experiment
from probe import EXPECTED_VERSION, build_plan, run, smoke
from probe_env import ProbeEnv, _dotenv
from safe_http import MAX_QUERY_LENGTH as MAX_LEN
from safe_http import ProbePolicyError, ReadOnlyClient
from sanitise import (
    EnumCollector,
    UnsafeArtefactError,
    dump_verified,
    safe_text,
    shape_of,
    verify_clean,
    violations,
)
from tls_check import categorise

Facts = dict[str, Any]

# Fake, obviously synthetic connection values. Addresses are assembled so that this
# file itself stays clean for scripts/check_no_secrets.py.
PRIVATE_IP = ".".join(["10", "20", "30", "40"])
OTHER_IP = ".".join(["192", "168", "7", "9"])
HOST = "soar-selftest." + "corp" + ".lan"
ORG = "7342"
KEY_ID = "0f0f0f0f-1111-2222-3333-444444444444"
SECRET = "SENTINEL-SECRET-DO-NOT-LEAK-7f3a"  # noqa: S105 - the repo's synthetic sentinel
EMAIL = "analyst.one@" + "selftest-corp.lan"
INCIDENT_ID, PLAYBOOK_ID, ATTACHMENT_ID = "990017", "880023", "770031"

ENV = ProbeEnv(base_url=f"https://{HOST}", org_id=ORG, key_id=KEY_ID, key_secret=SECRET)
# Administrator-chosen names, deliberately shaped to match the probe's own key searches
# ("playbook", "function", "result", "xml", "perm", ...): none may be reported by name.
HOSTILE_FIELD = "acme_playbook_function_result_xml_perm"
HOSTILE_TABLE = "acme_workflow_output_table"
PERMISSION_NAMES = ["create_acme_widget", "delete_all_acme_things", "read_acme_ledger",
                    "admin_acme", "run_acme_invocations", "acme_special"]  # fmt: skip
FORBIDDEN = (HOST, PRIVATE_IP, OTHER_IP, KEY_ID, SECRET, EMAIL, INCIDENT_ID, PLAYBOOK_ID,
             *PERMISSION_NAMES,
             ATTACHMENT_ID, "acme_ticket_ref", "acme_site", HOSTILE_FIELD, HOSTILE_TABLE,
             "Payroll breach", "jdoe")  # fmt: skip

# P2-00b: reference pages laid out like the appliance's, with live values planted in the
# prose, in a type cell and in a link, none of which may reach a fixture or the terminal.
_TASK_PUT = "PUT /orgs/{org_id}/tasks/{task_id}"
TASK_REST_PAGE = (
    f"<ul><li>{_TASK_PUT}</li></ul><h2>{_TASK_PUT}</h2><p>Saves a task on {HOST}.</p>"
    "<table><caption>Request Parameters</caption><tr><td>handle_format</td><td>header</td>"
    f"<td>see https://{HOST}/x</td></tr><tr><td>task_id</td><td>path</td><td>id</td></tr></table>"
    '<table><caption>Request Body</caption><tr><td>application/json</td><td><a href="'
    f'json_TaskDTO.html">TaskDTO</a> (JSON)</td><td>for {EMAIL}</td></tr></table>'
    "<table><caption>Response Codes</caption><tr><td>200</td><td>Success</td></tr>"
    f"<tr><td>409</td><td>Conflicting PUT on {PRIVATE_IP}</td></tr></table>"
    '<table><caption>Response Body</caption><tr><td>application/json</td><td><a href="'
    'json_StatusDTO.html">StatusDTO</a></td><td>status</td></tr></table>'
    "<h2>GET /orgs/{org_id}/tasks/{task_id}/instructions</h2>"
    '<table><caption>Response Body</caption><tr><td>x</td><td><a href="json_WrongDTO.html">'
    "WrongDTO</a></td><td>belongs to the next endpoint</td></tr></table>"
)
TASK_DTO_PAGE = (
    "<table><tr><th>name</th><th>data type</th><th>constraints</th><th>description</th></tr>"
    f"<tr><td>status</td><td>string</td><td></td><td>The status, as on {HOST}.</td></tr>"
    "<tr><td>id</td><td>number</td><td></td><td>The ID. This is a readonly property.</td></tr>"
    "<tr><td>name</td><td>string</td><td></td><td>A property that is called name.</td></tr>"
    "<tr><td>private</td><td>object</td><td></td><td>This field is only used during create."
    f"</td></tr><tr><td>owner</td><td>{HOST}</td><td>{PRIVATE_IP}</td><td>x</td></tr>"
    f"<tr><td>{HOST}</td><td>string</td><td></td><td>not a property name</td></tr></table>"
)

# P2-00b: a published description whose prose carries a live value in one place.
SWAGGER_DOC = {
    "swagger": "2.0",
    "paths": {"/orgs/{org_id}/tasks/{task_id}": {"put": {"summary": "Saves a task."}}},
    "definitions": {
        "TaskDTO": {
            "description": "Represents a task object.",
            "properties": {
                "required": {"type": "boolean", "description": "true if the task is required."},
                "name": {"type": "string", "description": f"required by {HOST} at {PRIVATE_IP}"},
            },
        }
    },
}

failures: list[str] = []


def check(condition: bool, label: str) -> None:
    print(("PASS  " if condition else "FAIL  ") + label)
    if not condition:
        failures.append(label)


def nasty_row(i: int) -> dict[str, Any]:
    return {
        "id": int(INCIDENT_ID) + i,
        "uuid": KEY_ID,
        "name": f"Payroll breach on {HOST}",
        "description": {"format": "text", "content": f"see https://{HOST}/x from {PRIVATE_IP}"},
        "creator": {"email": EMAIL, "display_name": "jdoe"},
        "input_type": "select",
        "type_id": 8 if i else 0,
        "vers": 3,
        "properties": {"acme_ticket_ref": f"T-{i}", "acme_site": OTHER_IP, HOSTILE_FIELD: "open"},
        "fields": {HOSTILE_FIELD: {"input_type": "text"}},
        "view_items": [{"content": KEY_ID, "field_type": "__function"}],
        "content": {"xml": "<definitions>" + HOST + "</definitions>"},
        "children": [],
        # P2-00b: a carried manual action and an object-level permission map, both hostile.
        "actions": [{"id": 5, "name": f"Isolate {HOST}", "enabled": True}],
        "perms": {"read": True, "write": True},
        "status": "O",
        "inc_training": False,
        "plan_status": "A",
        "inc_id": int(INCIDENT_ID),
    }


class FakeAppliance:
    def __init__(
        self,
        session_status: int = 200,
        *,
        apikeys_status: int = 200,
        barren: bool = False,
        denied: dict[str, int] | None = None,
        overlay: dict[str, Any] | None = None,
        tree: Any = None,
    ) -> None:
        self.session_status = session_status
        self.apikeys_status = apikeys_status
        self.barren = barren  # P2-00b: many incidents, none with anything to find
        self.denied = denied or {}  # P2-00b: path suffix -> status, for objects a key cannot see
        self.overlay = overlay or {}  # P2-00b: keys laid over every single-object read
        self.tree = tree  # P2-00b: what GET .../tasktree answers
        self.format_headers_seen: list[dict[str, str]] = []
        self.seen: list[tuple[str, str]] = []
        self.bodies: list[Any] = []

    def _barren(self, request: httpx.Request) -> httpx.Response | None:
        method, path = request.method, request.url.path.rstrip("/")
        if method == "POST" and path.endswith("/incidents/query_paged"):
            body = json.loads(request.content or b"null")
            self.bodies.append(body)
            rows = [{"id": int(INCIDENT_ID) + n, "name": f"Payroll breach {n}"} for n in range(12)]
            page = {"recordsTotal": 12, "recordsFiltered": 12, "data": rows[: body["length"]]}
            return httpx.Response(200, json=page)
        parts = path.split("/incidents/", 1)[-1].split("/") if "/incidents/" in path else []
        if len(parts) == 1 and parts[0].isdigit():
            return httpx.Response(200, json={"id": int(parts[0]), "actions": [], "name": HOST})
        if len(parts) == 2 and parts[0].isdigit():
            return httpx.Response(200, json=[])
        return None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.seen.append((method, path))
        self.format_headers_seen.append(
            {k: v for k, v in request.headers.items()
             if k in ("handle_format", "text_content_output_format")}
        )  # fmt: skip
        if self.barren and (barren := self._barren(request)) is not None:
            return barren
        if path.endswith("/tasktree") and self.tree is not None:
            return httpx.Response(200, json=self.tree)
        for suffix, status in self.denied.items():
            if path.endswith(suffix):
                hidden = {"success": False, "message": f"no {KEY_ID} at {HOST} for {path}"}
                return httpx.Response(status, json=hidden)
        if path.endswith("/apikeys") and self.apikeys_status != 200:
            denied = {"success": False, "message": f"key {KEY_ID} denied"}
            return httpx.Response(self.apikeys_status, json=denied)
        if path.startswith("/docs/rest-api/index"):
            return httpx.Response(200, html='<a href="resource_PlaybookREST.html">x</a>')
        if path.startswith("/docs/rest-api/ui/swagger"):
            return httpx.Response(200, json=SWAGGER_DOC)
        if path.startswith("/docs/rest-api/resource_TaskREST"):
            return httpx.Response(200, html=TASK_REST_PAGE)
        if path.startswith("/docs/rest-api/json_TaskDTO"):
            return httpx.Response(200, html=TASK_DTO_PAGE)
        if path.startswith("/docs/rest-api/resource_PlaybookREST"):
            body = (
                "<h2>GET /orgs/{org_id}/playbooks</h2><h2>POST /orgs/{org_id}/playbooks/query_paged"
                f"</h2><h2>GET /orgs/{ORG}/leaky/{INCIDENT_ID}</h2>"
                '<table><tr><td>application/json</td><td><a href="json_TaskDTO.html">TaskDTO</a>'
                f"</td></tr></table><p>curl https://{HOST}/rest</p>"
            )
            return httpx.Response(200, html=body)
        if path == "/rest/session":
            if self.session_status != 200:
                denied = {"success": False, "message": f"key {KEY_ID} denied at {request.url}"}
                return httpx.Response(self.session_status, json=denied)
            who = {"user_email": EMAIL, "user_display_name": "jdoe", "orgs": [nasty_row(0)]}
            return httpx.Response(200, json=who)
        if path == "/rest/const":
            return httpx.Response(200, json={"server_version": {"version": EXPECTED_VERSION}})
        if path.endswith("/types"):
            table = {f"{HOSTILE_TABLE}_{n}": nasty_row(n) for n in range(10)}
            return httpx.Response(200, json=table)
        if path.endswith("/contents"):
            return httpx.Response(
                200,
                content=b"%PDF secret body " + SECRET.encode(),
                headers={
                    "content-type": "application/pdf",
                    "content-disposition": f'attachment; filename="{HOST}-payroll.pdf"',
                },
            )
        if method == "POST" and path.rstrip("/").endswith("/configurations/exports"):
            sections = ("playbooks", "functions", "scripts", "workflows", "actions",
                        "message_destinations", "incident_types", "fields", "types")  # fmt: skip
            doc = {k: [nasty_row(0), nasty_row(1)] for k in sections}
            return httpx.Response(200, json={**doc, "export_format_version": 2})
        if path.rstrip("/").endswith("/query_paged"):
            if method != "POST":
                return httpx.Response(405, headers={"allow": "POST"}, json={"message": "no"})
            self.bodies.append(json.loads(request.content or b"null"))
            page = {"recordsTotal": 2, "recordsFiltered": 2, "data": [nasty_row(0)]}
            return httpx.Response(200, json=page)
        if path.endswith(("/history", "/newsfeed", "/groups")):
            return httpx.Response(404, json={"success": False, "message": f"no {request.url}"})
        if path.endswith("/apikeys"):
            other = {"apikey_id": "someone-else", "permissions": ["read_acme_ledger"]}
            mine = {"apikey_id": KEY_ID, "enabled": True, "permissions": PERMISSION_NAMES}
            return httpx.Response(200, json={"entities": [other, mine]})
        if path.endswith("/manual_input_form"):
            return httpx.Response(403, json={"success": False, "message": f"denied {KEY_ID}"})
        tail = path.rsplit("/", 1)[-1]
        if tail.isdigit():
            return httpx.Response(200, json={**nasty_row(1), **self.overlay})
        return httpx.Response(200, json=[nasty_row(0), nasty_row(1)])


def new_client(handler: Any) -> ReadOnlyClient:
    return ReadOnlyClient(ENV, ssl.create_default_context(), transport=httpx.MockTransport(handler))


QUERY_OK = {"filters": [], "start": 0, "length": 1}
EXPORT_OK = {"layouts": True, "actions": True, "phases_and_tasks": True}
Row = tuple[str, str, str, Any, dict[str, str] | None]


def refusal_matrix(org: str) -> list[Row]:
    """(why, method, path, body, extra query params): every one must be refused."""
    inc_q = f"{org}/incidents/query_paged"
    pb_q = f"{org}/playbooks/query_paged"
    export = f"{org}/configurations/exports"
    cond = {"field_name": "plan_status", "method": "equals", "value": "A"}
    rows: list[Row] = []
    # every verb other than GET/POST, on every path including the three permitted ones
    for verb in ("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"):
        for path in (inc_q, pb_q, export, f"{org}/incidents/1", f"{org}/tasks/1",
                     f"{org}/playbooks/1", f"{org}/configurations/imports/1"):  # fmt: skip
            rows.append((f"{verb} is never permitted", verb, path, QUERY_OK, None))
    # every other POST, including other paths that merely contain "query_paged"
    for path in (
        f"{org}/incidents", f"{org}/incidents/1/comments", f"{org}/incidents/1/artifacts",
        f"{org}/incidents/1/action_invocations", f"{org}/incidents/1/attachments",
        f"{org}/configurations/imports", f"{org}/playbooks", f"{org}/playbooks/imports",
        f"{org}/playbooks/exports", f"{org}/scripts", f"{org}/functions", f"{org}/workflows",
        f"{org}/actions", f"{org}/tasks/query_paged", f"{org}/artifacts/query_paged",
        f"{org}/incidents/1/query_paged", f"{org}/incidents/query_paged/extra",
        f"{org}/playbooks/1/query_paged", "/rest/orgs/1/incidents/query_paged",
        "/rest/incidents/query_paged", f"{org}/incidents/query_paged/../../incidents",
        f"{org}//incidents/query_paged", f"{org}/incidents/query_paged?x=1",
    ):  # fmt: skip
        rows.append(("POST path is not on the allow-list", "POST", path, QUERY_OK, None))
    # a permitted query path whose body is not purely paging / sorting / search criteria
    bad_bodies: list[Any] = [
        None, [], "x", {}, {"length": 0}, {"length": MAX_LEN + 1}, {"length": True},
        {"length": 1, "start": -1}, {"length": 1, "name": "x"}, {"length": 1, "plan_status": "C"},
        {"length": 1, "owner_id": "x"}, {"length": 1, "action_id": 1},
        {"length": 1, "status": "enabled"}, {"length": 1, "changes": []},
        {"length": 1, "version": 3},
        {"length": 1, "filters": [{"conditions": [], "changes": []}]},
        {"length": 1, "filters": [{"conditions": [{**cond, "new_value": {"object": "C"}}]}]},
        {"length": 1, "filters": [{"conditions": [{**cond, "method": "set"}]}]},
        {"length": 1, "filters": [{"conditions": [{**cond, "value": {"object": "C"}}]}]},
        {"length": 1, "filters": {"conditions": []}},
        {"length": 1, "sorts": [{"field_name": "id", "type": "asc", "apply": True}]},
        {"length": 1, "sorts": [{"field_name": "id", "type": "sideways"}]},
    ]  # fmt: skip
    for path in (inc_q, pb_q):
        for body in bad_bodies:
            rows.append(("query body is not read-only criteria", "POST", path, body, None))
        rows.append(("unexpected query parameter", "POST", path, QUERY_OK, {"force": "true"}))
    for body in (
        None,
        {"layouts": True, "import": True},
        {"layouts": "yes"},
        {"status": "ACCEPTED"},
    ):
        rows.append(("export body is not the three switches", "POST", export, body, None))
    rows.append(("unexpected query parameter", "POST", export, EXPORT_OK, {"commit": "true"}))
    # GET: no body, no escape from /rest/ and /docs/, no smuggled query string
    rows += [
        ("GET may not carry a body", "GET", f"{org}/incidents/1", {"x": 1}, None),
        ("GET outside /rest/ and /docs/", "GET", "/admin/console", None, None),
        ("malformed path", "GET", f"{org}/incidents?x=1", None, None),
        ("malformed path", "GET", f"{org}/../../etc", None, None),
    ]
    return rows


def test_policy() -> None:
    fake = FakeAppliance()
    client = new_client(fake)
    org = f"/rest/orgs/{ORG}"
    matrix = refusal_matrix(org)
    problems = []
    for why, method, path, body, params in matrix:
        try:
            client.request(method, path, "template", json_body=body, params=params)
        except ProbePolicyError as exc:
            if any(bad in str(exc) for bad in (ORG, "plan_status", "sideways", "ACCEPTED")):
                problems.append(f"refusal echoed a request value ({why})")
            continue
        problems.append(f"{method} {path.replace(ORG, '{org}')} ({why})")
    check(
        problems == [], f"policy: all {len(matrix)} forbidden requests are refused {problems[:3]}"
    )
    check(fake.seen == [] and client.requests_sent == 0, "policy: refused before any network I/O")
    check(len(client.refused) == len(matrix), "policy: every refusal is recorded for the ledger")

    paged = {"return_level": "normal"}
    allowed: list[tuple[str, str, Any, dict[str, str] | None]] = [
        ("GET", f"{org}/playbooks", None, None),
        ("GET", "/rest/session", None, None),
        ("GET", "/docs/rest-api/index.html", None, None),
        ("POST", f"{org}/incidents/query_paged", QUERY_OK, paged),
        ("POST", f"{org}/playbooks/query_paged", {"length": 1}, paged),
        ("POST", f"{org}/incidents/query_paged/", {
            "filters": [{"conditions": [{"field_name": "plan_status", "method": "in",
                                         "value": ["A", "C"]}]}],
            "sorts": [{"field_name": "create_date", "type": "desc"}],
            "start": 0, "length": 5}, paged),
        ("POST", f"{org}/configurations/exports", EXPORT_OK, None),
        ("POST", f"{org}/configurations/exports/", {}, None),
    ]  # fmt: skip
    for method, path, body, params in allowed:
        client.request(method, path, "t", json_body=body, params=params)
    check(len(fake.seen) == len(allowed), "policy: GET and the three P2-00 read-only POSTs pass")
    client.close()


def test_verifier() -> None:
    literals = ENV.literals()
    samples = {
        "ip address": f"host {PRIVATE_IP} ok",
        "e-mail address": f"mail {EMAIL}",
        "internal host name": "see " + "db01." + "corp",
        "url": "https://" + "intranet-portal.selftest.org" + "/x",
        "uuid": KEY_ID,
        "long token": "t=" + "A1b2C3d4" * 5,
        "literal org id": f"/rest/orgs/{ORG}/incidents",
        "literal api key secret": f"secret {SECRET}",
    }
    for category, text in samples.items():
        found = {c for _, c in violations(text, literals)}
        check(category in found, f"verifier: catches {category}")
    clean = (
        f"QRadar SOAR {EXPECTED_VERSION}; /rest/orgs/{{org_id}}/playbooks; soar.example.internal; "
        "203.0.113.10; user@example.com; 127.0.0.1"
    )
    check(violations(clean, literals) == [], "verifier: version string and placeholders pass")
    benign = (
        "and_within_one_filter_is_intersection /orgs/{org_id}/configurations/exports/history "
        "/orgs/{org_id}/message_destinations/destination_queue_depth_history_long"
    )
    check(violations(benign, literals) == [], "verifier: long identifiers and paths pass")
    hexish = "sha=" + "0123456789abcdef" * 4
    check({c for _, c in violations(hexish, literals)} == {"long token"},
          "verifier: a long hex digest is still a long token")  # fmt: skip
    check("withheld" in safe_text(f"x {SECRET}", literals), "terminal guard withholds a secret")
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "bad.json"
        try:
            dump_verified(target, {"name": f"leak {PRIVATE_IP}"}, literals)
            wrote = True
        except UnsafeArtefactError as exc:
            wrote = False
            check(PRIVATE_IP not in str(exc), "writer: refusal message does not echo the value")
        check(not wrote and not target.exists(), "writer: an unsafe artefact never reaches disk")


def test_shape() -> None:
    enums = EnumCollector()
    shape = shape_of([nasty_row(0), {**nasty_row(1), "extra": 1}], enums=enums)
    text = json.dumps(shape)
    check(all(bad not in text for bad in FORBIDDEN), "shape: no value or custom name survives")
    check(shape[0]["properties"] == {"<name>": "str"}, "shape: custom fields collapse to <name>")
    check("extra?" in shape[0], "shape: keys absent from some rows are marked optional")
    kept = enums.to_json()
    check(kept["input_type"] == ["select", "text"] and kept["type_id"] == [0, 8]
          and kept["format"] == ["text"], "enums: schema tokens kept")  # fmt: skip
    custom = EnumCollector()
    shape_of({"properties": {"status": "Compromised", "format": "Secretword"}}, enums=custom)
    check(custom.to_json() == {}, "enums: a custom field that is NAMED like an enum key is ignored")
    flood = EnumCollector()
    shape_of([{"status": f"word{n}"} for n in range(30)], enums=flood)
    check(flood.to_json() == {} and flood.not_enums == {"status"},
          "enums: a key with many distinct values is not an enum and keeps nothing")  # fmt: skip
    prose = EnumCollector()
    shape_of({"status": "two words"}, enums=prose)
    check(prose.to_json() == {}, "enums: prose is never kept")
    hostile = EnumCollector()
    shape_of({"input_type": f"select {PRIVATE_IP}", "status": EMAIL}, enums=hostile)
    check(hostile.to_json() == {} and hostile.rejected, "enums: a non-token value is rejected")
    table = shape_of({f"acme_table_{n}": nasty_row(n) for n in range(10)})
    check(list(table) == ["<name>"], "shape: a name-keyed map collapses without being told")
    check(shape_of({"weird key 10.1": 1}) == {"<key>": "int"}, "shape: odd key names are masked")


def test_full_run() -> None:
    fake = FakeAppliance()
    client = new_client(fake)
    printed: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
        import probe

        probe.ROOT = Path(tmp)
        rows = run(ENV, client, out, with_export=True, echo=printed.append)
        files = sorted(out.glob("*.json"))
        blob = "\n".join(p.read_text(encoding="utf-8") for p in files)
        check(len(files) >= len(build_plan(True)) - 2, f"run: {len(files)} artefacts written")
        for path in files:
            verify_clean(path.read_text(encoding="utf-8"), ENV.literals(), what=path.name)
        check(True, "run: every written artefact passes the verifier")
        leaked = [bad for bad in FORBIDDEN if bad in blob or bad in "\n".join(printed)]
        check(leaked == [], "run: no connection value, address, name or id in files or output")
        check(f"/orgs/{ORG}/" not in blob and "/leaky/" not in blob,
              "run: a documented path carrying digits is dropped")  # fmt: skip
        ledger = json.loads((out / "_ledger.json").read_text(encoding="utf-8"))
        documented = ledger["documented_endpoints"]["PlaybookREST"]
        check(["POST", "/orgs/{org_id}/playbooks/query_paged"] in documented,
              "run: on-box docs are parsed")  # fmt: skip
        keys = json.loads((out / "apikeys.json").read_text(encoding="utf-8"))["_facts"]
        check(keys["own_key_found"] and keys["own_key_has_mutating_permissions"]
              and keys["own_permission_categories"]["uncategorised"] == "1-9",
              "run: the key's permissions are reported as categories and buckets only")  # fmt: skip
        scan = json.loads((out / "attachment_scan.json").read_text(encoding="utf-8"))["_facts"]
        check(scan["attachment_found"] and scan["incidents_looked_at"] == 1 and scan["limit"] == 10
              and scan["stopped_at_first_attachment"],
              "run: the attachment hunt stops at the first hit, within its ceiling")  # fmt: skip
        contents = json.loads((out / "attachment_contents.json").read_text(encoding="utf-8"))
        check(contents["_facts"]["body_was_not_read"] and contents["shape"] is None,
              "run: attachment content is never read, only its headers")  # fmt: skip
        check(contents["_content_type"] == "application/pdf", "run: content type is recorded")
    non_get = sorted(
        {
            (m, p.rstrip("/").rsplit("/", 2)[-2:][0] + "/" + p.rstrip("/").rsplit("/", 1)[-1])
            for m, p in fake.seen
            if m != "GET"
        }
    )
    check(non_get == [("POST", "configurations/exports"), ("POST", "incidents/query_paged"),
                      ("POST", "playbooks/query_paged")],
          "run: the only non-GETs sent were the three read-only POSTs")  # fmt: skip
    lengths = sorted(b["length"] for b in fake.bodies)
    criteria_only = all(set(b) <= {"filters", "sorts", "start", "length"} for b in fake.bodies)
    one_row_each = lengths[-1] == 10 and set(lengths[:-1]) == {1}
    check(
        criteria_only and one_row_each,
        "run: every query asks for ONE row, except the one 10-row attachment hunt",
    )
    check(
        any(r["status"] == 405 and r["allow"] == "POST" for r in rows), "run: 405 + Allow recorded"
    )
    check(any(r["status"] == 403 for r in rows) and any(r["status"] == 404 for r in rows),
          "run: 403 and 404 are recorded as results")  # fmt: skip
    client.close()


def test_smoke() -> None:
    session = ("GET", "/rest/session")
    query = ("POST", f"/rest/orgs/{ORG}/incidents/query_paged")
    for status, expected in ((200, [session]), (403, [session, query])):
        fake = FakeAppliance(session_status=status)
        client = new_client(fake)
        printed: list[str] = []
        smoke(ENV, client, echo=printed.append)
        text = " | ".join(printed)
        check(
            fake.seen == expected, f"smoke: session {status} -> exactly {len(expected)} request(s)"
        )
        check(not [bad for bad in FORBIDDEN if bad in text],
              f"smoke: session {status} -> output is status and shape only")  # fmt: skip
        check("status=" in text and "top_level_keys=" in text, "smoke: status and key names shown")
        client.close()
    check(fake.bodies == [{"filters": [], "start": 0, "length": 1}],
          "smoke: the fallback query asks for one row and carries no criteria")  # fmt: skip


def test_dotenv_encodings() -> None:
    body = "# comment" + chr(10) + "SOAR_ORG_ID='7342'" + chr(10) + "UNRELATED=1" + chr(10)
    with tempfile.TemporaryDirectory() as tmp:
        for encoding in ("utf-8", "utf-8-sig", "utf-16"):
            path = Path(tmp) / f"env-{encoding}"
            path.write_text(body, encoding=encoding)
            label = f"env: a {encoding} .env is read; quotes stripped, unrelated names ignored"
            check(_dotenv(path) == {"SOAR_ORG_ID": "7342"}, label)
    check("7342" not in repr(ENV) and SECRET not in repr(ENV), "env: repr never shows a value")


def test_errors_carry_no_url() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    client = new_client(boom)
    r = client.request("GET", f"/rest/orgs/{ORG}/playbooks", "/rest/orgs/{org_id}/playbooks")
    check(r.error == "ConnectError" and HOST not in json.dumps(r.ledger_row()),
          "errors: a transport failure is a category, never a URL")  # fmt: skip
    tls = ssl.SSLCertVerificationError("hostname mismatch for " + HOST)
    tls.verify_code = 62
    wrapped = httpx.ConnectError("x")
    wrapped.__cause__ = tls
    check(
        categorise(wrapped) == "host name mismatch", "errors: TLS failures map to fixed categories"
    )
    client.close()


def _non_get(fake: FakeAppliance) -> list[tuple[str, str]]:
    sent = {(m, "/".join(p.rstrip("/").rsplit("/", 2)[-2:])) for m, p in fake.seen if m != "GET"}
    return sorted(sent)


def test_00b_tls() -> None:
    """P2-00b never connects unverified: no pinned mode, no verify=false, no bundle guessing."""
    context, label = probe_00b.verified_context(ENV)
    check(
        label == "python_default" and context.check_hostname
        and context.verify_mode is ssl.CERT_REQUIRED,
        "00b tls: the default context checks the chain and the host name",
    )  # fmt: skip
    refused = {
        "lab-pinned mode": replace(ENV, tls_mode="lab-pinned"),
        "SOAR_VERIFY_SSL=false": replace(ENV, verify_ssl="false"),
        "plain http": replace(ENV, base_url=f"http://{HOST}"),
        "two different bundles": replace(ENV, ca_bundle="one.pem", soar_ca_bundle="two.pem"),
        "an unreadable bundle": replace(ENV, soar_ca_bundle="does-not-exist.pem"),
    }
    for why, env in refused.items():
        try:
            probe_00b.verified_context(env)
            stopped, message = False, ""
        except SystemExit as exc:
            stopped, message = True, str(exc)
        check(stopped and ".pem" not in message and HOST not in message,
              f"00b tls: {why} is refused, and the refusal names no path or host")  # fmt: skip


def _run_00b(
    fake: FakeAppliance, only: frozenset[str] | None = None, env: ProbeEnv | None = None
) -> tuple[int, str, dict[str, Any]]:
    """(exit code, everything printed, {file name: document}) for one offline P2-00b run."""
    client = new_client(fake)
    printed: list[str] = []
    files: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
        probe_00b.ROOT = Path(tmp)
        rec = probe_00b.Recorder(env or ENV, client, out, echo=printed.append)
        code = probe_00b.run(rec, only)
        for path in sorted(out.glob("*.json")):
            text = path.read_text(encoding="utf-8")
            verify_clean(text, (env or ENV).literals(), what=path.name)
            files[path.name.removeprefix("p2_00b_").removesuffix(".json")] = json.loads(text)
    client.close()
    return code, " | ".join(printed), files


def _leaks(printed: str, files: dict[str, Any]) -> list[str]:
    blob = printed + json.dumps(files)
    return [bad for bad in FORBIDDEN if bad in blob]


def test_00b_run() -> None:
    fake = FakeAppliance(apikeys_status=403)
    code, printed, docs = _run_00b(fake)
    check(code == 0, "00b run: a read-only key (apikeys 403) runs every step")
    check(_leaks(printed, docs) == [],
          "00b run: no connection value, address, name or id in files or output")  # fmt: skip
    check(_non_get(fake) == [("POST", "incidents/query_paged"), ("POST", "playbooks/query_paged")],
          "00b run: the only non-GETs sent were the two approved read-only queries")  # fmt: skip
    check(max(b["length"] for b in fake.bodies) <= 10 and all(
        set(b) <= {"filters", "sorts", "start", "length"} for b in fake.bodies),
          "00b run: no page longer than 10, and every query body is criteria only")  # fmt: skip
    scan = docs["scan"]["_facts"]
    check(scan["incidents_looked_at"] == 1 and scan["not_found_within_limit"] == [],
          "00b run: every search stops at its first hit")  # fmt: skip
    carried = docs["carried_actions"]["_facts"]
    check(carried["carried_by"] == "incident" and carried["every_entry_has_positive_int_id"]
          and carried["every_entry_has_nonempty_str_name"]
          and carried["keys_beyond_id_and_name"] == ["enabled"],
          "00b run: carried actions are reported as keys and booleans")  # fmt: skip
    task = docs["task"]["_facts"]
    perms = task["object_perms"]
    check(task["status_value"] == "O"
          and perms == {"perms_map_present": True, "read": "all true",
                        "edit_assign_create_delete": "at least one true",
                        "annotate": "all false"},
          "00b run: object perms are three statements: no name, no value, no count")  # fmt: skip
    contents = docs["attachment_contents"]
    check(contents["_facts"]["body_was_not_read"] and contents["shape"] is None
          and contents["_facts"]["content_type"] == "application/pdf",
          "00b run: attachment content is never read, only its status and headers")  # fmt: skip
    check(docs["filter_semantics"]["_facts"]["verdict"] in ("contradicted", "not distinguishable"),
          "00b run: filter semantics are not called verified on inconclusive counts")  # fmt: skip
    put = docs["doc_task_put"]["_facts"]
    check(put == {"method": "PUT", "path": "/orgs/{org_id}/tasks/{task_id}", "documented": True,
                  "request_body_type": "TaskDTO", "response_body_type": "StatusDTO",
                  "response_codes": [200, 409],
                  "parameters": {"handle_format": "header", "task_id": "path"}},
          "00b docs: a documented request is types, codes and parameter names")  # fmt: skip
    dto = docs["doc_type_TaskDTO"]["_facts"]["properties"]
    check(sorted(dto) == ["id", "name", "owner", "private", "status"]
          and dto["id"]["documented_read_only"] and not dto["status"]["documented_read_only"]
          and dto["private"]["documented_create_only"]
          and dto["owner"] == {"type": "<unparsed>", "constraints": "",
                               "documented_read_only": False, "documented_create_only": False},
          "00b docs: a data type is names, types and flags; odd cells are dropped")  # fmt: skip
    ledger = docs["_ledger_00b"]
    check(ledger["refused_by_policy"] == [] and all("{" in r["path"] or r["path"].startswith(
        ("/rest/const", "/docs/")) for r in ledger["requests"]),
          "00b run: the ledger holds path templates, never an id")  # fmt: skip


def test_00b_stops_on_a_mutating_key() -> None:
    fake = FakeAppliance()  # GET /apikeys answers 200 and lists mutating permissions
    code, printed, docs = _run_00b(fake)
    paths = [p for _, p in fake.seen]
    check(code == probe_00b.EXIT_MUTATING_KEY and "STOPPED" in printed,
          "00b stop: a key with mutating permissions stops the research")  # fmt: skip
    check(len(paths) == 2 and paths[0] == "/rest/const" and paths[1].endswith("/apikeys"),
          "00b stop: nothing is requested after the preflight")  # fmt: skip
    check(_leaks(printed, docs) == [],
          "00b stop: the stop report names no permission and no value")  # fmt: skip


def test_00b_scan_ceiling() -> None:
    fake = FakeAppliance(apikeys_status=403, barren=True)
    code, printed, docs = _run_00b(fake, frozenset({"scan"}))
    single = [p for m, p in fake.seen if m == "GET" and p.rsplit("/", 1)[-1].isdigit()
              and "/incidents/" in p]  # fmt: skip
    check(code == 0 and len(single) == 10 and fake.bodies[0]["length"] == 10,
          "00b scan: never more than 10 incidents, however many exist")  # fmt: skip
    facts = docs["scan"]["_facts"]
    check(facts["incidents_looked_at"] == 10 and facts["answered"] == []
          and facts["not_found_within_limit"] == ["actions", "attachment", "comments", "task"],
          "00b scan: an unanswered question is reported as not found, not widened")  # fmt: skip
    check(_leaks(printed, docs) == [], "00b scan: nothing leaks from a barren scan")


def test_00b_execution_query() -> None:
    """The one POST P2-00b added: one exact body, once, and nothing near it."""
    org = f"/rest/orgs/{ORG}"
    path = f"{org}/playbooks/execution/query_paged"
    exact = {"filters": [], "start": 0, "length": 1}
    cond = {"field_name": "status", "method": "equals", "value": "running"}
    refused: list[tuple[str, str, Any]] = [
        ("POST", path, {"filters": [], "start": 0, "length": 2}),
        ("POST", path, {"filters": [], "start": 1, "length": 1}),
        ("POST", path, {"filters": [], "length": 1}),
        ("POST", path, {"filters": [{"conditions": [cond]}], "start": 0, "length": 1}),
        ("POST", path, {**exact, "sorts": [{"field_name": "id", "type": "asc"}]}),
        ("POST", path, {**exact, "status": "canceled"}),
        ("POST", path, {"filters": [], "start": 0, "length": True}),
        ("POST", path, None),
        ("POST", f"{org}/playbooks/execution/1/activities", exact),
        ("POST", f"{org}/playbooks/execution/1/activities", None),
        ("POST", f"{org}/playbooks/execution/cancel", exact),
        ("POST", f"{org}/playbooks/execution/statistics/most_executed_playbooks", exact),
        ("PUT", f"{org}/playbooks/execution/1/status", exact),
        ("POST", f"{org}/workflow_instances/1/query_paged", exact),
    ]
    fake = FakeAppliance(apikeys_status=403)
    client = new_client(fake)
    passed = []
    for method, target, body in refused:
        try:
            client.request(method, target, "t", json_body=body)
            passed.append(target)
        except ProbePolicyError:
            pass
    check(passed == [] and fake.seen == [],
          f"00b policy: all {len(refused)} near-misses of the approved query refused")  # fmt: skip
    client.request("POST", path, "t", json_body=dict(exact))
    try:
        client.request("POST", path, "t", json_body=dict(exact))
        twice = True
    except ProbePolicyError:
        twice = False
    check(not twice and fake.seen == [("POST", path)],
          "00b policy: the exact body passes once; a second send is refused unsent")  # fmt: skip
    client.close()

    # The probe step: opt-in only, shape-only output, and never sent again once recorded.
    fake = FakeAppliance(apikeys_status=403)
    client = new_client(fake)
    printed: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
        probe_00b.ROOT = Path(tmp)
        rec = probe_00b.Recorder(ENV, client, out, echo=printed.append)
        probe_00b.run(rec, frozenset({"execution_query"}))
        text = (out / "p2_00b_execution_query.json").read_text(encoding="utf-8")
        second = new_client(fake)
        probe_00b.run(probe_00b.Recorder(ENV, second, out, echo=printed.append),
                      frozenset({"execution_query"}))  # fmt: skip
        second.close()
    sent = [pth for m, pth in fake.seen if m == "POST"]
    facts = json.loads(text)["_facts"]
    check(sent == [path] and fake.bodies == [exact],
          "00b step: exactly one execution query is sent, with the approved body")  # fmt: skip
    check(facts["any_execution_row"] is True and "detail_msg" not in text
          and not [bad for bad in FORBIDDEN if bad in text or bad in " | ".join(printed)],
          "00b step: the execution query is recorded as shape and booleans only")  # fmt: skip
    client.close()


def test_00b_designated_task() -> None:
    """The owner names a disposable task; the probe reads THAT one and checks where it lives."""
    task_id = str(int(INCIDENT_ID) + 1)
    for incident, expected in ((INCIDENT_ID, True), ("424242", False)):
        env = replace(ENV, incident_id=incident, task_id=task_id)
        fake = FakeAppliance(apikeys_status=403)
        _, printed, docs = _run_00b(fake, frozenset({"scan"}), env)
        task = docs["task"]["_facts"]
        read = [p for _, p in fake.seen if p.endswith(f"/tasks/{task_id}")]
        check(task["owner_designated_task"] and len(read) == 2
              and task["belongs_to_the_designated_incident"] is expected,
              f"00b task: the designated task is read; in its incident: {expected}")  # fmt: skip
        blob = printed + json.dumps(docs)
        check(_leaks(printed, docs) == [] and task_id not in blob and "424242" not in blob
              and docs["scan"]["_facts"]["source"] == "owner-chosen incident",
              "00b task: neither designated id is printed or stored")  # fmt: skip


def _run_designated(fake: FakeAppliance, env: ProbeEnv) -> tuple[int, str, dict[str, Any]]:
    client = new_client(fake)
    printed: list[str] = []
    files: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
        probe_00b.ROOT = Path(tmp)
        rec = probe_00b.Recorder(env, client, out, echo=printed.append)
        code = probe_00b.designated(rec, probe_00b.Ctx(ids={"org_id": env.org_id}))
        rec.finish()
        for path in sorted(out.glob("*.json")):
            text = path.read_text(encoding="utf-8")
            verify_clean(text, env.literals(), what=path.name)
            files[path.name.removeprefix("p2_00b_").removesuffix(".json")] = json.loads(text)
    client.close()
    return code, " | ".join(printed), files


def test_00b_designated_objects() -> None:
    """Stage 1B: two designated GETs; stop on a blocker; otherwise that incident only."""
    task_id = str(int(INCIDENT_ID) + 1)
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=task_id)
    inc, task = f"/incidents/{INCIDENT_ID}", f"/tasks/{task_id}"

    fake = FakeAppliance()  # a key that COULD list API keys: the step must not even ask
    code, printed, docs = _run_designated(fake, env)
    paths = [p for _, p in fake.seen]
    own = all(inc in p or task in p for p in paths)
    check(code == 0 and {m for m, _ in fake.seen} == {"GET"} and own
          and not any(p.endswith(("/apikeys", "/const", "/tasks")) for p in paths),
          "00b designated: GET only, designated objects, no preflight, no listing")  # fmt: skip
    facts = docs["designated"]["_facts"]
    check(facts["incident_http_status"] == 200 and facts["task_http_status"] == 200
          and facts["task_belongs_to_the_designated_incident"] is True
          and facts["exposes"]["attachment"] and facts["exposes"]["note"]
          and facts["exposes"]["carried_actions_on_incident"] == "1-9",
          "00b designated: statuses, membership and what the incident exposes")  # fmt: skip
    check(docs["attachment_contents"]["_facts"]["body_was_not_read"]
          and docs["attachment_contents"]["shape"] is None
          and "designated_task_canonical" in docs and "carried_actions" in docs,
          "00b designated: content headers only; canonical task and carried actions")  # fmt: skip
    blob = printed + json.dumps(docs)
    check(_leaks(printed, docs) == [] and task_id not in blob,
          "00b designated: neither id, and no value, is printed or stored")  # fmt: skip

    blockers = {
        "the task is 404": ({task: 404}, env, [200, 404]),
        "the incident is 403": ({inc: 403}, env, [403, 200]),
        "both are hidden": ({inc: 404, task: 404}, env, [404, 404]),
        "the task lives elsewhere": ({}, replace(env, incident_id="424242"), [200, 200]),
    }
    for why, (denied, env_case, statuses) in blockers.items():
        fake = FakeAppliance(apikeys_status=403, denied=denied)
        code, printed, docs = _run_designated(fake, env_case)
        facts = docs["designated"]["_facts"]
        seen_statuses = [facts["incident_http_status"], facts["task_http_status"]]
        check(code == probe_00b.EXIT_DESIGNATED_STOP and len(fake.seen) == 2
              and seen_statuses == statuses and "stopped" in facts
              and sorted(docs) == ["_ledger_00b", "designated"],
              f"00b designated: {why} -> both statuses reported, then a full stop")  # fmt: skip
        check(_leaks(printed, docs) == [] and "424242" not in printed + json.dumps(docs),
              f"00b designated: {why} -> the stop report has no id and no server text")  # fmt: skip

    fake = FakeAppliance(apikeys_status=403)
    code, printed, _ = _run_designated(fake, ENV)  # nothing designated
    check(code == 2 and fake.seen == [], "00b designated: without both ids nothing is sent")


def _observation(label: str, body: dict[str, Any], env: ProbeEnv) -> dict[str, Any]:
    """A recorded observation, built by the real reducer from a synthetic body."""
    # The reducer calls a body a full object when it holds every key of the live GET on
    # record; give it that record, with the body's own keys, wherever OUT_DIR points.
    shape_request.OUT_DIR.mkdir(parents=True, exist_ok=True)
    live = {"shape": {str(k): "x" for k in body}}
    (shape_request.OUT_DIR / "p2_00b_task.json").write_text(json.dumps(live), encoding="utf-8")
    facts, shape = shape_request.reduce_request(
        body, label=label, method="PUT", path_template="/rest/orgs/{org_id}/tasks/{task_id}",
        query={}, headers={"handle_format": "ids"},
        designated_task_id=env.task_id, designated_incident_id=env.incident_id,
    )  # fmt: skip
    return {"_fixture": "observed-ui-request-shape", "_facts": facts, "shape": shape}


def _write_pair(out: Path, env: ProbeEnv, *, reopen_status: str = "O") -> None:
    """Both observations and their comparison, as the owner's two reducer runs leave them."""
    out.mkdir(parents=True, exist_ok=True)
    shape_request.OUT_DIR = out
    base = {**nasty_row(1), "active": True, "required": True, "closed_date": None}
    reopened = {**base, "status": reopen_status, "closed_date": 1700000000000}
    bodies = {"close": {**base, "status": "C"}, "reopen": reopened}
    for label, body in bodies.items():
        try:
            doc = _observation(label, body, env)
        except shape_request.RefusedInputError:
            continue  # exactly what happens to a mislabelled capture: nothing is written
        (out / f"p2_00b_ui_request_{label}.json").write_text(json.dumps(doc), encoding="utf-8")
    pair = {"_facts": shape_request.compare_pair("close", "reopen")}
    (out / "p2_00b_ui_request_pair.json").write_text(json.dumps(pair), encoding="utf-8")


def test_00b_designated_task_check() -> None:
    """ONE GET in the UI's formats, and only when a valid observation pair is on record."""
    task_id = str(int(INCIDENT_ID) + 1)
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=task_id)
    stop = probe_00b.EXIT_DESIGNATED_STOP
    cases: dict[str, tuple[str, dict[str, int], int, int]] = {
        "a valid pair": ("O", {}, 0, 1),
        "required=true": ("O", {}, 0, 1),  # a recorded risk indicator now, not a stop
        "the task is hidden": ("O", {f"/tasks/{task_id}": 404}, stop, 1),
        "no genuine reopen observation": ("C", {}, 2, 0),
    }
    for why, (reopen_status, denied, expected, requests) in cases.items():
        fake = FakeAppliance(denied=denied, overlay={"required": True})
        client = new_client(fake)
        printed: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
            probe_00b.ROOT = Path(tmp)
            _write_pair(out, env, reopen_status=reopen_status)
            rec = probe_00b.Recorder(env, client, out, echo=printed.append)
            code = probe_00b.designated_task_check(rec, probe_00b.Ctx(ids={"org_id": ORG}))
            recorded = out / "p2_00b_designated_task_ui_formats.json"
            blob = " | ".join(printed) + (
                recorded.read_text(encoding="utf-8") if recorded.is_file() else ""
            )
        client.close()
        only_task = all(m == "GET" and p.endswith(f"/tasks/{task_id}") for m, p in fake.seen)
        check(code == expected and len(fake.seen) == requests and only_task,
              f"00b task read: {why} -> {requests} request(s), exit {expected}")  # fmt: skip
        check(not [bad for bad in FORBIDDEN if bad in blob] and task_id not in blob,
              f"00b task read: {why} -> no id and no value printed or stored")  # fmt: skip


def test_00b_pair() -> None:
    """The close/reopen pair: valid only when both are genuine and of the designated task."""
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=str(int(INCIDENT_ID) + 1))
    with tempfile.TemporaryDirectory() as tmp:
        _write_pair(Path(tmp), env)
        good = shape_request.compare_pair("close", "reopen")
    check(good["valid_pair"] and good["problems"] == []
          and good["state"]["close"] == {"status_value": "C", "closed_date_is_null": True,
                                         "active": True, "required": True}
          and good["state"]["reopen"]["closed_date_is_null"] is False
          and good["state_facts_that_differ"] == ["closed_date_is_null", "status_value"]
          and good["keys_whose_json_type_differs"] == {
              "closed_date": {"close": "null", "reopen": "int"}},
          "pair: a genuine C/O pair is valid; state is letters, nullness and booleans")  # fmt: skip
    check(not [bad for bad in FORBIDDEN if bad in json.dumps(good)] and "1700000" not in
          json.dumps(good), "pair: the comparison holds no value, id or timestamp")  # fmt: skip
    with tempfile.TemporaryDirectory() as tmp:
        _write_pair(Path(tmp), env, reopen_status="C")  # the capture mistake that happened
        bad = shape_request.compare_pair("close", "reopen")
        kept = (Path(tmp) / "p2_00b_ui_request_reopen.json").exists()
    check(not kept and not bad["valid_pair"] and "reopen: no fixture" in bad["problems"],
          "pair: a status-C payload is refused under --label reopen; pair invalid")  # fmt: skip
    with tempfile.TemporaryDirectory() as tmp:
        _write_pair(Path(tmp), replace(env, task_id="424242"))  # observations of another task
        other = shape_request.compare_pair("close", "reopen")
    check(not other["valid_pair"]
          and "close: not shown to be the designated task" in other["problems"],
          "pair: observations of some other task do not make a valid pair")  # fmt: skip


def test_task_candidate() -> None:
    """The body-construction algorithm: fresh GET + proven state changes, or a stop."""
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=str(int(INCIDENT_ID) + 1))
    ids = {"task_id": env.task_id, "incident_id": env.incident_id}
    scratch = tempfile.TemporaryDirectory()
    shape_request.OUT_DIR = Path(scratch.name)
    task = {**nasty_row(1), "active": True, "frozen": False, "custom": True, "required": True,
            "closed_date": None, "status": "O", "task_layout": None}  # fmt: skip
    closed = {**task, "status": "C", "closed_date": 1700000000000}
    seen = {"close": _observation("close", {**task, "status": "C"}, env),
            "reopen": _observation("reopen", {**closed, "status": "O"}, env),
            "reopen_nulls": _observation("reopen", {**task, "status": "O"}, env)}  # fmt: skip
    build = task_candidate.build_candidate

    c = build(task, target="C", observation=seen["close"], **ids)
    check(c.ok and c.changed_keys == ("status",) and c.body is not None
          and c.body["status"] == "C" and c.body["closed_date"] is None
          and {k: v for k, v in c.body.items() if k != "status"}
          == {k: v for k, v in task.items() if k != "status"},
          "candidate: close = the fresh task with status C and nothing else touched")  # fmt: skip
    o = build(closed, target="O", observation=seen["reopen"], **ids)
    check(o.ok and o.changed_keys == ("status",) and o.body is not None
          and o.body["closed_date"] == closed["closed_date"],
          "candidate: reopen passes closed_date through when the UI sent one")  # fmt: skip
    check(task_candidate.CHANGED_KEYS == ("status",)
          and task_candidate.MAX_EXPERIMENT_REQUESTS == 9,
          "candidate: only status may change; the ceiling is 9 requests")  # fmt: skip
    n_stop = build(closed, target="O", observation=seen["reopen_nulls"], **ids)
    check(HOST not in repr(c) and "body" not in repr(c) and task == {**task},
          "candidate: the body is never in a repr and the fresh task is not modified")  # fmt: skip

    stops = {
        "the task is already closed": build(closed, target="C", observation=seen["close"], **ids),
        "an inactive task": build({**task, "active": False}, target="C",
                                  observation=seen["close"], **ids),
        "a frozen task": build({**task, "frozen": True}, target="C",
                               observation=seen["close"], **ids),
        "a task that is not custom": build({**task, "custom": False}, target="C",
                                           observation=seen["close"], **ids),
        "a task in another incident": build({**task, "inc_id": 7}, target="C",
                                            observation=seen["close"], **ids),
        "another task": build({**task, "id": 7}, target="C", observation=seen["close"], **ids),
        "a key the UI never sent": build({**task, "surprise": 1}, target="C",
                                         observation=seen["close"], **ids),
        "a missing key": build({k: v for k, v in task.items() if k != "vers"}, target="C",
                               observation=seen["close"], **ids),
        "a changed JSON type": build({**task, "vers": "3"}, target="C",
                                     observation=seen["close"], **ids),
        "reopening a task whose closed_date is null (never invented)": build(
            {**closed, "closed_date": None}, target="O", observation=seen["reopen"], **ids),
        "closing a task whose closed_date is set (never cleared)": build(
            {**task, "closed_date": 1700000000000}, target="C", observation=seen["close"], **ids),
        "the direct-GET representation of task_layout (an empty list)": build(
            {**task, "task_layout": []}, target="C", observation=seen["close"], **ids),
        "a task with no task_layout key": build(
            {k: v for k, v in task.items() if k != "task_layout"}, target="C",
            observation=seen["close"], **ids),
        "a task with no closed_date key": build(
            {k: v for k, v in task.items() if k != "closed_date"}, target="C",
            observation=seen["close"], **ids),
        "a reopen observation that sent a null closed_date": build(
            closed, target="O", observation=seen["reopen_nulls"], **ids),
        "the wrong observation": build(task, target="C", observation=seen["reopen"], **ids),
        "no observation": build(task, target="C", observation={}, **ids),
        "an observation of another task": build(
            task, target="C", observation=_observation(
                "close", {**task, "status": "C"}, replace(env, task_id="424242")), **ids),
        "an unreadable task": build(None, target="C", observation=seen["close"], **ids),
        "an unknown target": build(task, target="X", observation=seen["close"], **ids),
    }  # fmt: skip
    for why, result in stops.items():
        told = " ".join(result.stops)
        check(not result.ok and result.body is None and bool(result.stops)
              and not [bad for bad in FORBIDDEN if bad in told],
              f"candidate: {why} -> a stop, no body, and no value in the reason")  # fmt: skip

    rollback = task_candidate.rollback_stops
    fine = {"close_succeeded": True, "phase_unchanged": True, "requests_sent": 6,
            "reopen_candidate": o}  # fmt: skip
    check(rollback(**fine) == [], "rollback: allowed when every prerequisite holds")
    refusals = {
        "the incident phase changed": {**fine, "phase_unchanged": False},
        "the close is not verified": {**fine, "close_succeeded": False},
        "the request ceiling would be passed": {**fine, "requests_sent": 7},
        "there is no reopen candidate": {**fine, "reopen_candidate": n_stop},
        "the candidate is a close, not a reopen": {**fine, "reopen_candidate": c},
    }
    for why, case in refusals.items():
        check(bool(rollback(**case)), f"rollback: NOT sent when {why}")
    scratch.cleanup()
    report = task_candidate.restoration_report(task, {**task, "vers": 4})
    check(report == {"same_key_set": True, "status_restored": True,
                     "closed_date_nullness_restored": True,
                     "keys_whose_value_differs_from_the_baseline": ["vers"]},
          "candidate: restoration is reported as key names and booleans")  # fmt: skip
    source = Path(task_candidate.__file__).read_text(encoding="utf-8")
    banned = ("import httpx", "import requests", "urllib", "import socket", "http.client",
              "safe_http", "subprocess")  # fmt: skip
    check(not [word for word in banned if word in source],
          "candidate: the module imports nothing that could send a request")  # fmt: skip


def test_00b_format_headers() -> None:
    """The two format controls as headers: closed names, closed values, nothing else."""
    fake = FakeAppliance(apikeys_status=403)
    client = new_client(fake)
    good = {"handle_format": "ids", "text_content_output_format": "objects_convert"}
    client.request("GET", f"/rest/orgs/{ORG}/tasks/1", "t", default_params=False,
                   format_headers=good)  # fmt: skip
    one = [("GET", f"/rest/orgs/{ORG}/tasks/1")]
    check(fake.format_headers_seen == [good] and fake.seen == one,
          "headers: the two format controls are sent as headers, with no query string")  # fmt: skip
    bad_sets = [{"cookie": "a=b"}, {"authorization": "Basic x"}, {"x-sess-id": "1"},
                {"handle_format": SECRET}, {"text_content_output_format": "anything"},
                {"Handle_format": "ids"}]  # fmt: skip
    refused = 0
    for headers in bad_sets:
        try:
            client.request("GET", f"/rest/orgs/{ORG}/tasks/1", "t", format_headers=headers)
        except ProbePolicyError as exc:
            refused += SECRET not in str(exc)
    check(refused == len(bad_sets) and len(fake.seen) == 1,
          "headers: any other header name or value is refused before anything is sent")  # fmt: skip
    client.close()


def test_00b_tasktree() -> None:
    """The task tree is narrowed in memory to exactly one designated task, or nothing."""
    task_id = str(int(INCIDENT_ID) + 1)
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=task_id)
    mine = {**nasty_row(1), "active": True, "frozen": False, "custom": True, "required": True,
            "closed_date": None, "task_layout": None,
            "perms": {"read": True, "write": True, "close": True}}  # fmt: skip
    other = {**nasty_row(5), "task_layout": [{"x": HOST}]}
    stop = probe_00b.EXIT_DESIGNATED_STOP
    trees: dict[str, tuple[Any, int, bool]] = {
        "a tree with the task once": (
            {"phases": [{"name": HOST, "tasks": [other, mine]}]},
            0,
            True,
        ),
        "a bare list of tasks": ([other, mine], 0, True),
        "the task twice": ({"a": [mine], "b": {"children": [mine]}}, stop, False),
        "no such task": ({"phases": [{"tasks": [other]}]}, stop, False),
        "the task under another incident": ([{**mine, "inc_id": 7}], stop, False),
    }
    for why, (tree, expected, found) in trees.items():
        fake = FakeAppliance(apikeys_status=403, tree=tree)
        client = new_client(fake)
        printed: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
            probe_00b.ROOT = Path(tmp)
            _write_pair(out, env)
            rec = probe_00b.Recorder(env, client, out, echo=printed.append)
            code = probe_00b.tasktree_read(rec, probe_00b.Ctx(ids={"org_id": ORG}))
            text = (out / "p2_00b_tasktree_task.json").read_text(encoding="utf-8")
        client.close()
        facts = json.loads(text)["_facts"]
        sent = fake.seen == [("GET", f"/rest/orgs/{ORG}/incidents/{INCIDENT_ID}/tasktree")]
        check(code == expected and sent and facts["designated_task_found_exactly_once"] is found
              and fake.format_headers_seen == [probe_00b.UI_FORMAT_PARAMS],
              f"tasktree: {why} -> one GET with format headers; found={found}")  # fmt: skip
        blob = text + " | ".join(printed)
        check(not [bad for bad in FORBIDDEN if bad in blob] and task_id not in blob,
              f"tasktree: {why} -> no id, name or value of ANY task is kept")  # fmt: skip
    fake = FakeAppliance(apikeys_status=403, tree=[other, mine])
    client = new_client(fake)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
        probe_00b.ROOT = Path(tmp)
        _write_pair(out, env)
        rec = probe_00b.Recorder(env, client, out, echo=lambda _line: None)
        probe_00b.tasktree_read(rec, probe_00b.Ctx(ids={"org_id": ORG}))
        recorded = (out / "p2_00b_tasktree_task.json").read_text(encoding="utf-8")
        facts = json.loads(recorded)["_facts"]
    client.close()
    check(facts["task_layout_class"]["fresh_read"] == "null"
          and facts["documented_status_change_flags"] == {"flags": ["read", "write", "close"],
                                                          "statement": "all true"}
          and facts["object_perms"] == {"perms_map_present": True, "read": "all true",
                                        "edit_assign_create_delete": "at least one true",
                                        "annotate": "all false"},
          "tasktree: task_layout is a class; permissions are statements, not per-flag")  # fmt: skip


def test_00b_preflight() -> None:
    """The pre-mutation report: two GETs, the real builder, a GO only when everything holds."""
    task_id = str(int(INCIDENT_ID) + 1)
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=task_id)
    base = {**nasty_row(1), "active": True, "frozen": False, "custom": True, "required": True,
            "closed_date": None, "status": "O", "task_layout": None}  # fmt: skip
    allowed = {"read": True, "write": True, "close": True}
    cases: dict[str, tuple[dict[str, Any], bool]] = {
        "an open task the credential may write and close": ({**base, "perms": allowed}, True),
        "a credential that may not close it": (
            {**base, "perms": {**allowed, "close": False}}, False),
        "a task that is already closed": (
            {**base, "perms": allowed, "status": "C", "closed_date": 1700000000000}, False),
        "the empty-list representation of task_layout": (
            {**base, "perms": allowed, "task_layout": []}, False),
    }  # fmt: skip
    for why, (task, go) in cases.items():
        fake = FakeAppliance(apikeys_status=403, tree=[task], overlay={"phase_id": 1005})
        client = new_client(fake)
        printed: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "tests" / "fixtures" / "soar" / "verified"
            probe_00b.ROOT = Path(tmp)
            out.mkdir(parents=True)
            shape_request.OUT_DIR = out
            seen = _observation("close", {**base, "perms": allowed, "status": "C"}, env)
            (out / "p2_00b_ui_request_close.json").write_text(json.dumps(seen), encoding="utf-8")
            rec = probe_00b.Recorder(env, client, out, echo=printed.append)
            code = probe_00b.preflight_close(rec, probe_00b.Ctx(ids={"org_id": ORG}))
            text = (out / "p2_00b_preflight_close.json").read_text(encoding="utf-8")
        client.close()
        facts = json.loads(text)["_facts"]
        methods = {m for m, _ in fake.seen}
        # A credential that may not close still yields a buildable candidate: the permission
        # gate, not the builder, is what says NO-GO there.
        buildable = "credential" in why
        check(facts["go"] is go and code == (0 if go else probe_00b.EXIT_NO_GO)
              and methods == {"GET"} and len(fake.seen) == 2 and bool(facts["no_go_reasons"]) != go
              and (facts["close_candidate"]["changed_keys"] == ["status"]) is buildable,
              f"preflight: {why} -> {'GO' if go else 'NO-GO'}; two GETs; never a PUT")  # fmt: skip
        blob = text + " | ".join(printed)
        check(not [bad for bad in FORBIDDEN if bad in blob] and task_id not in blob
              and "1005" not in blob and "1700000000000" not in blob,
              f"preflight: {why} -> no id, phase, timestamp or value is kept")  # fmt: skip


class FakeTaskAppliance:
    """A stateful lab: one designated task in a task tree, and an incident with a phase."""

    STAMP = 1700000000000
    PHASE = 1005

    def __init__(self, env: ProbeEnv, **quirks: Any) -> None:
        self.env, self.quirks = env, quirks
        self.task: dict[str, Any] = {
            **nasty_row(1), "id": int(env.task_id), "inc_id": int(env.incident_id),
            "active": True, "frozen": False, "custom": True, "required": True,
            "status": quirks.get("status", "O"),
            "closed_date": self.STAMP if quirks.get("status") == "C" else None,
            "task_layout": quirks.get("layout"),
            "perms": {"read": True, "write": quirks.get("write", True), "close": True},
        }  # fmt: skip
        self.phase = self.PHASE
        self.seen: list[tuple[str, str]] = []
        self.put_bodies: list[dict[str, Any]] = []
        self.served: list[dict[str, Any]] = []  # the task as it was last served before a PUT
        self.headers: list[dict[str, str]] = []
        self.queries: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.seen.append((method, path))
        self.queries.append(request.url.query.decode())
        self.headers.append({k: v for k, v in request.headers.items()
                             if k in ("handle_format", "text_content_output_format")})  # fmt: skip
        if method == "GET" and path.endswith(f"/tasks/{self.env.task_id}"):
            shown = json.loads(json.dumps(self.task))
            if self.quirks.get("closed_layout_null") and shown["status"] == "C":
                shown["task_layout"] = None
            return httpx.Response(200, json=shown)
        if method == "GET" and path.endswith("/tasktree"):
            gone = self.quirks.get("vanish_after_close") and self.task["status"] == "C"
            tree = [nasty_row(5)] if gone else [nasty_row(5), json.loads(json.dumps(self.task))]
            return httpx.Response(200, json=tree)
        if method == "GET":
            return httpx.Response(200, json={**nasty_row(0), "phase_id": self.phase})
        body = json.loads(request.content)
        self.put_bodies.append(body)
        self.served.append(json.loads(json.dumps(self.task)))
        closing = body.get("status") == "C"
        if closing and self.quirks.get("close_error"):
            raise httpx.ConnectError(f"cannot reach {request.url}", request=request)
        status = self.quirks.get("close_status" if closing else "reopen_status", 200)
        applies = self.quirks.get("close_applies", True) if closing else status == 200
        if applies and (status == 200 or self.quirks.get("applies_despite_status")):
            self.task["status"] = body["status"]
            if closing:
                self.task["closed_date"] = self.STAMP
                self.phase += 1 if self.quirks.get("phase_moves") else 0
                if self.quirks.get("new_key"):
                    self.task["surprise"] = HOST
                if self.quirks.get("write_revoked"):
                    self.task["perms"]["write"] = False
            elif self.quirks.get("reopen_clears"):
                self.task["closed_date"] = None
        if status != 200:
            return httpx.Response(status, json={"success": False, "message": f"no {HOST}"})
        ok = {"success": True, "title": None, "message": None, "hints": [], "error_code": None}
        return httpx.Response(200, json=ok)


def _experiment(
    execute: bool = True, source: str = "tasktree", **quirks: Any
) -> tuple[int, FakeTaskAppliance, Facts, str]:
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=str(int(INCIDENT_ID) + 1))
    fake = FakeTaskAppliance(env, **quirks)
    client = task_experiment.ExperimentClient(
        env, ssl.create_default_context(), transport=httpx.MockTransport(fake)
    )
    printed: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        shape_request.OUT_DIR = out
        open_task = {**fake.task, "status": "O", "closed_date": None, "task_layout": None,
                     "perms": {"read": True, "write": True, "close": True}}  # fmt: skip
        pair = {"close": {**open_task, "status": "C"},
                "reopen": {**open_task, "closed_date": fake.STAMP}}  # fmt: skip
        for label, body in pair.items():
            doc = _observation(label, body, env)
            (out / f"p2_00b_ui_request_{label}.json").write_text(json.dumps(doc), encoding="utf-8")
        code = task_experiment.run_experiment(
            env, client, out, execute=execute, echo=printed.append, source=source
        )
        stem = "p2_00b_task_experiment" + ("_documented" if source == "documented" else "")
        name = stem + (".json" if fake.put_bodies else "_dry_run.json")
        text = (out / name).read_text(encoding="utf-8")
        verify_clean(text, env.literals(), what=name)
    client.close()
    return code, fake, json.loads(text)["_facts"], text + " | ".join(printed)


def test_experiment_happy_path() -> None:
    code, fake, ev, blob = _experiment()
    tree = f"/rest/orgs/{ORG}/incidents/{INCIDENT_ID}/tasktree"
    inc = f"/rest/orgs/{ORG}/incidents/{INCIDENT_ID}"
    put = f"/rest/orgs/{ORG}/tasks/{int(INCIDENT_ID) + 1}"
    expected = [("GET", tree), ("GET", inc), ("PUT", put), ("GET", tree), ("GET", inc),
                ("GET", tree), ("PUT", put), ("GET", tree), ("GET", inc)]  # fmt: skip
    check(code == 0 and fake.seen == expected and ev["request_count"]["total"] == 9,
          "experiment: exactly the 9 planned requests, in order: 7 GET and 2 PUT")  # fmt: skip
    diffs = [sorted(k for k in body if body[k] != served[k])
             for body, served in zip(fake.put_bodies, fake.served, strict=True)]  # fmt: skip
    same_keys = all(set(b) == set(s) for b, s in zip(fake.put_bodies, fake.served, strict=True))
    check(diffs == [["status"], ["status"]] and same_keys
          and [b["status"] for b in fake.put_bodies] == ["C", "O"]
          and fake.put_bodies[0]["closed_date"] is None
          and fake.put_bodies[1]["closed_date"] == fake.STAMP,
          "experiment: each PUT body is the fresh task with ONLY status changed")  # fmt: skip
    controls = {"handle_format": "ids", "text_content_output_format": "objects_convert"}
    check(all(h == controls for h in fake.headers) and not any(fake.queries),
          "experiment: every request has the two format headers and no query string")  # fmt: skip
    check(ev["close_candidate"]["changed_keys"] == ["status"]
          and ev["reopen_candidate"]["changed_keys"] == ["status"]
          and ev["close_put"]["status_dto_compatible"] and ev["close_put"]["success"] is True
          and ev["close_verified"] and ev["rollback"]["allowed"] and ev["reopen_verified"]
          and ev["after_close"]["field_names_that_differ_from_the_baseline"]
          == ["closed_date", "status"]
          and ev["final"]["status_value"] == "O" and ev["final"]["phase_unchanged"]
          and ev["final"]["field_names_that_differ_from_the_baseline"] == ["closed_date"],
          "experiment: evidence is statuses, names, booleans; server changes by NAME")  # fmt: skip
    check(not [bad for bad in FORBIDDEN if bad in blob] and str(fake.STAMP) not in blob
          and str(fake.PHASE) not in blob and str(int(INCIDENT_ID) + 1) not in blob,
          "experiment: no id, phase, timestamp, name or text is printed or stored")  # fmt: skip


def test_experiment_stops() -> None:
    """Every way the experiment ends early: how many requests, and never a second PUT."""
    cases: dict[str, tuple[dict[str, Any], int, int, str]] = {
        "a dry run": ({"execute": False}, 2, 0, "dry run"),
        "a credential without write": ({"write": False}, 2, 0, "NO-GO"),
        "a task that is already closed": ({"status": "C"}, 2, 0, "NO-GO"),
        "the empty-list task_layout": ({"layout": []}, 2, 0, "NO-GO"),
        "the incident phase moves on close": ({"phase_moves": True}, 5, 1, "HARD STOP"),
        "the close is refused (403)": ({"close_status": 403}, 5, 1, "did not take effect"),
        "the close answers 200 but changes nothing": (
            {"close_applies": False}, 5, 1, "did not take effect"),
        "the close answers 500 yet the task is closed": (
            {"close_status": 500, "applies_despite_status": True}, 5, 1, "not unambiguous"),
        "the close adds a key to the task": ({"new_key": True}, 5, 1, "not unambiguous"),
        "the task vanishes after the close": (
            {"vanish_after_close": True}, 5, 1, "did not take effect"),
        "the close request fails in transport": ({"close_error": True}, 5, 1, "did not take"),
        "write is revoked once the task is closed": (
            {"write_revoked": True}, 6, 1, "prerequisites do not hold"),
        "the reopen is refused (403)": ({"reopen_status": 403}, 9, 2, "reopen is not verified"),
    }  # fmt: skip
    _, _, denied, _ = _experiment(write=False)
    check(denied["baseline"]["required_flags"]["values"]
          == {"read": True, "write": False, "close": True} and denied["go"] is False,
          "experiment: a failing permission gate names the flag: read, write, close")  # fmt: skip
    for why, (quirks, requests, puts, outcome) in cases.items():
        code, fake, ev, blob = _experiment(**quirks)
        sent_puts = [m for m, _ in fake.seen if m == "PUT"]
        check(code != 0 and len(fake.seen) == requests and len(sent_puts) == puts
              and outcome in ev["outcome"]
              and [b["status"] for b in fake.put_bodies] == ["C", "O"][:puts],
              f"experiment: {why} -> {requests} request(s), {puts} PUT(s), no retry")  # fmt: skip
        check(not [bad for bad in FORBIDDEN if bad in blob] and str(fake.PHASE) not in blob,
              f"experiment: {why} -> the report holds no value")  # fmt: skip
    code, fake, ev, _ = _experiment(reopen_clears=True)
    check(code == 0 and ev["final"]["closed_date_is_null"] is True
          and ev["final"]["field_names_that_differ_from_the_baseline"] == [],
          "experiment: the server's treatment of closed_date on reopen is reported")  # fmt: skip


def test_experiment_documented_source() -> None:
    """The documented single-task GET as the source: task_layout [] goes back untouched."""
    task = f"/rest/orgs/{ORG}/tasks/{int(INCIDENT_ID) + 1}"
    inc = f"/rest/orgs/{ORG}/incidents/{INCIDENT_ID}"
    code, fake, ev, blob = _experiment(source="documented", layout=[])
    expected = [("GET", task), ("GET", inc), ("PUT", task), ("GET", task), ("GET", inc),
                ("GET", task), ("PUT", task), ("GET", task), ("GET", inc)]  # fmt: skip
    check(code == 0 and fake.seen == expected and not any("tasktree" in p for _, p in fake.seen),
          "documented: 9 requests, the task tree is never read")  # fmt: skip
    diffs = [sorted(k for k in body if body[k] != served[k])
             for body, served in zip(fake.put_bodies, fake.served, strict=True)]  # fmt: skip
    untouched = all(b["task_layout"] == [] for b in fake.put_bodies)
    check(diffs == [["status"], ["status"]] and untouched
          and ev["source"] == "documented"
          and ev["after_close"]["task_layout_class"] == "empty list"
          and ev["final"]["task_layout_class"] == "empty list",
          "documented: task_layout [] is sent back UNCHANGED; only status differs")  # fmt: skip
    code, fake, ev, _ = _experiment(source="documented", layout=[], closed_layout_null=True)
    check(code == 0 and [b["task_layout"] for b in fake.put_bodies] == [[], None]
          and ev["after_close"]["task_layout_class"] == "null",
          "documented: the closed read is passed through as it is, never normalised")  # fmt: skip
    stops: dict[str, tuple[dict[str, Any], int, int]] = {
        "the documented read shows null, not []": ({"layout": None}, 2, 0),
        "the PUT is rejected (400)": ({"layout": [], "close_status": 400}, 5, 1),
        "the phase moves": ({"layout": [], "phase_moves": True}, 5, 1),
    }
    for why, (quirks, requests, puts) in stops.items():
        code, fake, ev, blob = _experiment(source="documented", **quirks)
        bodies = [b["task_layout"] for b in fake.put_bodies]
        check(code != 0 and len(fake.seen) == requests and len(fake.put_bodies) == puts
              and all(layout == [] for layout in bodies),
              f"documented: {why} -> {requests} requests, {puts} PUT(s), no retry")  # fmt: skip
        check(not [bad for bad in FORBIDDEN if bad in blob], f"documented: {why} -> no value kept")
    code, fake, _, _ = _experiment(layout=[])  # the DEFAULT source must stay as strict as before
    check(code != 0 and fake.put_bodies == [],
          "documented: the task-tree source still refuses an empty-list task_layout")  # fmt: skip


def test_experiment_client_policy() -> None:
    """The client cannot be talked into anything but its three operations."""
    env = replace(ENV, incident_id=INCIDENT_ID, task_id=str(int(INCIDENT_ID) + 1))
    fake = FakeTaskAppliance(env)
    client = task_experiment.ExperimentClient(
        env, ssl.create_default_context(), transport=httpx.MockTransport(fake)
    )
    fresh = dict(fake.task)
    good = task_candidate.Candidate("C", (), ("status",), {**fresh, "status": "C"})
    bad: dict[str, Any] = {
        "a plain body": {**fresh, "status": "C"},
        "a candidate that was stopped": task_candidate.Candidate("C", ("stop",)),
        "a candidate that changes more than status": task_candidate.Candidate(
            "C", (), ("closed_date", "status"), {**fresh, "status": "C"}),
        "a reopen before any close": task_candidate.Candidate(
            "O", (), ("status",), {**fresh, "status": "O"}),
        "a candidate for another task": task_candidate.Candidate(
            "C", (), ("status",), {**fresh, "id": 7, "status": "C"}),
        "a candidate in another incident": task_candidate.Candidate(
            "C", (), ("status",), {**fresh, "inc_id": 7, "status": "C"}),
        "a candidate whose body disagrees with its target": task_candidate.Candidate(
            "C", (), ("status",), {**fresh, "status": "O"}),
    }  # fmt: skip
    for why, candidate in bad.items():
        try:
            client.put_task(candidate)
            refused = False
        except task_experiment.ExperimentPolicyError as exc:
            refused = HOST not in str(exc)
        check(refused and fake.seen == [], f"experiment client: {why} is refused, unsent")
    client.put_task(good)
    again = 0
    reopen = task_candidate.Candidate("O", (), ("status",), {**fresh, "status": "O"})
    for candidate in (good, reopen, reopen):
        try:
            client.put_task(candidate)
        except task_experiment.ExperimentPolicyError:
            again += 1
    check(again == 2 and [m for m, _ in fake.seen] == ["PUT", "PUT"],
          "experiment client: a second close and a third PUT are refused")  # fmt: skip
    gets = 0
    for _ in range(9):
        try:
            client.get_tree()
            gets += 1
        except task_experiment.ExperimentPolicyError:
            break
    check(gets == 7 and len(fake.seen) == 9, "experiment client: 7 GETs and 9 requests at most")
    check(not [name for name in dir(client) if name in ("request", "post", "delete", "patch")],
          "experiment client: there is no general request method to misuse")  # fmt: skip
    client.close()
    for why, broken in {
        "an unverifying TLS context": ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    }.items():
        broken.check_hostname = False
        try:
            task_experiment.ExperimentClient(env, broken)
            built = True
        except task_experiment.ExperimentPolicyError:
            built = False
        check(not built, f"experiment client: {why} is refused")


def test_00b_threading() -> None:
    reply = {"id": 3, "parent_id": 2, "text": HOST, "children": []}
    rows = [
        {"id": 1, "parent_id": None, "children": [{"id": 2, "parent_id": 1, "children": [reply]}]},
        {"id": 4, "parent_id": None, "text": f"Payroll breach {EMAIL}", "children": []},
    ]
    facts = probe_00b._thread_facts(rows)
    check(facts == {"top_level_notes": "1-9", "any_reply_nested_under_children": True,
                    "max_depth": 3, "every_reply_has_an_integer_parent_id": True,
                    "reply_parent_id_equals_the_parent_note_id": True,
                    "top_level_parent_id_is_null": True,
                    "a_reply_is_also_listed_at_top_level": False},
          "00b comments: threading is booleans and a depth, never a note")  # fmt: skip
    flat = probe_00b._thread_facts([{"id": 1, "parent_id": None}, {"id": 2, "parent_id": 1}])
    check(not flat["any_reply_nested_under_children"]
          and flat["a_reply_is_also_listed_at_top_level"],
          "00b comments: a flat list with parent ids is told apart from nesting")  # fmt: skip


def _refused(call: Any) -> str | None:
    """The refusal message, or None if the input was accepted."""
    try:
        call()
    except shape_request.RefusedInputError as exc:
        return str(exc)
    return None


def test_shape_request() -> None:
    """The owner's browser observation: structure in, nothing else, and a HAR is refused."""
    template = "/rest/orgs/{org_id}/tasks/{task_id}"
    body = {**nasty_row(1), "auto_deactivate": True, "csrf_token": SECRET,
            "phase_id": {"id": 7, "name": HOST},
            "instructions": {"format": "html", "content": f"<b>{HOST}</b>"}}  # fmt: skip
    known = {"status": {}, "id": {"documented_read_only": True},
             "private": {"documented_create_only": True}}  # fmt: skip
    live = {"shape": {"id": "int", "status": "str", "form": "null"}}
    with tempfile.TemporaryDirectory() as tmp:
        shape_request.OUT_DIR = Path(tmp)
        reference = Path(tmp) / "p2_00b_doc_type_TaskDTO.json"
        reference.write_text(json.dumps({"_facts": {"properties": known}}), encoding="utf-8")
        (Path(tmp) / "p2_00b_task.json").write_text(json.dumps(live), encoding="utf-8")
        facts, shape = shape_request.reduce_request(
            body, label="reopen", method="PUT", path_template=template,
            query=shape_request.parse_pairs(["handle_format=names", "sess=abc123"], headers=False),
            headers=shape_request.parse_pairs(["Handle_Format=objects"], headers=True),
            designated_task_id=str(int(INCIDENT_ID) + 1), designated_incident_id="424242",
        )  # fmt: skip
        mislabelled = _refused(
            lambda: shape_request.reduce_request(
                body, label="close", method="PUT", path_template=template, query={}, headers={}
            )
        )
    check(mislabelled is not None and "status C" in mislabelled
          and not [bad for bad in FORBIDDEN if bad in mislabelled],
          "ui request: a status-O payload under --label close is refused")  # fmt: skip
    check(facts["body_is_the_designated_task"] is True
          and facts["body_is_in_the_designated_incident"] is False
          and facts["closed_date_is_null"] == "absent" and facts["active"] is None
          and facts["required"] is None,
          "ui request: designation is two booleans; absent state facts say so")  # fmt: skip
    text = json.dumps([facts, shape])
    check(not [bad for bad in FORBIDDEN if bad in text] and "abc123" not in text,
          "ui request: no value, id, host or token survives the reduction")  # fmt: skip
    check(facts["query"] == {"handle_format": "names", "sess": "<value withheld>"}
          and facts["headers_named_by_the_owner"] == {"handle_format": "objects"},
          "ui request: only documented enum tokens are kept as values")  # fmt: skip
    check(facts["live_only_keys_present"] == {"auto_deactivate": True, "form": False,
                                              "task_layout": False, "user_notes": False}
          and facts["documented_read_only_properties_present"] == ["id"]
          and facts["keys_of_the_live_get_that_are_absent"] == ["form"]
          and facts["full_object"] is False and facts["status_value"] == "O"
          and {"csrf_token", "vers"} <= set(facts["version_like_keys"])
          and facts["handle_forms"]["phase_id"] == "object{id,name}"
          and facts["instructions_form"] == "object{format,content}",
          "ui request: the contract questions are answered as names and booleans")  # fmt: skip
    har = json.dumps({"log": {"entries": [{"request": {"cookies": [SECRET]}}]}}).encode()
    bad_inputs = {
        "a copied cURL command": f"curl 'https://{HOST}/rest' -H 'Cookie: {SECRET}'".encode(),
        "a copied fetch call": f'fetch("https://{HOST}/rest", {{}})'.encode(),
        "a raw HTTP message": f"PUT /rest/orgs/{ORG}/tasks/1 HTTP/1.1".encode(),
        "a HAR export": har,
        "a body with headers in it": json.dumps({"headers": {"cookie": SECRET}}).encode(),
        "something that is not JSON": f"status=C&token={SECRET}".encode(),
        "nothing": b"  ",
    }
    for why, raw in bad_inputs.items():
        message = _refused(lambda raw=raw: shape_request.decode_body(raw))
        check(message is not None and not [bad for bad in FORBIDDEN if bad in message],
              f"ui request: {why} is refused, and the refusal echoes nothing")  # fmt: skip
    bad_calls = {
        "a session header": lambda: shape_request.parse_pairs(["Cookie=x"], headers=True),
        "a CSRF header": lambda: shape_request.parse_pairs(["X-sess-id"], headers=True),
        "a path with a real id": lambda: shape_request.reduce_request(
            {}, label="x", method="PUT", path_template=f"/rest/orgs/{ORG}/tasks/55",
            query={}, headers={}),
        "a full URL as the path": lambda: shape_request.reduce_request(
            {}, label="x", method="PUT", path_template=f"https://{HOST}/rest", query={},
            headers={}),
    }  # fmt: skip
    for why, call in bad_calls.items():
        message = _refused(call)
        check(message is not None and HOST not in message and ORG not in message,
              f"ui request: {why} is refused")  # fmt: skip


def test_00b_swagger_grep() -> None:
    fake = FakeAppliance(apikeys_status=403)
    client = new_client(fake)
    printed: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        rec = probe_00b.Recorder(ENV, client, Path(tmp), echo=printed.append)
        probe_00b.doc_swagger_grep(rec, "required")
        written = list(Path(tmp).glob("*.json"))
    text = " | ".join(printed)
    check("TaskDTO.required [boolean; readOnly=False]: true if the task is required." in text
          and "2 mention(s)" in text and "withheld" in text
          and not [bad for bad in FORBIDDEN if bad in text],
          "00b docs: a description search shows schema prose, withholds a leak")  # fmt: skip
    check(written == [] and fake.seen == [("GET", "/docs/rest-api/ui/swagger.json")],
          "00b docs: a description search is one static GET and stores nothing")  # fmt: skip
    client.close()


def test_00b_docs() -> None:
    fake = FakeAppliance(apikeys_status=403)
    client = new_client(fake)
    printed: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        rec = probe_00b.Recorder(ENV, client, Path(tmp), echo=printed.append)
        probe_00b.doc_index(rec, "Playbook")
        probe_00b.doc_page(rec, "resource_PlaybookREST.html", "orgs|json|curl", 0, 50)
        sent = len(fake.seen)
        for bad in ("../secret.html", "x.html?y=1", "https://example.com/x.html", "a/b.html"):
            probe_00b.doc_page(rec, bad, ".", 0, 5)
    text = "\n".join(printed)
    check("resource_PlaybookREST.html" in text and "[[json_TaskDTO]]" in text,
          "00b docs: pages are listed and a link to a DTO page is shown as [[page]]")  # fmt: skip
    check("withheld" in text and not [bad for bad in FORBIDDEN if bad in text],
          "00b docs: a documentation line carrying a live value is withheld")  # fmt: skip
    check(len(fake.seen) == sent and all(p.startswith("/docs/rest-api/") for _, p in fake.seen),
          "00b docs: only well-formed page names under /docs/rest-api/ are requested")  # fmt: skip
    found: list[str] = []
    rec.echo = found.append
    probe_00b.doc_find(rec, "json_TaskDTO")
    sweep = " | ".join(found)
    check("1 endpoint section(s) match" in sweep and "withheld" in sweep
          and not [bad for bad in FORBIDDEN if bad in sweep]
          and all(p.startswith("/docs/rest-api/") for _, p in fake.seen),
          "00b docs: a sweep names documented endpoints and withholds a leaky one")  # fmt: skip
    client.close()


# P2-03: field definitions laid out like the recorded ones, hostile in every value that is
# not the `required` token, and a description with a documented string `required`.
P2_03_SWAGGER = {
    "swagger": "2.0",
    "definitions": {
        **SWAGGER_DOC["definitions"],
        "FieldDefDTO": {
            "properties": {
                "required": {
                    "type": "string",
                    "enum": ["always", "close", HOST],
                    "description": f"Needed when closing; see {HOST}.",
                },
                "name": {"type": "string"},
            }
        },
    },
}


def _p2_03_rows(type_name: str, requireds: list[Any]) -> list[dict[str, Any]]:
    shape = json.loads(
        (probe_p2_03.OUT_DIR / f"fields_{type_name}.json").read_text(encoding="utf-8")
    )["shape"][0]
    rows = []
    for i, required in enumerate(requireds):
        row: dict[str, Any] = {k: None for k in shape if not k.endswith("?")}
        row.update(
            name=f"{HOSTILE_FIELD}_{i}",
            text=f"Payroll breach on {HOST} for {EMAIL}",
            prefix="properties" if i % 2 else None,
        )
        if required != "<absent>":
            row["required"] = required
        rows.append(row)
    return rows


def _run_p2_03(handler: Any, step: Any) -> tuple[int, str, dict[str, Any], list[tuple[str, str]]]:
    seen: list[tuple[str, str]] = []

    def transport(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return handler(request)

    client = new_client(transport)
    printed: list[str] = []
    files: dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        rec = probe_00b.Recorder(ENV, client, Path(tmp), echo=printed.append)
        code = step(rec)
        probe_p2_03.finish(rec)
        for path in sorted(Path(tmp).glob("*.json")):
            text = path.read_text(encoding="utf-8")
            verify_clean(text, ENV.literals(), what=path.name)
            files[path.name] = json.loads(text)
    client.close()
    return code, " | ".join(printed), files, seen


def test_p2_03() -> None:
    values = {
        "incident": ["always", "close", None, "<absent>", f"see {HOST}", 7, "close"],
        "task": ["<absent>", "always"],
        "artifact": ["<absent>"],
    }

    def good(request: httpx.Request) -> httpx.Response:
        type_name = request.url.path.split("/")[-2]
        return httpx.Response(200, json=_p2_03_rows(type_name, values[type_name]))

    code, text, files, seen = _run_p2_03(good, probe_p2_03.field_tokens)
    org = f"/rest/orgs/{ORG}/types/"
    check(code == 0 and seen == [("GET", f"{org}{t}/fields") for t in probe_p2_03.FIELD_TYPES],
          "p2-03: the field step is exactly three GETs, in a closed order")  # fmt: skip
    inc = files["p2_03_fields_incident_required.json"]
    check(inc["_enums"] == {"required": ["always", "close"]} and inc["_ticket"] == "P2-03"
          and inc["_facts"]["required"]["rows_by_token"]["close"]
          == {"builtin": "1-9", "custom": "1-9", "rows": "1-9"}
          and inc["_facts"]["required"]["rows_by_token"]["always"]["custom"] == "0"
          and inc["_facts"]["required"]["rows_without_a_token"]
          == {"absent": "1-9", "not_a_string": "1-9", "not_a_token": "1-9", "null": "1-9"}
          and inc["_request"]["query_keys"] == ["handle_format", "text_content_output_format"],
          "p2-03: tokens and buckets are kept; a non-token value is only counted")  # fmt: skip
    check(files["p2_03_fields_task_required.json"]["_enums"] == {"required": ["always"]}
          and files["p2_03_fields_artifact_required.json"]["_enums"] == {"required": []},
          "p2-03: each object type keeps its own tokens; none seen is an empty list")  # fmt: skip
    check(not _leaks(text, files) and sorted(files) == [
        "_ledger_p2_03.json", "p2_03_fields_artifact_required.json",
        "p2_03_fields_incident_required.json", "p2_03_fields_task_required.json"],
          "p2-03: no field name, label or connection value gets out")  # fmt: skip

    def drifted(request: httpx.Request) -> httpx.Response:
        rows = _p2_03_rows("incident", ["always"])
        return httpx.Response(200, json=[{**rows[0], "brand_new_key": 1}])

    for why, handler in {
        "an unrecorded key": drifted,
        "a 403": lambda _: httpx.Response(403, json={"message": f"denied {KEY_ID}"}),
        "a wrapper instead of a list": lambda _: httpx.Response(200, json={"entities": []}),
    }.items():
        code, text, files, seen = _run_p2_03(handler, probe_p2_03.field_tokens)
        check(code == probe_p2_03.EXIT_STOP and len(seen) == 1 and "STOPPED" in text
              and sorted(files) == ["_ledger_p2_03.json"] and not _leaks(text, files),
              f"p2-03: {why} stops the run after one GET; nothing is written")  # fmt: skip

    code, text, files, seen = _run_p2_03(
        lambda _: httpx.Response(200, json=P2_03_SWAGGER), probe_p2_03.swagger_required
    )
    doc = files["p2_03_doc_swagger_required.json"]["_facts"]
    check(code == 0 and seen == [("GET", "/docs/rest-api/ui/swagger.json")]
          and list(doc["data_types"]) == ["FieldDefDTO"]
          and doc["data_types"]["FieldDefDTO"]["enum"] == ["always", "close"]
          and doc["data_types"]["FieldDefDTO"]["type"] == "string"
          and doc["data_types"]["FieldDefDTO"]["description_mentions_closing"] is True
          and doc["data_types_with_a_boolean_required"] == "1-9",
          "p2-03: the description step is one static GET; type, enum, a flag")  # fmt: skip
    check("withheld" in text and not _leaks(text, files) and "Needed when" not in json.dumps(files),
          "p2-03: a description is shown, never stored, withheld if it leaks")  # fmt: skip
    for method in ("PUT", "POST", "PATCH", "DELETE"):
        client = new_client(lambda _: httpx.Response(200, json=[]))
        try:
            client.request(method, f"/rest/orgs/{ORG}/types/incident/fields", "t", json_body={})
            refused = False
        except ProbePolicyError:
            refused = True
        client.close()
        check(refused, f"p2-03: {method} to a field list is refused by the client it uses")


# P2-04: the workflow research. A description, two reference pages, a collection and one
# workflow object laid out like the appliance's, hostile in every value; a workflow XML
# with standard, vendor and unknown namespaces, an embedded JSON payload that refers to a
# function, an embedded script and a condition expression. None of it may get out.
WF_ID = 660042
WF_DETAIL_PATH = "/orgs/{org_id}/workflows/{workflow_id}"
P2_04_SWAGGER = {
    "swagger": "2.0",
    "paths": {
        "/orgs/{org_id}/workflows": {
            "get": {
                "summary": f"Lists workflows at {HOST}",
                "parameters": [{"name": "handle_format", "in": "query"}],
                "responses": {"200": {"schema": {"$ref": "#/definitions/WorkflowListDTO"}}},
            },
            "post": {"summary": "creates", "responses": {"200": {}}},
        },
        WF_DETAIL_PATH: {
            "get": {
                "summary": f"one workflow; see {EMAIL}",
                "parameters": [{"name": "workflow_id", "in": "path"}],
                "responses": {"200": {"schema": {"$ref": "#/definitions/WorkflowDTO"}}},
            },
            "put": {"responses": {"200": {}}},
        },
        f"/orgs/{ORG}/workflows/{WF_ID}": {"get": {}},  # digits: never a template
    },
    "definitions": {
        "WorkflowDTO": {
            "description": f"Represents a workflow on {HOST}.",
            "properties": {
                "workflow_id": {"type": "integer", "description": "The ID."},
                "programmatic_name": {"type": "string", "description": EMAIL},
                "content": {"$ref": "#/definitions/WorkflowContentDTO"},
                "creator_id": {"type": "integer", "readOnly": True},
            },
            "required": ["workflow_id"],
        },
        "WorkflowContentDTO": {
            "properties": {"xml": {"type": "string"}, "workflow_id": {"type": "integer"}}
        },
        "WorkflowListDTO": {
            "properties": {
                "entities": {"type": "array", "items": {"$ref": "#/definitions/WorkflowDTO"}}
            }
        },
        "TaskDTO": {"properties": {"name": {"type": "string"}}},
    },
}
WORKFLOW_DTO_PAGE = (
    "<table><tr><th>name</th><th>data type</th><th>constraints</th><th>description</th></tr>"
    f"<tr><td>workflow_id</td><td>number</td><td></td><td>The ID on {HOST}. readonly</td></tr>"
    "<tr><td>programmatic_name</td><td>string</td><td>required</td><td>x</td></tr>"
    '<tr><td>content</td><td><a href="json_WorkflowContentDTO.html">WorkflowContentDTO</a>'
    f"</td><td></td><td>for {EMAIL}</td></tr></table>"
)
WORKFLOW_REST_PAGE = (
    "<ul><li>GET /orgs/{org_id}/workflows</li><li>GET " + WF_DETAIL_PATH + "</li></ul>"
    "<h2>GET /orgs/{org_id}/workflows</h2><p>Lists the workflows.</p>"
    "<table><caption>Response Body</caption><tr><td>application/json</td><td>"
    '<a href="json_WorkflowListDTO.html">WorkflowListDTO</a></td><td>x</td></tr></table>'
    "<h2>GET " + WF_DETAIL_PATH + "</h2>"
    f"<p>Gets one workflow from https://{HOST}/rest for {EMAIL}.</p>"
    "<table><caption>Request Parameters</caption><tr><td>workflow_id</td><td>path</td>"
    "<td>id</td></tr></table>"
    "<table><caption>Response Codes</caption><tr><td>200</td><td>Success</td></tr>"
    f"<tr><td>404</td><td>Not on {PRIVATE_IP}</td></tr></table>"
    "<table><caption>Response Body</caption><tr><td>application/json</td><td>"
    '<a href="json_WorkflowDTO.html">WorkflowDTO</a></td><td>x</td></tr></table>'
    f"<h2>GET /orgs/{ORG}/leaky/{WF_ID}</h2><p>curl https://{HOST}/rest</p>"
)
SCRIPT_BODY = f'incident.addNote("{PRIVATE_IP}")  # {SECRET}'
FUNCTION_PAYLOAD = json.dumps(
    {
        "inputs": {KEY_ID: {"input_type": "text", "text": EMAIL}},
        "post_processing_script": SCRIPT_BODY,
        "result_name": "acme_result",
        "function": {"uuid": KEY_ID, "name": "fn_acme_lookup", "id": 4242},
    }
)
OTHER_PAYLOAD = json.dumps(
    {"properties": {"acme_site": OTHER_IP}, "fn_acme_lookup": 1, "owner": "jdoe", "kind": "text"}
)
WORKFLOW_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
  xmlns:bpmndi="http://www.omg.org/spec/BPMN/20100524/DI"
  xmlns:resilient="http://resilient.ibm.com/bpmn" xmlns:acme="https://{HOST}/schema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="https://{HOST}/x.xsd" id="{KEY_ID}" targetNamespace="https://{HOST}/tn">
  <process id="playbook_acme_{INCIDENT_ID}" isExecutable="true" name="Payroll breach on {HOST}">
    <startEvent id="StartEvent_1"><outgoing>SequenceFlow_1</outgoing></startEvent>
    <serviceTask id="ServiceTask_1" name="fn_acme_lookup" resilient:type="function">
      <extensionElements>
        <resilient:function uuid="{KEY_ID}">{html.escape(FUNCTION_PAYLOAD)}</resilient:function>
        <acme:thing>{html.escape(OTHER_PAYLOAD)}</acme:thing>
        <resilient:script>{html.escape(SCRIPT_BODY)}</resilient:script>
      </extensionElements>
      <incoming>SequenceFlow_1</incoming><outgoing>SequenceFlow_2</outgoing>
    </serviceTask>
    <exclusiveGateway id="Gateway_1" name="jdoe decides"/>
    <endEvent id="EndEvent_1"/>
    <sequenceFlow id="SequenceFlow_1" sourceRef="StartEvent_1" targetRef="ServiceTask_1"/>
    <sequenceFlow id="SequenceFlow_2" sourceRef="ServiceTask_1" targetRef="Gateway_1">
      <conditionExpression xsi:type="tFormalExpression">{HOST} == 1</conditionExpression>
    </sequenceFlow>
    <sequenceFlow id="SequenceFlow_3" sourceRef="Gateway_1" targetRef="EndEvent_1"/>
  </process>
  <bpmndi:BPMNDiagram id="d1"><bpmndi:BPMNPlane bpmnElement="playbook_acme"/></bpmndi:BPMNDiagram>
</definitions>
"""


def _p2_04_row(workflow_id: int = WF_ID, *, content: bool = True) -> dict[str, Any]:
    row: dict[str, Any] = {
        "workflow_id": workflow_id,
        "uuid": KEY_ID,
        "programmatic_name": "acme_workflow",
        "name": f"Payroll breach on {HOST}",
        "description": f"see https://{HOST}/x from {PRIVATE_IP}",
        "object_type": "incident",
        "creator_id": 7,
        "actions": [{"id": 5, "name": f"Isolate {HOST}"}],
    }
    if content:
        row["content"] = {"xml": WORKFLOW_XML, "workflow_id": workflow_id, "version": 3}
    return row


def p2_04_handler(
    *, rows: list[dict[str, Any]] | None = None, status: int = 200, wrapper: bool = True
) -> Any:
    """The static documentation, and the collection: rows as given (one by default)."""
    listing = [_p2_04_row()] if rows is None else rows

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/docs/rest-api/ui/swagger"):
            return httpx.Response(200, json=P2_04_SWAGGER)
        if path.startswith("/docs/rest-api/json_WorkflowDTO"):
            return httpx.Response(200, html=WORKFLOW_DTO_PAGE)
        if path.startswith("/docs/rest-api/resource_WorkflowREST"):
            return httpx.Response(200, html=WORKFLOW_REST_PAGE)
        if path == f"/rest/orgs/{ORG}/workflows":
            if status != 200:
                return httpx.Response(status, json={"message": f"no {KEY_ID} at {HOST}"})
            return httpx.Response(200, json={"entities": listing} if wrapper else listing)
        return httpx.Response(404, json={"message": f"no route at {HOST}"})

    return handler


def _run_p2_04(
    handler: Any, *steps: Any, env: ProbeEnv = ENV, out_dir: Path | None = None
) -> tuple[list[int], str, dict[str, Any], list[Any]]:
    seen: list[tuple[str, str, str]] = []

    def transport(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.url.query.decode()))
        return handler(request)

    client = new_client(transport)
    printed: list[str] = []
    files: dict[str, Any] = {}
    codes: list[int] = []
    with tempfile.TemporaryDirectory() as tmp:
        where = out_dir or Path(tmp)
        rec = probe_00b.Recorder(env, client, where, echo=printed.append)
        for step in steps:
            codes.append(step(rec))
        probe_p2_04.finish(rec)
        for path in sorted(where.glob("*.json")):
            text = path.read_text(encoding="utf-8")
            verify_clean(text, env.literals(), what=path.name)
            files[path.name] = json.loads(text)
    client.close()
    return codes, " | ".join(printed), files, seen


XML_FACT_KEYS = {
    "parsed", "root", "namespace_classes", "elements", "attribute_names_by_element",
    "source_target_attribute_names_by_element",
    "elements_with_both_a_source_and_a_target_attribute",
    "identifier_attribute_names_by_element",
    "elements_referenced_by_a_source_or_target_attribute", "referenced_values",
    "referenced_values_that_are_element_identifiers",
    "every_referenced_value_is_an_element_identifier",
    "elements_with_text_by_element", "json_payload_shapes_by_element",
    "json_payloads_that_did_not_parse", "function_candidate_keys",
    "identity_like_keys_under_function_candidates", "function_candidate_value_forms",
}  # fmt: skip
ROW_FACT_KEYS = {
    "content_keys", "xml_bearing_property", "xml_bearing_property_in_content",
    "xml_is_string", "xml_size",
}  # fmt: skip
XML_FORBIDDEN = (*FORBIDDEN, "fn_acme_lookup", "acme_result", "acme_workflow", "SequenceFlow_1",
                 "StartEvent_1", "ServiceTask_1", "addNote", "== 1", "resilient.ibm.com",
                 "omg.org", "tFormalExpression", "playbook_acme", str(WF_ID))  # fmt: skip
WORKFLOW_KEYS = ["actions", "content", "creator_id", "description", "name", "object_type",
                 "programmatic_name", "uuid", "workflow_id"]  # fmt: skip


def test_p2_04() -> None:
    org = f"/rest/orgs/{ORG}"
    wf = org + "/workflows"
    listing_query = "handle_format=names&text_content_output_format=always_text"
    get_detail = "GET " + WF_DETAIL_PATH

    # R1: one static GET; operations, the DTO family, no prose.
    codes, text, files, seen = _run_p2_04(p2_04_handler(), probe_p2_04.swagger)
    facts = files["p2_04_doc_swagger_workflows.json"]["_facts"]
    ops = facts["paths_mentioning_workflows"]
    definitions = facts["definitions"]
    check(
        codes == [0]
        and seen == [("GET", "/docs/rest-api/ui/swagger.json", "")]
        and sorted(ops)
        == [
            "GET /orgs/{org_id}/workflows",
            get_detail,
            "POST /orgs/{org_id}/workflows",
            "PUT " + WF_DETAIL_PATH,
        ]
        and ops[get_detail]["parameters"] == {"workflow_id": "path"}
        and ops[get_detail]["responses"]["200"]["ref"] == "WorkflowDTO"
        and sorted(definitions) == ["WorkflowContentDTO", "WorkflowDTO"]
        and definitions["WorkflowDTO"]["properties"]["content"]["ref"] == "WorkflowContentDTO"
        and definitions["WorkflowContentDTO"]["properties"]["xml"]["type"] == "string"
        and definitions["WorkflowDTO"]["read_only_properties"] == ["creator_id"]
        and facts["definitions_named_like_a_workflow"]
        == ["WorkflowContentDTO", "WorkflowDTO", "WorkflowListDTO"],
        "p2-04 R1: the /workflows operations and the WorkflowDTO family, as names and types",
    )
    check(
        not _leaks(text, files)
        and "Represents" not in json.dumps(files)
        and "Lists workflows" not in json.dumps(files)
        and "leaky" not in json.dumps(files),
        "p2-04 R1: no description, summary, digit path or connection value gets out",
    )

    # R2: two static GETs; the data type and the endpoint sections; hostile lines withheld.
    codes, text, files, seen = _run_p2_04(
        p2_04_handler(), lambda rec: probe_p2_04.doc_pages(rec, 1, 40)
    )
    dto = files["p2_04_doc_type_WorkflowDTO.json"]["_facts"]["properties"]
    rest = files["p2_04_doc_workflow_rest.json"]["_facts"]["endpoints"]
    check(
        codes == [0]
        and [s[1] for s in seen]
        == ["/docs/rest-api/json_WorkflowDTO.html", "/docs/rest-api/resource_WorkflowREST.html"]
        and dto["workflow_id"]
        == {
            "type": "number",
            "constraints": "",
            "documented_read_only": True,
            "documented_create_only": False,
        }
        and dto["content"]["type"] == "WorkflowContentDTO"
        and sorted(rest) == ["GET /orgs/{org_id}/workflows", get_detail]
        and rest[get_detail]["response_body_type"] == "WorkflowDTO"
        and rest[get_detail]["response_codes"] == [200, 404]
        and rest[get_detail]["parameters"] == {"workflow_id": "path"},
        "p2-04 R2: the data type and the two documented endpoint sections",
    )
    check(
        "withheld" in text
        and not _leaks(text, files)
        and "leaky" not in json.dumps(files)
        and sorted(files["_ledger_p2_04.json"]["documentation_pages_read"])
        == ["json_WorkflowDTO.html", "resource_WorkflowREST.html"],
        "p2-04 R2: hostile lines are withheld; nothing leaks; the pages are on the ledger",
    )

    # R3 denied, or answered in a container the record did not verify: stop, nothing
    # about the answer is written.
    for why, handler in {
        "a 403": p2_04_handler(status=403),
        "a bare list": p2_04_handler(wrapper=False),
    }.items():
        codes, text, files, seen = _run_p2_04(handler, probe_p2_04.swagger, probe_p2_04.workflows)
        check(
            codes == [0, probe_p2_04.EXIT_STOP]
            and len(seen) == 2
            and "STOPPED" in text
            and "p2_04_workflows.json" not in files
            and "p2_04_workflow_xml.json" not in files
            and files["_ledger_p2_04.json"]["requests"][-1]["path"]
            == "/rest/orgs/{org_id}/workflows"
            and not _leaks(text, files),
            f"p2-04 R3: {why} stops the run after the one GET; only the ledger row is kept",
        )

    # R3 empty: recorded; nothing analysed; still one GET.
    codes, text, files, seen = _run_p2_04(
        p2_04_handler(rows=[]), probe_p2_04.swagger, probe_p2_04.workflows
    )
    check(
        codes == [0, 0]
        and seen[1] == ("GET", wf, listing_query)
        and len(seen) == 2
        and files["p2_04_workflows.json"]["_facts"]
        == {
            "rows": "0",
            "row_keys": [],
            "documented_and_observed": [],
            "documented_only": [],
            "observed_only": [],
        }
        and files["p2_04_workflows.json"]["shape"] == {"entities": []}
        and "R5 NOT RUN" in text
        and "p2_04_workflow_xml.json" not in files,
        "p2-04 R3: an empty collection is recorded and nothing is analysed",
    )

    # One row, no selector: R5 runs over that row, and no second request is sent.
    codes, text, files, seen = _run_p2_04(
        p2_04_handler(), probe_p2_04.swagger, probe_p2_04.workflows
    )
    row = files["p2_04_workflows.json"]
    check(
        codes == [0, 0]
        and seen[1:] == [("GET", wf, listing_query)]
        and "the only workflow" in text
        and row["_facts"]
        == {
            "rows": "1-9",
            "row_keys": WORKFLOW_KEYS,
            "documented_and_observed": [
                "content",
                "creator_id",
                "programmatic_name",
                "workflow_id",
            ],
            "documented_only": [],
            "observed_only": ["actions", "description", "name", "object_type", "uuid"],
        }
        and row["shape"]["entities"][0]["content"]
        == {"version": "int", "workflow_id": "int", "xml": "str"}
        and row["_enums"] == {"object_type": ["incident"]},
        "p2-04 R3: the row as keys and types, against the documented WorkflowDTO; one GET",
    )
    xml = files["p2_04_workflow_xml.json"]["_facts"]
    check(
        set(xml) == XML_FACT_KEYS | ROW_FACT_KEYS
        and xml["parsed"] is True
        and (
            xml["content_keys"],
            xml["xml_bearing_property"],
            xml["xml_is_string"],
            xml["xml_size"],
        )
        == (["version", "workflow_id", "xml"], "xml", True, "<10KB")
        and xml["root"]
        == {
            "namespace_class": "bpmn_model",
            "local_name": "definitions",
            "attribute_names": ["id", "schemaLocation", "targetNamespace"],
        }
        and sorted(xml["namespace_classes"]) == ["bpmn_di", "bpmn_model", "other", "vendor_ibm"]
        and xml["namespace_classes"]["vendor_ibm"] == ["function", "script"]
        and xml["namespace_classes"]["other"] == ["thing"]
        and "serviceTask" in xml["namespace_classes"]["bpmn_model"]
        and xml["attribute_names_by_element"]["vendor_ibm:function"] == ["uuid"]
        and xml["attribute_names_by_element"]["bpmn_model:serviceTask"] == ["id", "name", "type"]
        and xml["elements"] == "10-99",
        "p2-04 R5: root, namespace classes, element and attribute names, buckets",
    )
    check(
        xml["source_target_attribute_names_by_element"]
        == {"bpmn_model:sequenceFlow": ["sourceRef", "targetRef"]}
        and xml["elements_with_both_a_source_and_a_target_attribute"] == "1-9"
        and xml["identifier_attribute_names_by_element"]["bpmn_model:startEvent"] == ["id"]
        and xml["identifier_attribute_names_by_element"]["vendor_ibm:function"] == ["uuid"]
        and "bpmn_model:incoming" not in xml["identifier_attribute_names_by_element"]
        and xml["elements_referenced_by_a_source_or_target_attribute"]
        == [
            "bpmn_model:endEvent",
            "bpmn_model:exclusiveGateway",
            "bpmn_model:serviceTask",
            "bpmn_model:startEvent",
        ]
        and xml["referenced_values"] == "1-9"
        and xml["referenced_values_that_are_element_identifiers"] == "1-9"
        and xml["every_referenced_value_is_an_element_identifier"] is True,
        "p2-04 R5: edges by attribute name; their values are element identifiers, as a fact",
    )
    payloads = xml["json_payload_shapes_by_element"]
    check(
        payloads["vendor_ibm:function"]
        == {
            "function": {"id": "int", "name": "str", "uuid": "str"},
            "inputs": {"<name>": {"input_type": "str", "text": "str"}},
            "post_processing_script": "str",
            "result_name": "str",
        }
        and payloads["other:thing"]
        == {"<name>": "int", "kind": "str", "owner": "str", "properties": {"<name>": "str"}}
        and xml["function_candidate_keys"]
        == {"vendor_ibm:function.function": ["id", "name", "uuid"]}
        and xml["identity_like_keys_under_function_candidates"]
        == {"vendor_ibm:function.function": ["id", "name", "uuid"]}
        and xml["function_candidate_value_forms"]
        == {
            "vendor_ibm:function.function": ["object"],
            "vendor_ibm:function.function.id": ["integer"],
            "vendor_ibm:function.function.name": ["string"],
            "vendor_ibm:function.function.uuid": ["uuid_shaped_string"],
        }
        and xml["elements_with_text_by_element"]["vendor_ibm:script"] == "1-9"
        and xml["json_payloads_that_did_not_parse"] == "0",
        "p2-04 R5: the function reference as key names, JSON types and value forms; a value "
        "used as a key is collapsed; the script element is counted, never read",
    )
    blob = text + json.dumps(files)
    check(
        not [bad for bad in XML_FORBIDDEN if bad in blob]
        and WORKFLOW_XML not in blob
        and "<definitions" not in blob
        and SCRIPT_BODY not in blob,
        "p2-04 R5: no XML text, script, expression, name, id, uuid, URL or value gets out",
    )
    check(
        sorted(files)
        == [
            "_ledger_p2_04.json",
            "p2_04_doc_swagger_workflows.json",
            "p2_04_workflow_xml.json",
            "p2_04_workflows.json",
        ]
        and files["_ledger_p2_04.json"]["refused_by_policy"] == []
        and [r["path"] for r in files["_ledger_p2_04.json"]["requests"]]
        == ["/docs/rest-api/ui/swagger.json", "/rest/orgs/{org_id}/workflows"],
        "p2-04: exactly these fixtures and ledger rows, as templates; no detail route",
    )

    # Several rows: no selector stops; the owner's selector picks exactly one; a selector
    # that matches nothing stops. The chosen id never gets out.
    two = [_p2_04_row(WF_ID), _p2_04_row(WF_ID + 1)]
    codes, text, files, seen = _run_p2_04(
        p2_04_handler(rows=two), probe_p2_04.swagger, probe_p2_04.workflows
    )
    check(
        codes == [0, probe_p2_04.EXIT_STOP]
        and len(seen) == 2
        and "explicit research workflow selector is required" in text
        and "p2_04_workflows.json" in files
        and "p2_04_workflow_xml.json" not in files
        and not [bad for bad in XML_FORBIDDEN if bad in text + json.dumps(files)],
        "p2-04 R3: several workflows and no selector: recorded, nothing analysed, stop",
    )
    chosen = replace(ENV, workflow_id=str(WF_ID + 1))
    codes, text, files, seen = _run_p2_04(
        p2_04_handler(rows=two), probe_p2_04.swagger, probe_p2_04.workflows, env=chosen
    )
    check(
        codes == [0, 0]
        and len(seen) == 2
        and "owner-designated" in text
        and files["p2_04_workflow_xml.json"]["_facts"]["parsed"] is True
        and str(WF_ID + 1) not in text + json.dumps(files),
        "p2-04 R3: the owner's selector picks one of several; its id is never written",
    )
    for why, value in (("an id that matches no row", str(WF_ID + 7)), ("a non-integer", "x")):
        codes, text, files, seen = _run_p2_04(
            p2_04_handler(rows=two), probe_p2_04.swagger, probe_p2_04.workflows,
            env=replace(ENV, workflow_id=value),
        )  # fmt: skip
        check(
            codes == [0, probe_p2_04.EXIT_STOP]
            and len(seen) == 2
            and "STOPPED" in text
            and "p2_04_workflow_xml.json" not in files,
            f"p2-04 R3: {why} as the selector stops the run",
        )

    # A row without XML under content: recorded as such; nothing parsed.
    codes, text, files, seen = _run_p2_04(
        p2_04_handler(rows=[_p2_04_row(content=False)]), probe_p2_04.swagger,
        probe_p2_04.workflows,
    )  # fmt: skip
    check(
        codes == [0, 0]
        and len(seen) == 2
        and "R5 NOT RUN" in text
        and files["p2_04_workflow_xml.json"]["_facts"]
        == {
            "content_keys": [],
            "xml_bearing_property": None,
            "xml_bearing_property_in_content": False,
            "xml_is_string": False,
            "xml_size": "n/a",
            "parsed": False,
        },
        "p2-04 R3: a row without XML is recorded as such and nothing is parsed",
    )

    # The ledger keeps an earlier observation of the same step when the status changed.
    with tempfile.TemporaryDirectory() as tmp:
        where = Path(tmp)
        _run_p2_04(p2_04_handler(status=403), probe_p2_04.workflows, out_dir=where)
        _, _, files, _ = _run_p2_04(p2_04_handler(), probe_p2_04.workflows, out_dir=where)
    rows_by_step = {r["step"]: r["status"] for r in files["_ledger_p2_04.json"]["requests"]}
    check(
        rows_by_step == {"workflows@403": 403, "workflows": 200},
        "p2-04: a re-run keeps the earlier answer of the same step on the ledger",
    )

    # R5 alone: hostile documents are refused unparsed, and nothing is ever fetched.
    external = (f'<!DOCTYPE x [<!ENTITY e SYSTEM "https://{HOST}/secret">]>'
                "<definitions>&e;</definitions>")  # fmt: skip
    for why, document, refusal in (
        ("a DTD with an external entity", external, "DOCTYPE or ENTITY"),
        ("an entity declaration", f'<!ENTITY a "{HOST}"><d>&a;</d>', "DOCTYPE or ENTITY"),
        ("an undefined entity reference", "<d>&acme;</d>", "does not predefine"),
        ("malformed XML", "<d><e></d>", "malformed"),
        ("a document over the size bound", "<d>" + "x" * probe_p2_04.MAX_XML_CHARS + "</d>",
         "larger"),
        ("more elements than the bound",
         "<d>" + "<e/>" * (probe_p2_04.MAX_XML_NODES + 1) + "</d>", "more elements"),
    ):  # fmt: skip
        facts = probe_p2_04.analyse_xml(document)
        check(
            facts["parsed"] is False
            and refusal in facts["refused"]
            and set(facts) == {"parsed", "refused"}
            and HOST not in json.dumps(facts),
            f"p2-04 R5: {why} is refused unparsed",
        )
    schema_ref = (
        f'<d xmlns="https://{HOST}/ns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        f' xsi:schemaLocation="https://{HOST}/ns https://{HOST}/d.xsd"><e a="{EMAIL}"/></d>'
    )
    facts = probe_p2_04.analyse_xml(schema_ref)
    check(
        facts["parsed"] is True
        and facts["root"]["namespace_class"] == "other"
        and facts["namespace_classes"] == {"other": ["d", "e"]}
        and facts["attribute_names_by_element"] == {"other:d": ["schemaLocation"], "other:e": ["a"]}
        and facts["every_referenced_value_is_an_element_identifier"] is False
        and HOST not in json.dumps(facts)
        and EMAIL not in json.dumps(facts),
        "p2-04 R5: a schema location and an unknown namespace are classified, never fetched",
    )
    classify = probe_p2_04.classify_namespace
    check(
        classify("http://www.omg.org/spec/BPMN/20100524/MODEL") == "bpmn_model"
        and classify("http://www.omg.org/spec/BPMN/20100524/MODEL/") == "other"
        and classify("http://resilient.ibm.com/bpmn") == "vendor_ibm"
        and classify("http://ibm.com.acme.example/x") == "other"
        and classify("urn:acme:bpmn") == "other"
        and classify("") == "other",
        "p2-04 R5: namespaces are recognised exactly or by the vendor host, else other",
    )
    forms = probe_p2_04._form_of
    check(
        (
            forms(4242),
            forms(KEY_ID),
            forms("4242"),
            forms("fn_x"),
            forms({"id": 1}),
            forms([1]),
            forms(None),
            forms(True),
        )
        == (
            "integer",
            "uuid_shaped_string",
            "digits_string",
            "string",
            "object",
            "array",
            "null",
            "bool",
        ),
        "p2-04 R5: a reference value is reported by its form and never by its content",
    )

    # The client it uses refuses every other method on the workflow paths.
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        for path in (wf, f"{wf}/{WF_ID}"):
            client = new_client(lambda _: httpx.Response(200, json={}))
            try:
                client.request(method, path, "t", json_body={})
                refused = False
            except ProbePolicyError:
                refused = True
            client.close()
            check(refused, f"p2-04: {method} on a workflow path is refused by the client it uses")


def main() -> int:
    tests = (test_policy, test_verifier, test_shape, test_full_run, test_smoke,
             test_dotenv_encodings,
             test_errors_carry_no_url,
             test_00b_tls, test_00b_run, test_00b_stops_on_a_mutating_key,
             test_00b_scan_ceiling, test_00b_execution_query, test_00b_designated_task,
             test_00b_designated_objects, test_00b_designated_task_check, test_00b_pair,
             test_task_candidate, test_00b_format_headers,
             test_00b_tasktree, test_00b_preflight, test_experiment_happy_path,
             test_experiment_stops, test_experiment_documented_source,
             test_experiment_client_policy,
             test_00b_threading, test_shape_request, test_00b_swagger_grep,
             test_00b_docs, test_p2_03, test_p2_04)  # fmt: skip
    for test in tests:
        test()
    print(f"\n{'OK' if not failures else 'FAILED'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
