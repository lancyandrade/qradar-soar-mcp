"""Offline self-test of the P2-00 probe tooling. No network, no appliance.

    uv run python scripts/probe/selftest.py

It proves, against an in-process fake appliance that stuffs every response with
environment-like values:

1. the HTTP policy refuses every write, every POST outside the three read-only
   ones, and every query body that is not pure paging/sorting/search criteria,
   before anything is sent;
2. the verifier rejects each category of environment-specific text and the
   writer refuses to put a rejected artefact on disk;
3. shapes never carry administrator-chosen names or appliance values;
4. a full run of the probe plan leaves none of the connection values, fake
   private addresses, e-mail addresses, host names, UUIDs or object ids in any
   fixture, in the ledger, or in what is printed;
5. a transport failure is reported as a category, never with the URL.
"""

from __future__ import annotations

import json
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx
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
    }


class FakeAppliance:
    def __init__(self, session_status: int = 200) -> None:
        self.session_status = session_status
        self.seen: list[tuple[str, str]] = []
        self.bodies: list[Any] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        self.seen.append((method, path))
        if path.startswith("/docs/rest-api/index"):
            return httpx.Response(200, html='<a href="resource_PlaybookREST.html">x</a>')
        if path.startswith("/docs/rest-api/resource_PlaybookREST"):
            body = (
                "<h2>GET /orgs/{org_id}/playbooks</h2><h2>POST /orgs/{org_id}/playbooks/query_paged"
                f"</h2><h2>GET /orgs/{ORG}/leaky/{INCIDENT_ID}</h2>"
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
            return httpx.Response(200, json=nasty_row(1))
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
    check(len(fake.seen) == len(allowed), "policy: GET and exactly three read-only POSTs pass")
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


def main() -> int:
    tests = (test_policy, test_verifier, test_shape, test_full_run, test_smoke,
             test_dotenv_encodings,
             test_errors_carry_no_url)  # fmt: skip
    for test in tests:
        test()
    print(f"\n{'OK' if not failures else 'FAILED'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
