"""P2-00b: the controlled task-status experiment. The only file here that can send a PUT.

    uv run python scripts/probe/guarded.py task_experiment.py --source documented  # dry run
    uv run python scripts/probe/guarded.py task_experiment.py --source documented --execute

Research tooling: it is not part of the installed package and nothing in ``src/`` uses it.

Owner-authorised for a disposable lab appliance and one owner-designated disposable task
(``P2_PROBE_INCIDENT_ID`` / ``P2_PROBE_TASK_ID``). What the code enforces, not the operator:

* **Fixed operations, nothing else.** ``ExperimentClient`` has no general request method. It
  can GET the designated task, GET the designated incident's task tree, GET the designated
  incident, and PUT the designated task. Every path is built from the designated ids; none
  is an argument.
* **Two sources, never mixed.** ``--source documented`` builds every candidate from the
  documented ``GET /tasks/{task_id}`` and never reads the task tree; ``--source tasktree``
  (the default, kept for provenance) builds it from the task tree, as the web UI does.
* **A hard ceiling**: 7 GET, 2 PUT, 9 requests. An attempt counts even if it fails. Nothing
  is ever retried, and there is no alternate body and no fallback representation.
* **A PUT takes a ``Candidate``, not a body.** It must come from
  ``task_candidate.build_candidate``, be ``ok``, differ from the fresh read in ``status``
  only, and be for the designated task. The first PUT must close (``C``); the second may
  only reopen (``O``), once, and only after ``task_candidate.rollback_stops`` is empty.
* **Fresh reads.** Each candidate is built from a task-tree read taken immediately before
  it. Browser fixtures supply structure to compare against, never a value.
* **A phase change is a hard stop.** If the incident's ``phase_id`` differs after the close,
  no reopen is sent: nothing shows that reopening reverses a phase transition.
* **Verified TLS only**, the two format headers the web UI sends, no query string.

What is printed and stored is statuses, key names, JSON types, booleans and fixed
sentences. Ids, the phase, timestamps, names and text stay in memory.

The task tree is an undocumented, UI-internal endpoint. It was used because it is the read
whose representation matches what the UI was observed to send; that is a research finding,
not a claim that it is a supported API. The documented source then proved sufficient, so
nothing needs the task tree (docs/soar-api-verified.md §3.1).
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx
import task_candidate
from probe_00b import (
    INC,
    OUT_DIR,
    PUT_TEMPLATE,
    STATUS_CHANGE_FLAGS,
    TASKTREE,
    UI_FORMAT_PARAMS,
    _class_of,
    _fixture,
    _task_facts,
    narrow_tasktree,
    status_change_flag_values,
    status_change_flags,
    verified_context,
)
from probe_env import ProbeEnv, ProbeEnvError, load_env
from safe_http import DEFAULT_MAX_BYTES, Result, size_bucket
from sanitise import UnsafeArtefactError, dump_verified, safe_text, shape_of
from task_candidate import Candidate
from tls_check import categorise

MAX_GET, MAX_PUT = 7, 2
MAX_TOTAL = task_candidate.MAX_EXPERIMENT_REQUESTS
STATUS_DTO_KEYS = frozenset({"success", "title", "message", "hints", "error_code", "error_payload"})
# Prerequisites of the experiment that must still hold after the close: if one of these
# changes, that is an unexpected side effect, and the pre-approved reopen is not sent.
INVARIANT_KEYS = ("id", "inc_id", "active", "frozen", "custom", "required")
_SCHEMA_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
EXIT_NOT_EXECUTED, EXIT_STOPPED = 6, 7
Facts = dict[str, Any]


class ExperimentPolicyError(RuntimeError):
    """The request is outside the experiment. Nothing was sent. A fixed sentence."""


class ExperimentClient:
    """Three fixed operations on the designated objects, under a hard request ceiling."""

    def __init__(
        self,
        env: ProbeEnv,
        ssl_context: ssl.SSLContext,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not (env.incident_id.isdigit() and env.task_id.isdigit() and env.org_id.isdigit()):
            raise ExperimentPolicyError("the designated ids must be plain numbers")
        if not isinstance(ssl_context, ssl.SSLContext) or not ssl_context.check_hostname:
            raise ExperimentPolicyError("the experiment needs a verifying TLS context")
        org = f"/rest/orgs/{env.org_id}"
        self._env = env
        self._tree = f"{org}/incidents/{env.incident_id}/tasktree"
        self._incident = f"{org}/incidents/{env.incident_id}"
        self._task = f"{org}/tasks/{env.task_id}"
        self.sent: list[Result] = []
        self.targets: list[str] = []
        self._client = httpx.Client(
            base_url=env.base_url,
            auth=(env.key_id, env.key_secret),
            verify=ssl_context,
            timeout=env.timeout,
            follow_redirects=False,
            transport=transport,
            headers={"Accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    @property
    def gets(self) -> int:
        return sum(1 for r in self.sent if r.method == "GET")

    @property
    def puts(self) -> int:
        return sum(1 for r in self.sent if r.method == "PUT")

    def get_tree(self) -> Result:
        return self._send("GET", self._tree, TASKTREE, None)

    def get_incident(self) -> Result:
        return self._send("GET", self._incident, INC, None)

    def get_task(self) -> Result:
        """The documented single-task read of the designated task."""
        return self._send("GET", self._task, PUT_TEMPLATE, None)

    def put_task(self, candidate: Candidate) -> Result:
        """ONE attempt. The candidate is checked again here; the body is never an argument."""
        expected = "C" if not self.targets else "O"
        body = candidate.body if isinstance(candidate, Candidate) else None
        if not isinstance(candidate, Candidate) or not candidate.ok or body is None:
            raise ExperimentPolicyError("a PUT needs a candidate that was built without a stop")
        if candidate.changed_keys != task_candidate.CHANGED_KEYS:
            raise ExperimentPolicyError("a candidate may differ from the fresh read in status only")
        if len(self.targets) >= MAX_PUT or candidate.target != expected:
            raise ExperimentPolicyError("the experiment is one close, then at most one reopen")
        if body.get("status") != candidate.target:
            raise ExperimentPolicyError("the candidate does not carry its own target status")
        if str(body.get("id")) != self._env.task_id:
            raise ExperimentPolicyError("the candidate is not the designated task")
        if str(body.get("inc_id")) != self._env.incident_id:
            raise ExperimentPolicyError("the candidate is not in the designated incident")
        self.targets.append(candidate.target)
        return self._send("PUT", self._task, PUT_TEMPLATE, body)

    def _send(self, method: str, path: str, template: str, body: Any) -> Result:
        if len(self.sent) >= MAX_TOTAL:
            raise ExperimentPolicyError("the ceiling of 9 requests is reached")
        if method == "GET" and self.gets >= MAX_GET:
            raise ExperimentPolicyError("the ceiling of 7 GETs is reached")
        if method == "PUT" and self.puts >= MAX_PUT:
            raise ExperimentPolicyError("the ceiling of 2 PUTs is reached")
        result = Result(method, template, ())
        result.format_headers = tuple(f"{k}={v}" for k, v in sorted(UI_FORMAT_PARAMS.items()))
        self.sent.append(result)  # an attempt counts, whatever happens next; never retried
        started = time.perf_counter()
        try:
            with self._client.stream(
                method, path, json=body, headers=dict(UI_FORMAT_PARAMS)
            ) as response:
                result.status = response.status_code
                ctype = response.headers.get("content-type", "")
                result.content_type = ctype.split(";")[0].strip().lower() or None
                chunks, total = [], 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > DEFAULT_MAX_BYTES:
                        result.truncated = True
                        break
                    chunks.append(chunk)
                result.body = b"".join(chunks)
                result.size_bucket = size_bucket(total)
        except Exception as exc:  # a category, never a message: it can carry the URL
            result.error = categorise(exc)
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)
        if result.body and not result.truncated and result.content_type == "application/json":
            try:
                result.json = json.loads(result.body)
            except ValueError:
                result.error = "malformed json"
        return result


# ------------------------------------------------------------------------------ evidence
def changed_names(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    """Names of the keys whose value differs. Never a value; an odd key name is masked."""
    names = {
        str(k) if _SCHEMA_NAME.match(str(k)) else "<key>"
        for k in set(before) | set(after)
        if before.get(k) != after.get(k) or (k in before) != (k in after)
    }
    return sorted(names)


def put_evidence(r: Result) -> Facts:
    doc = r.json if isinstance(r.json, Mapping) else None
    keys = sorted(k for k in map(str, doc or {}) if _SCHEMA_NAME.match(k))
    return {
        "http_status": r.status,
        "transport_error": r.error,
        "content_type": r.content_type,
        "response_is_a_json_object": doc is not None,
        "response_keys": keys,
        "response_shape": shape_of(doc) if doc is not None else None,
        "status_dto_compatible": doc is not None and "success" in doc
        and set(keys) <= STATUS_DTO_KEYS,
        "success": doc.get("success") if doc is not None
        and isinstance(doc.get("success"), bool) else None,
    }  # fmt: skip


def put_succeeded(evidence: Facts) -> bool:
    """2xx, and ``success`` true when the response carries that field."""
    status = evidence["http_status"]
    return isinstance(status, int) and 200 <= status < 300 and evidence["success"] is not False


def state_facts(task: Mapping[str, Any], baseline: Mapping[str, Any] | None = None) -> Facts:
    facts: Facts = {
        "status_value": task.get("status") if task.get("status") in ("O", "C") else "other",
        "closed_date_is_null": task.get("closed_date") is None,
        "task_layout_class": _class_of(task.get("task_layout")) if "task_layout" in task
        else "absent",
        "key_count": len(task),
        "required_flags": status_change_flags(task),
    }  # fmt: skip
    if baseline is not None:
        facts["same_key_set_as_the_baseline"] = set(map(str, task)) == set(map(str, baseline))
        facts["invariants_unchanged"] = all(task.get(k) == baseline.get(k) for k in INVARIANT_KEYS)
        facts["field_names_that_differ_from_the_baseline"] = changed_names(baseline, task)
    return facts


class _Run:
    """One experiment. Holds the in-memory objects; emits only sanitised evidence."""

    def __init__(
        self,
        env: ProbeEnv,
        client: ExperimentClient,
        out_dir: Path,
        echo: Callable[[str], None],
        source: str = "tasktree",
    ) -> None:
        if source not in task_candidate.SOURCES:
            raise ExperimentPolicyError("the source must be 'tasktree' or 'documented'")
        self.env, self.client, self.out_dir, self.echo = env, client, out_dir, echo
        self.source = source
        self.evidence: Facts = {"executed": False, "outcome": "not started", "source": source}

    def say(self, line: str) -> None:
        self.echo(safe_text(line, self.env.literals()))

    def read_task(self) -> tuple[Mapping[str, Any], str]:
        if self.source == "documented":  # never the task tree in this mode
            r = self.client.get_task()
            doc = r.json if r.ok and isinstance(r.json, Mapping) else {}
            if not doc:
                return {}, f"the documented task read failed ({r.status or r.error})"
            if str(doc.get("id")) != self.env.task_id:
                return {}, "the object read is not the designated task"
            if str(doc.get("inc_id")) != self.env.incident_id:
                return {}, "the task is not in the designated incident"
            return doc, ""
        r = self.client.get_tree()
        if not r.ok:
            return {}, f"the task tree read failed ({r.status or r.error})"
        return narrow_tasktree(r.json, self.env.task_id, self.env.incident_id)

    def read_phase(self) -> int | None:
        r = self.client.get_incident()
        doc = r.json if r.ok and isinstance(r.json, Mapping) else {}
        phase = doc.get("phase_id")
        return phase if isinstance(phase, int) and not isinstance(phase, bool) else None

    def finish(self, outcome: str, code: int) -> int:
        self.evidence["outcome"] = outcome
        self.evidence["requests"] = [
            {"n": n, "method": r.method, "path_template": r.template,
             "format_headers": list(r.format_headers), "http_status": r.status, "error": r.error}
            for n, r in enumerate(self.client.sent, start=1)
        ]  # fmt: skip
        self.evidence["request_count"] = {
            "total": len(self.client.sent), "get": self.client.gets, "put": self.client.puts,
            "ceiling": {"total": MAX_TOTAL, "get": MAX_GET, "put": MAX_PUT},
        }  # fmt: skip
        document = {
            "_fixture": "controlled-experiment",
            "_ticket": "P2-00b",
            "_note": "one controlled task-status experiment on an owner-designated disposable "
            "task of a disposable lab appliance; statuses, names, types and booleans only",
            "_facts": self.evidence,
        }
        stem = "p2_00b_task_experiment" + ("_documented" if self.source == "documented" else "")
        name = stem + (".json" if self.evidence["executed"] else "_dry_run.json")
        try:
            dump_verified(self.out_dir / name, document, self.env.literals())
        except UnsafeArtefactError as exc:
            self.say(f"evidence NOT WRITTEN: {exc}")
        for key, value in self.evidence.items():
            self.say(f"EXP    {key}: {json.dumps(value, sort_keys=True)}")
        return code

    def run(self, *, execute: bool) -> int:
        env, ev = self.env, self.evidence
        ids = {"task_id": env.task_id, "incident_id": env.incident_id}
        # A. baseline: the fresh source representation, then the incident phase (in memory)
        fresh, why = self.read_task()
        phase0 = self.read_phase()
        flags = status_change_flags(fresh) if fresh else "not reported"
        close = task_candidate.build_candidate(
            fresh or None, target="C", observation=_fixture(self.out_dir, "ui_request_close"),
            source=self.source, **ids,
        )  # fmt: skip
        reasons = list(close.stops)
        if not fresh:
            reasons.insert(0, f"the source read did not yield exactly one designated task: {why}")
        if phase0 is None:
            reasons.append("the incident phase could not be captured")
        if flags != "all true":
            reasons.append("read, write and close are not all reported true for this credential")
        ev["baseline"] = {
            "source": PUT_TEMPLATE if self.source == "documented" else TASKTREE,
            "narrowed_to_exactly_one_designated_task": bool(fresh),
            "task": {**_task_facts(fresh), **state_facts(fresh)} if fresh else None,
            "required_flags": {"flags": list(STATUS_CHANGE_FLAGS), "statement": flags,
                               "values": status_change_flag_values(fresh) if fresh else None},
            "phase_captured_in_memory": phase0 is not None,
        }  # fmt: skip
        ev["close_candidate"] = {"built": close.ok, "changed_keys": list(close.changed_keys),
                                 "stops": list(close.stops)}  # fmt: skip
        ev["proposed_put"] = {"method": "PUT", "path_template": PUT_TEMPLATE, "query": {},
                              "format_headers": UI_FORMAT_PARAMS}  # fmt: skip
        ev["go"], ev["no_go_reasons"] = not reasons, reasons
        if reasons:
            return self.finish("NO-GO: a prerequisite failed; no PUT was sent", EXIT_NOT_EXECUTED)
        if not execute:
            return self.finish("GO, but this was a dry run; no PUT was sent", EXIT_NOT_EXECUTED)

        # C. exactly one close PUT
        ev["executed"] = True
        ev["close_put"] = put_evidence(self.client.put_task(close))
        # D. verify, whatever the PUT answered: the task's real state decides what comes next
        after, why = self.read_task()
        phase1 = self.read_phase()
        ev["after_close"] = {
            "found_exactly_once": bool(after), "not_found_because": why or None,
            **(state_facts(after, fresh) if after else {}),
            "phase_read": phase1 is not None,
            "phase_unchanged": phase1 is not None and phase1 == phase0,
        }  # fmt: skip
        closed = bool(after) and after.get("status") == "C" and after.get("closed_date") is not None
        ev["close_verified"] = closed and put_succeeded(ev["close_put"])
        if not after or after.get("status") == "O":
            return self.finish(
                "the close did not take effect (or could not be verified); no reopen was sent",
                EXIT_STOPPED,
            )
        if phase1 is None or phase1 != phase0:
            return self.finish(
                "HARD STOP: the incident phase changed (or could not be read) after the close; "
                "no API reopen was sent; recovery is left to a human in the UI",
                EXIT_STOPPED,
            )
        side_effect = not (
            ev["after_close"]["same_key_set_as_the_baseline"]
            and ev["after_close"]["invariants_unchanged"]
            # the tree must still show what the UI sent; the documented read is only observed
            and (self.source == "documented" or ev["after_close"]["task_layout_class"] == "null")
        )
        if not ev["close_verified"] or side_effect:
            return self.finish(
                "STOP: the close is not unambiguous, or a prerequisite changed; the task is "
                "closed and no reopen was sent",
                EXIT_STOPPED,
            )

        # E. a NEW fresh read; the reopen candidate; the rollback prerequisites
        closed_task, why = self.read_task()
        reopen = task_candidate.build_candidate(
            closed_task or None, target="O",
            observation=_fixture(self.out_dir, "ui_request_reopen"), source=self.source, **ids,
        )  # fmt: skip
        stops = task_candidate.rollback_stops(
            close_succeeded=True, phase_unchanged=True,
            requests_sent=len(self.client.sent), reopen_candidate=reopen,
        )  # fmt: skip
        if closed_task and status_change_flags(closed_task) != "all true":
            stops.append("read, write and close are no longer all reported true")
        ev["reopen_candidate"] = {"built": reopen.ok, "changed_keys": list(reopen.changed_keys),
                                  "stops": list(reopen.stops)}  # fmt: skip
        ev["rollback"] = {"allowed": not stops, "stops": stops}
        if stops:
            return self.finish(
                "STOP: the pre-approved reopen's prerequisites do not hold; the task is closed",
                EXIT_STOPPED,
            )
        # F. exactly one reopen PUT, then G. the final verification
        ev["reopen_put"] = put_evidence(self.client.put_task(reopen))
        final, why = self.read_task()
        phase2 = self.read_phase()
        ev["final"] = {
            "found_exactly_once": bool(final), "not_found_because": why or None,
            **(state_facts(final, fresh) if final else {}),
            "phase_read": phase2 is not None,
            "phase_unchanged": phase2 is not None and phase2 == phase0,
            "field_names_that_differ_from_the_closed_task": changed_names(closed_task, final)
            if final else None,
        }  # fmt: skip
        reopened = bool(final) and final.get("status") == "O" and put_succeeded(ev["reopen_put"])
        ev["reopen_verified"] = reopened
        if reopened and ev["final"]["phase_unchanged"]:
            return self.finish("COMPLETE: closed, verified, reopened, verified", 0)
        return self.finish("STOP: the reopen is not verified; see the final state", EXIT_STOPPED)


def run_experiment(
    env: ProbeEnv,
    client: ExperimentClient,
    out_dir: Path,
    *,
    execute: bool,
    echo: Callable[[str], None] = print,
    source: str = "tasktree",
) -> int:
    return _Run(env, client, out_dir, echo, source).run(execute=execute)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--execute", action="store_true",
        help="send the close PUT (and the reopen PUT if its prerequisites hold); "
        "without it this is a dry run of two GETs",
    )  # fmt: skip
    parser.add_argument(
        "--source", default="tasktree", choices=task_candidate.SOURCES,
        help="where the fresh task is read from: the task tree (as the UI does) or the "
        "documented GET /tasks/{task_id}, whose task_layout is passed through unchanged",
    )  # fmt: skip
    args = parser.parse_args(argv)
    try:
        env = load_env()
    except ProbeEnvError as exc:
        print(f"cannot run: {exc} (values come from the environment or a git-ignored .env)")
        return 2
    if not env.incident_id or not env.task_id:
        print("set P2_PROBE_INCIDENT_ID and P2_PROBE_TASK_ID (git-ignored .env)")
        return 2
    context, label = verified_context(env)
    print(f"TLS: verified ({label}); chain and host name are checked; no unverified connection")
    print(f"mode: {'EXECUTE' if args.execute else 'dry run (no PUT can be sent)'}")
    print(f"source representation: {args.source}")
    try:
        client = ExperimentClient(env, context)
    except ExperimentPolicyError as exc:
        print(f"cannot run: {exc}")
        return 2
    try:
        return run_experiment(env, client, OUT_DIR, execute=args.execute, source=args.source)
    except ExperimentPolicyError as exc:
        print(f"REFUSED BY THE EXPERIMENT POLICY: {exc}")
        return EXIT_STOPPED
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
