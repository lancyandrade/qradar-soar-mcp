"""The probe's only way to talk to the appliance: read-only by construction.

Policy, enforced structurally in ``ReadOnlyClient.check`` BEFORE any byte leaves
the machine (owner decision for P2-00):

* ``GET`` under ``/rest/`` and ``/docs/`` is allowed, and may not carry a body.
* ``POST`` is allowed for exactly four org-scoped paths, each semantically
  read-only, each with a body that is validated key by key:

  - ``/incidents/query_paged`` and ``/playbooks/query_paged``: the body may hold
    only ``filters``, ``sorts``, ``start`` and ``length`` (paging, sorting and
    search criteria). Conditions may hold only ``field_name``, ``method`` (one of
    the twelve search operators) and ``value``; sorts only ``field_name`` and
    ``type``. ``length`` is capped. Anything else - any key that could create,
    modify, close, assign, invoke, import, enable or disable - is refused.
  - ``/configurations/exports``: only the three boolean section switches.
  - ``/playbooks/execution/query_paged`` (owner decision for P2-00b): one exact body,
    ``{"filters": [], "start": 0, "length": 1}``, and at most once per client. The
    other execution paths (``.../activities``, ``.../cancel``, ``.../status``) stay refused.

* Every ``PUT``, ``PATCH`` and ``DELETE`` is refused, on every path.
* Every other ``POST`` is refused, including any *other* path whose name contains
  ``query_paged``: a name is not evidence of read-only semantics.

Results never carry a URL, a header value or an exception message: failures are
reduced to a fixed category. Paths are recorded as templates.
"""

from __future__ import annotations

import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
from probe_env import ProbeEnv
from tls_check import categorise

DEFAULT_PARAMS = {"handle_format": "names", "text_content_output_format": "always_text"}
DEFAULT_MAX_BYTES = 8_000_000
EXPORT_SUFFIX = "/configurations/exports"
QUERY_SUFFIXES = ("/incidents/query_paged", "/playbooks/query_paged")
# P2-00b: approved by the owner with this exact body, exactly once.
EXECUTION_QUERY_SUFFIX = "/playbooks/execution/query_paged"
EXECUTION_QUERY_BODY = {"filters": [], "start": 0, "length": 1}
QUERY_BODY_KEYS = frozenset({"filters", "sorts", "start", "length"})
FILTER_KEYS = frozenset({"conditions"})
CONDITION_KEYS = frozenset({"field_name", "method", "value"})
SORT_KEYS = frozenset({"field_name", "type"})
SEARCH_METHODS = frozenset(
    {
        "equals", "not_equals", "in", "not_in", "contains", "not_contains",
        "gte", "gt", "lte", "lt", "has_a_value", "does_not_have_a_value",
    }
)  # fmt: skip
EXPORT_BODY_KEYS = frozenset({"layouts", "actions", "phases_and_tasks"})
POST_QUERY_PARAMS = frozenset(
    {"return_level", "handle_format", "text_content_output_format", "include_records_total"}
)
MAX_QUERY_LENGTH = 50
# The two output-format controls may travel as HTTP headers instead of query parameters, as
# the web UI sends them (P2-00b). Names and values are closed sets from the appliance's
# reference; no other request header can be set through this client.
FORMAT_HEADER_VALUES: dict[str, frozenset[str]] = {
    "handle_format": frozenset({"default", "ids", "names", "objects"}),
    "text_content_output_format": frozenset(
        {"default", "objects_convert", "objects_no_convert", "objects_convert_html",
         "objects_convert_text", "always_text"}
    ),
}  # fmt: skip


def validate_format_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if value not in FORMAT_HEADER_VALUES.get(name, frozenset()):
            raise ProbePolicyError("only the two documented format headers, with documented values")
        out[name] = value
    return out


class ProbePolicyError(RuntimeError):
    """The request is outside the P2-00 read-only boundary. Nothing was sent."""


@dataclass(slots=True)
class Result:
    method: str
    template: str
    query_keys: tuple[str, ...]
    status: int | None = None
    content_type: str | None = None
    allow: str | None = None
    size_bucket: str = "n/a"
    elapsed_ms: int = 0
    error: str | None = None
    truncated: bool = False
    has_content_disposition: bool = False
    has_content_length: bool = False
    chunked: bool = False
    format_headers: tuple[str, ...] = ()
    body: bytes = field(default=b"", repr=False)
    json: Any = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def ledger_row(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.template,
            "query_keys": list(self.query_keys),
            "format_headers": list(self.format_headers),
            "status": self.status,
            "content_type": self.content_type,
            "allow": self.allow,
            "size": self.size_bucket,
            "error": self.error,
        }


def size_bucket(n: int) -> str:
    for limit, label in ((0, "0"), (1_000, "<1KB"), (100_000, "<100KB"), (1_000_000, "<1MB")):
        if n <= limit:
            return label
    return "<10MB" if n <= 10_000_000 else ">=10MB"


def _scalar(value: object) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _validate_query_body(body: object) -> None:
    """Only paging, sorting and search criteria. Every key is on an allow-list."""
    if not isinstance(body, Mapping) or set(body) - QUERY_BODY_KEYS:
        raise ProbePolicyError("a query body may hold only filters, sorts, start and length")
    start, length = body.get("start", 0), body.get("length")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise ProbePolicyError("start must be a non-negative integer")
    if isinstance(length, bool) or not isinstance(length, int):
        raise ProbePolicyError("length is required and must be an integer")
    if not 1 <= length <= MAX_QUERY_LENGTH:
        raise ProbePolicyError(f"length must be between 1 and {MAX_QUERY_LENGTH}")
    filters = body.get("filters", [])
    if not isinstance(filters, list):
        raise ProbePolicyError("filters must be a list")
    for group in filters:
        if not isinstance(group, Mapping) or set(group) - FILTER_KEYS:
            raise ProbePolicyError("a filter may hold only conditions")
        conditions = group.get("conditions", [])
        if not isinstance(conditions, list):
            raise ProbePolicyError("conditions must be a list")
        for cond in conditions:
            if not isinstance(cond, Mapping) or set(cond) - CONDITION_KEYS:
                raise ProbePolicyError("a condition may hold only field_name, method and value")
            if (
                not isinstance(cond.get("field_name"), str)
                or cond.get("method") not in SEARCH_METHODS
            ):
                raise ProbePolicyError("a condition needs a field_name and a known search method")
            value = cond.get("value")
            if not (_scalar(value) or (isinstance(value, list) and all(map(_scalar, value)))):
                raise ProbePolicyError("a condition value must be a scalar or a list of scalars")
    sorts = body.get("sorts", [])
    if not isinstance(sorts, list):
        raise ProbePolicyError("sorts must be a list")
    for sort in sorts:
        if not isinstance(sort, Mapping) or set(sort) - SORT_KEYS:
            raise ProbePolicyError("a sort may hold only field_name and type")
        if not isinstance(sort.get("field_name"), str) or sort.get("type") not in ("asc", "desc"):
            raise ProbePolicyError("a sort needs a field_name and type asc|desc")


def _validate_export_body(body: object) -> None:
    if not isinstance(body, Mapping) or set(body) - EXPORT_BODY_KEYS:
        raise ProbePolicyError("an export body may hold only the three section switches")
    if not all(isinstance(v, bool) for v in body.values()):
        raise ProbePolicyError("export section switches must be booleans")


class ReadOnlyClient:
    def __init__(
        self,
        env: ProbeEnv,
        ssl_context: ssl.SSLContext | bool,
        *,
        sni_hostname: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._org_prefix = f"/rest/orgs/{env.org_id}"
        self._export_path = self._org_prefix + EXPORT_SUFFIX
        self._query_paths = frozenset(self._org_prefix + suffix for suffix in QUERY_SUFFIXES)
        self._execution_query_path = self._org_prefix + EXECUTION_QUERY_SUFFIX
        self._execution_query_spent = False
        self._extensions = {"sni_hostname": sni_hostname} if sni_hostname else {}
        self.requests_sent = 0
        self.refused: list[str] = []
        self._client = httpx.Client(
            base_url=env.base_url,
            auth=(env.key_id, env.key_secret),
            verify=ssl_context,
            timeout=env.timeout,
            follow_redirects=False,
            transport=transport,
            headers={"Accept": "application/json, */*;q=0.5"},
        )

    def close(self) -> None:
        self._client.close()

    def org_path(self, suffix: str) -> str:
        return self._org_prefix + "/" + suffix.lstrip("/")

    # ------------------------------------------------------------------ policy
    def check(
        self,
        method: str,
        path: str,
        template: str,
        json_body: Any = None,
        query: Mapping[str, str] | None = None,
    ) -> None:
        """Raise ``ProbePolicyError`` unless the request is provably read-only.

        Runs before the HTTP client is touched. Refusal reasons name the rule, never a
        value from the request.
        """
        verb = method.upper()
        try:
            self._check(verb, path, json_body, query or {})
        except ProbePolicyError as exc:
            self.refused.append(f"{verb} {template}")
            raise ProbePolicyError(f"{verb} {template}: {exc}") from None

    def _check(self, verb: str, path: str, body: Any, query: Mapping[str, str]) -> None:
        if not path.startswith("/") or ".." in path or "?" in path or "#" in path or "//" in path:
            raise ProbePolicyError("malformed path")
        if verb == "GET":
            if body is not None:
                raise ProbePolicyError("a GET may not carry a body")
            if not path.startswith(("/rest/", "/docs/")):
                raise ProbePolicyError("GET is limited to /rest/ and /docs/")
            return
        if verb != "POST":
            raise ProbePolicyError("only GET and the approved read-only POSTs are permitted")
        target = path.rstrip("/")
        if set(query) - POST_QUERY_PARAMS:
            raise ProbePolicyError("unexpected query parameter on a POST")
        if target == self._export_path:
            _validate_export_body(body)
        elif target in self._query_paths:
            _validate_query_body(body)
        elif target == self._execution_query_path:
            _validate_query_body(body)  # rejects a bool posing as a number before the comparison
            if body != EXECUTION_QUERY_BODY:
                raise ProbePolicyError("the execution query is approved with one exact body")
            if self._execution_query_spent:
                raise ProbePolicyError("the execution query is approved exactly once")
        else:
            raise ProbePolicyError("this POST path is not on the read-only allow-list")

    # ----------------------------------------------------------------- request
    def request(
        self,
        method: str,
        path: str,
        template: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Any = None,
        headers_only: bool = False,
        max_bytes: int = DEFAULT_MAX_BYTES,
        default_params: bool = True,
        format_headers: Mapping[str, str] | None = None,
    ) -> Result:
        query = {**(DEFAULT_PARAMS if default_params else {}), **(params or {})}
        try:
            controls = validate_format_headers(format_headers)
        except ProbePolicyError as exc:
            self.refused.append(f"{method.upper()} {template}")
            raise ProbePolicyError(f"{method.upper()} {template}: {exc}") from None
        self.check(method, path, template, json_body, query)
        if path.rstrip("/") == self._execution_query_path:
            self._execution_query_spent = True  # spent on the attempt, whatever the outcome
        result = Result(method.upper(), template, tuple(sorted(query)))
        result.format_headers = tuple(f"{k}={v}" for k, v in sorted(controls.items()))
        started = time.perf_counter()
        try:
            self.requests_sent += 1
            with self._client.stream(
                method.upper(),
                path,
                params=query,
                json=json_body,
                headers=controls or None,
                extensions=self._extensions,
            ) as response:
                result.status = response.status_code
                ctype = response.headers.get("content-type", "")
                result.content_type = ctype.split(";")[0].strip().lower() or None
                result.allow = response.headers.get("allow")
                result.has_content_disposition = "content-disposition" in response.headers
                declared = response.headers.get("content-length")
                result.has_content_length = declared is not None
                encoding = response.headers.get("transfer-encoding", "")
                result.chunked = "chunked" in encoding.lower()
                if headers_only:
                    result.size_bucket = size_bucket(int(declared)) if declared else "unknown"
                else:
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            result.truncated = True
                            break
                        chunks.append(chunk)
                    result.body = b"".join(chunks)
                    result.size_bucket = size_bucket(total)
        except Exception as exc:
            result.error = categorise(exc)
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)
        if result.body and not result.truncated and result.content_type == "application/json":
            try:
                import json

                result.json = json.loads(result.body)
            except ValueError:
                result.error = "malformed json"
        return result
