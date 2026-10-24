"""A minimal GitHub REST/GraphQL client (stdlib only).

The transport is injectable so the tests run offline. The token is held only in
the request header; it never appears in an exception message, a log line or a
return value.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from review_loop import policy

API = "https://api.github.com"


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


Transport = Callable[[str, str, dict[str, str], bytes | None], Response]


class GitHubError(RuntimeError):
    """A GitHub call failed. The message never contains the token."""


def urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> Response:
    if not url.startswith(API + "/"):
        raise GitHubError("refusing a request outside api.github.com")
    req = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - host checked above
            return Response(
                resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
            )
    except urllib.error.HTTPError as err:
        return Response(err.code, {k.lower(): v for k, v in err.headers.items()}, err.read())


_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHub:
    def __init__(self, token: str, repo: str, transport: Transport = urllib_transport) -> None:
        if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", repo):
            raise GitHubError("invalid repository name")
        self._token = token
        self.repo = repo
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "qradar-soar-review-loop",
        }

    def _call(self, method: str, url: str, payload: Any = None) -> Response:
        body = None if payload is None else json.dumps(payload).encode()
        headers = self._headers()
        if body is not None:
            headers["Content-Type"] = "application/json"
        resp = self._transport(method, url, headers, body)
        if resp.status >= 400:
            # Status and path only: response bodies can echo request content.
            path = urllib.parse.urlsplit(url).path
            raise GitHubError(f"GitHub {method} {path} failed with HTTP {resp.status}")
        return resp

    def request(self, method: str, path: str, payload: Any = None) -> Any:
        resp = self._call(method, f"{API}{path}", payload)
        return json.loads(resp.body) if resp.body else None

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def paginate(self, path: str, *, key: str | None = None) -> list[Any]:
        """Follow ``Link: rel=next``. Exceeding ``policy.MAX_PAGES`` fails closed."""
        sep = "&" if "?" in path else "?"
        url: str | None = f"{API}{path}{sep}per_page=100"
        items: list[Any] = []
        for _ in range(policy.MAX_PAGES):
            if url is None:
                return items
            resp = self._call("GET", url)
            data: Any = json.loads(resp.body) if resp.body else []
            page = data if key is None else (data.get(key) if isinstance(data, dict) else None)
            if not isinstance(page, list):
                raise GitHubError(f"unexpected page shape for {path}")
            items.extend(page)
            match = _NEXT.search(resp.headers.get("link", ""))
            url = match.group(1) if match else None
            if url is not None and not url.startswith(API + "/"):
                raise GitHubError("pagination left api.github.com")
        if url is not None:
            raise GitHubError(
                f"more than {policy.MAX_PAGES} pages for {path}; refusing to continue"
            )
        return items

    def graphql(self, query: str, variables: dict[str, Any]) -> Any:
        resp = self._call("POST", f"{API}/graphql", {"query": query, "variables": variables})
        data = json.loads(resp.body)
        if data.get("errors"):
            raise GitHubError("GraphQL query returned errors")
        return data["data"]
