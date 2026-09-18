"""Shared fixtures. Nothing here reads the real environment or the network.

``respx`` intercepts every ``httpx`` request under ``BASE_URL`` and hands it to
``FakeSoar.handler``; anything outside that base URL is an error
(``assert_all_mocked``), which is how the suite proves it never talks to a
network.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
import respx

from tests.fake_soar import API_KEY_ID, API_KEY_SECRET, BASE_URL, ORG_ID, REQUIRED_PARAMS, FakeSoar

SENTINEL = API_KEY_SECRET


@pytest.fixture(autouse=True)
def _scrub_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The suite must behave identically with or without SOAR_* variables set."""
    for key in list(os.environ):
        if key.startswith("SOAR_"):
            monkeypatch.delenv(key)


def connection_env(**overrides: str) -> dict[str, str]:
    env = {
        "SOAR_BASE_URL": BASE_URL,
        "SOAR_ORG_ID": str(ORG_ID),
        "SOAR_API_KEY_ID": API_KEY_ID,
        "SOAR_API_KEY_SECRET": API_KEY_SECRET,
    }
    env.update(overrides)
    return env


@pytest.fixture
def fake() -> Iterator[FakeSoar]:
    """A FakeSoar wired behind respx for the duration of the test."""
    engine = FakeSoar()
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=engine.handler)
        engine.router = router  # type: ignore[attr-defined]
        yield engine


@pytest.fixture
async def raw_client() -> AsyncIterator[httpx.AsyncClient]:
    """A bare httpx client with the credentials and the two required params.

    Used by the P1-01 contract suite to pin the REST semantics without the
    project's own client in the way.
    """
    async with httpx.AsyncClient(
        base_url=BASE_URL,
        auth=(API_KEY_ID, API_KEY_SECRET),
        params=REQUIRED_PARAMS,
    ) as c:
        yield c
