"""Builds ``tests/fixtures/catalog/lab-v51.json``, the offline catalog of 04 §1 (P2-01).

Provenance: the real ``CollectionsBackend`` run against the offline ``FakeSoar``, whose
discovery payloads are the shapes P2-00 recorded from QRadar SOAR 51.0.9.0.20848 filled
with synthetic values (``tests/discovery_data.py``). So the file has the structure the lab
returned and no value from it: no host, id, name, text or credential. Its timestamp is
fixed, and the org id is the repository's placeholder.

The incident field definitions come from the fake's Phase-1 synthetic fixture
(``tests/fixtures/soar/incident_fields.json``), whose ``required`` tokens are baseline
assumptions on named fields. They are stripped here: the only committed evidence for
token values (the P2-03 addendum) kept token sets per object type and no field identity,
so the catalog attributes no ``required`` token to any field (08 §28.4). The Phase-1
fixture itself is unchanged for the tests and fake behaviour that rely on it.

``test_catalog_fixture.py`` rebuilds it and compares, so the committed file cannot drift
from the models, the backend or the verified shapes. To regenerate after such a change::

    uv run python -m tests.catalog_fixture
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import respx

from qradar_soar_mcp.catalog import Catalog, CollectionsBackend
from qradar_soar_mcp.client.base import SoarClient
from qradar_soar_mcp.config import Settings
from tests.conftest import connection_env
from tests.fake_soar import BASE_URL, FakeSoar

FIXTURE = Path(__file__).parent / "fixtures" / "catalog" / "lab-v51.json"
FETCHED_AT = datetime(2026, 9, 18, tzinfo=UTC)  # the day P2-00 recorded the shapes


def without_required_tokens(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The field definitions with no ``required`` key: absent, as the appliance sends it
    where a field has no token, and never a token this fixture cannot attribute."""
    return [{k: v for k, v in row.items() if k != "required"} for row in rows]


async def build_lab_catalog(fake: FakeSoar | None = None) -> Catalog:
    engine = fake or FakeSoar()
    engine.fields = without_required_tokens(engine.fields)
    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        router.route().mock(side_effect=engine.handler)
        async with SoarClient(Settings.load(connection_env())) as client:
            return await CollectionsBackend(client, now=lambda: FETCHED_AT).load()


if __name__ == "__main__":
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(asyncio.run(build_lab_catalog()).to_json(), encoding="utf-8", newline="\n")
