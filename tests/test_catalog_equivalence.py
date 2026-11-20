"""Offline tests of the P2-01 equivalence rule (``tests/catalog_equivalence.py``).

These prove the comparison, not the AC: the AC needs a real ``export`` catalog from the
lab, which does not exist (the export contract is unverified; ``ExportBackend`` refuses
every load). The lab-marked counterpart is ``tests/lab/test_catalog_equivalence.py``.
Catalogs built here are synthetic copies of the committed offline fixture.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from qradar_soar_mcp.catalog import Catalog
from qradar_soar_mcp.catalog.backends import ExportBackend
from qradar_soar_mcp.errors import SoarCatalogUnavailableError
from tests.catalog_equivalence import (
    LOAD_METADATA,
    catalog_differences,
    describe,
    differences,
    normalise,
)
from tests.catalog_fixture import FIXTURE
from tests.conftest import SENTINEL


def lab() -> Catalog:
    return Catalog.from_json(FIXTURE.read_bytes())


def variant(catalog: Catalog, **changes: object) -> Catalog:
    doc = catalog.model_dump()
    doc.update(changes)
    return Catalog.model_validate(doc)


def test_only_the_load_metadata_is_ignored():
    assert frozenset({"source", "fetched_at"}) == LOAD_METADATA
    base = lab()
    other = variant(base, source="export", fetched_at=datetime(2030, 1, 1, tzinfo=UTC))
    assert catalog_differences(base, other) == []
    assert set(normalise(base)) == set(base.model_dump(mode="json")) - LOAD_METADATA


def test_a_changed_field_is_reported_by_path_without_its_value():
    base = lab()
    name = sorted(base.fields)[0]
    changed = base.fields[name].model_copy(update={"label": SENTINEL})
    other = variant(base, fields={**base.model_dump()["fields"], name: changed.model_dump()})
    diffs = catalog_differences(base, other)
    assert diffs == [f"fields.{name}.label"]
    assert SENTINEL not in describe(diffs)


def test_a_missing_entry_and_a_section_state_are_differences():
    base = lab()
    fields = base.model_dump()["fields"]
    dropped = sorted(fields)[0]
    sections = base.model_dump()["sections"]
    sections["fields"] = {**sections["fields"], "count": len(fields) - 1}
    other = variant(
        base, fields={k: v for k, v in fields.items() if k != dropped}, sections=sections
    )
    diffs = catalog_differences(base, other)
    assert f"fields.{dropped} (only in the first)" in diffs
    assert "sections.fields.count" in diffs


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ({"x": [1, 2]}, {"x": [1]}, ["x (length 2 != 1)"]),
        ({"x": 1}, {"x": 1.0}, ["x"]),  # a type change is a difference
        ({"x": None}, {"x": False}, ["x"]),  # null never equals false
        ([{"a": 1}], [{"a": 2}], ["[0].a"]),
    ],
)
def test_differences_are_strict(a: object, b: object, expected: list[str]):
    assert differences(a, b) == expected


def test_the_report_is_bounded():
    text = describe([f"p{i}" for i in range(80)])
    assert text.startswith("80 difference(s)") and "(+30 more)" in text


async def test_the_export_backend_is_still_unavailable_and_sends_nothing():
    """Guards against a backend that quietly starts answering: until the export contract
    is verified (P2-00c), the export half of the AC cannot be met, and a refusal is never
    a catalog."""
    with pytest.raises(SoarCatalogUnavailableError) as info:
        await ExportBackend().load()
    assert info.value.not_sent is True
