"""P2-01: the committed offline catalog, ``tests/fixtures/catalog/lab-v51.json`` (04 §1).

It loads with no network at all, matches the current schema exactly, cannot drift from
the backend or the verified shapes (it is rebuilt here and compared), and contains
nothing that looks like a secret, a host, a person or a real identifier.
"""

from __future__ import annotations

import importlib.util
import json
import re
import socket
import sys
from pathlib import Path
from types import ModuleType

import pytest

from qradar_soar_mcp.catalog import Catalog, SectionState
from tests.catalog_fixture import FETCHED_AT, FIXTURE, build_lab_catalog
from tests.conftest import SENTINEL

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the offline catalog fixture must load without any network access")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def test_the_fixture_loads_with_zero_network(no_network: None):
    catalog = Catalog.from_json(FIXTURE.read_bytes())
    assert catalog.source == "collections"
    assert catalog.soar_version == "51.0.9.0.20848" and catalog.org_id == "201"
    assert catalog.fetched_at == FETCHED_AT and catalog.fetched_at.utcoffset() is not None
    for name in (
        "functions",
        "scripts",
        "message_destinations",
        "incident_types",
        "phases",
        "fields",
        "datatables",
        "playbooks",
        "rules",
        "groups",
    ):
        assert getattr(catalog, name), f"{name} is empty in the offline fixture"
    fn = next(iter(catalog.functions.values()))
    assert fn.inputs and fn.unresolved_inputs == 0


def test_the_fixture_matches_the_current_schema_byte_for_byte(no_network: None):
    text = FIXTURE.read_text(encoding="utf-8")
    assert Catalog.from_json(text).to_json() == text


def test_the_fixture_says_what_is_unknown(no_network: None):
    catalog = Catalog.from_json(FIXTURE.read_bytes())
    assert catalog.sections["api_key_permissions"].state is SectionState.NOT_OBSERVABLE
    assert catalog.sections["installed_apps"].state is SectionState.NOT_OBSERVABLE
    assert catalog.api_key_permissions == frozenset() and catalog.installed_apps == {}
    # SOAR returned no workflow to the research key: loaded, count 0, no detail invented.
    assert catalog.sections["workflows"].state is SectionState.LOADED
    assert catalog.workflows == {}


async def test_the_fixture_is_what_the_backend_builds_from_the_verified_shapes():
    """Provenance, enforced: regenerate with ``uv run python -m tests.catalog_fixture``."""
    rebuilt = await build_lab_catalog()
    assert rebuilt.to_json() == FIXTURE.read_text(encoding="utf-8")
    assert rebuilt == Catalog.from_json(FIXTURE.read_bytes())


def test_the_fixture_is_lf_terminated_utf8():
    raw = FIXTURE.read_bytes()
    assert b"\r" not in raw and raw.endswith(b"}\n")
    raw.decode("utf-8")


def test_no_secret_like_value_is_present():
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    # The one sentence that names a credential is this project's own explanation of why
    # a permission set cannot be observed. It is checked literally and then set aside.
    from qradar_soar_mcp.catalog.backends import NO_PERMISSION_SOURCE

    assert document["sections"]["api_key_permissions"]["reason"] == NO_PERMISSION_SOURCE
    document["sections"]["api_key_permissions"]["reason"] = None
    # ... as is the name of the (empty) section itself, which is schema, not a value.
    assert document["api_key_permissions"] == []
    text = json.dumps(document).replace('"api_key_permissions"', '""')
    assert SENTINEL not in text
    for pattern in (
        r"(?i)passw",
        r"(?i)secret",
        r"(?i)authorization",
        r"(?i)basic\s",
        r"(?i)bearer",
        r"(?i)token",
        r"(?i)api[ _-]?key",
        r"-----BEGIN",
        r"https?://",
        r"@",
    ):
        assert re.search(pattern, text) is None, pattern


def test_the_fixture_passes_the_probe_sanitiser_and_the_repository_scanner():
    """The same two checks that guard the P2-00 fixtures and the whole tree: no address,
    host, e-mail, url, real-looking identifier or long token."""
    sanitise = _load("probe_sanitise", ROOT / "scripts" / "probe" / "sanitise.py")
    assert sanitise.violations(FIXTURE.read_text(encoding="utf-8")) == []
    scanner = _load("check_no_secrets", ROOT / "scripts" / "check_no_secrets.py")
    assert scanner.scan(ROOT, FIXTURE.relative_to(ROOT).as_posix()) == []


def test_every_value_is_synthetic_or_a_recorded_enumeration():
    """Nothing realistic-looking: a string is a made-up placeholder, a recorded enum, the
    appliance version, or text that came from this repository's own fixtures and code."""
    catalog = Catalog.from_json(FIXTURE.read_bytes())
    for section in ("functions", "scripts", "playbooks", "rules", "groups", "phases"):
        for name, spec in getattr(catalog, section).items():
            assert re.fullmatch(r"[a-z_]+[-_]\d+", name), (section, name)
            assert spec.uuid.startswith("uuid-"), (section, name)
