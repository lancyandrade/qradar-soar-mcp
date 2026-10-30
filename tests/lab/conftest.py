"""LAB-01: the gate in front of every live lab test (07 §2, §7).

Every test under ``tests/lab/`` must carry exactly one of the ``lab``,
``lab_write`` or ``lab_destructive`` markers (collection fails otherwise), and an
autouse fixture resolves its target through :mod:`tests.lab.guard` before the test
body runs: not enabled ⇒ skip, enabled but unsafe ⇒ fail. With no ``SOAR_TEST_*``
variable set, which is how CI runs, every lab test is skipped and nothing is sent.

The ``SOAR_TEST_*`` variables are read once, here, at collection: the root
``conftest.py`` scrubs every ``SOAR_*`` variable before each test so the offline
suite behaves the same on any machine.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest

from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.security.audit import verify
from qradar_soar_mcp.tls import build_trust
from qradar_soar_mcp.tools import Runtime
from tests.lab.guard import (
    LabNotEnabledError,
    LabRefusedError,
    LabTarget,
    LabTier,
    ReadOnlyTransport,
    capture_env,
    resolve,
)

LAB_ENV, RUNTIME_ENV = capture_env(os.environ)
LAB_DIR = Path(__file__).resolve().parent
LAB_MARKERS = {t.value for t in LabTier}


def _lab_markers(item: pytest.Item) -> set[str]:
    return {m.name for m in item.iter_markers()} & LAB_MARKERS


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if LAB_DIR not in Path(str(item.path)).resolve().parents:
            continue
        marks = _lab_markers(item)
        if len(marks) != 1:
            raise pytest.UsageError(
                f"{item.nodeid}: a test under tests/lab/ needs exactly one of "
                f"{sorted(LAB_MARKERS)}, found {sorted(marks)}"
            )


@pytest.fixture(autouse=True)
def lab_target(request: pytest.FixtureRequest) -> LabTarget:
    """The resolved target for this test's tier. Skips or fails; never falls back."""
    (mark,) = _lab_markers(request.node)
    try:
        return resolve(LAB_ENV, LabTier(mark), runtime_env=RUNTIME_ENV)
    except LabNotEnabledError as exc:
        pytest.skip(str(exc))
    except LabRefusedError as exc:
        pytest.fail(f"lab guard refused: {exc}", pytrace=False)


@pytest.fixture(scope="session")
def t4_state_dir(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """One state directory, and so **one** audit log, for every T4 test of the run.

    The audit chain continues across runtimes (each test reopens the same log), so the
    chain verified at the end covers the whole run (07 §7.5). At session end the log is
    verified once more and copied to ``SOAR_TEST_EVIDENCE_DIR``.
    """
    state = tmp_path_factory.mktemp("t4-state")
    yield state
    audit = state / "audit.jsonl"
    keep_evidence(audit, request_nodeid="t4-run")


@pytest.fixture
async def t4_runtime(
    lab_target: LabTarget, t4_state_dir: Path
) -> AsyncIterator[tuple[Runtime, ReadOnlyTransport]]:
    """A server runtime for T4: default (deny-all) configuration, TLS verified, every
    request through :class:`ReadOnlyTransport`, audit required in the run's shared
    state directory.

    Teardown fails the test if the guard blocked anything or the run's audit chain, as
    far as it goes, does not verify (07 §7.5: ``qradar-soar-audit verify`` clean over
    the run).
    """
    assert lab_target.tier is LabTier.READ_ONLY
    env = lab_target.runtime_env(t4_state_dir)
    settings = Settings.load(env)
    inner = httpx.AsyncHTTPTransport(verify=build_trust(settings).httpx_verify)
    guard = ReadOnlyTransport(
        inner, host=lab_target.host, org_id=lab_target.org_id, port=lab_target.port
    )
    rt = Runtime.build(env, transport="stdio", http_transport=guard)
    if not rt.usable:
        await guard.aclose()
        pytest.fail("the lab runtime refused to start (see the log)", pytrace=False)
    try:
        yield rt, guard
    finally:
        await rt.aclose()
    assert guard.blocked == [], f"read-only guard blocked {guard.blocked}"
    audit = t4_state_dir / "audit.jsonl"
    if audit.exists():
        result = verify(audit)
        assert result.ok, f"audit chain broken at seq {result.first_broken_seq}: {result.reason}"


def keep_evidence(audit: Path, *, request_nodeid: str) -> Path | None:
    """Copy a lab run's audit log to ``SOAR_TEST_EVIDENCE_DIR`` with its SHA-256.

    pytest rotates its temporary directories, so without this the evidence the gate
    needs (07 §7.5, lab plan §6) is lost. Never overwrites: an existing name gets a
    numeric suffix. Nothing is copied when the variable is unset.
    """
    target_dir = (LAB_ENV.get("SOAR_TEST_EVIDENCE_DIR") or "").strip()
    if not target_dir or not audit.exists():
        return None
    out = Path(target_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", request_nodeid.split(" ")[0])[-120:]
    n = 0
    while (dest := out / f"{stem}{'-' + str(n) if n else ''}.audit.jsonl").exists():
        n += 1
    data = audit.read_bytes()
    dest.write_bytes(data)
    dest.with_suffix(".sha256").write_text(
        f"{hashlib.sha256(data).hexdigest()}  {dest.name}\n", encoding="utf-8"
    )
    return dest
