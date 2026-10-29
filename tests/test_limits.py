"""P1-07: per-tier caps persisted through the audit log, one-per-call, breaker, kill switch."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.security.limits import BREAKER_THRESHOLD, Limits, SlidingWindow, iter_jsonl
from qradar_soar_mcp.security.permissions import Code
from qradar_soar_mcp.security.tiers import Tier


class Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _settings(tmp_path: Path, **env: str) -> Settings:
    base = {
        "SOAR_KILL_SWITCH_FILE": str(tmp_path / "HALT"),
        "SOAR_AUDIT_LOG_PATH": str(tmp_path / "audit.jsonl"),
    }
    base.update(env)
    return Settings.load(base)


# ------------------------------------------------------------- window


def test_sliding_window():
    clock = Clock()
    w = SlidingWindow(3, 60, clock)
    results = []
    for _ in range(4):
        results.append(w.try_acquire())
        clock.t += 10
    assert results == [True, True, True, False]
    clock.t = 1059.9
    assert not w.try_acquire()
    clock.t = 1060.1
    assert w.try_acquire() and not w.try_acquire()
    assert SlidingWindow(0, 60, Clock()).try_acquire() is False
    assert SlidingWindow(-1, 60, Clock()).limit == 0


# ------------------------------------------------------------- caps


def test_sixth_tier3_call_in_an_hour_denies(tmp_path: Path):
    lim = Limits(_settings(tmp_path), clock=Clock())
    for _ in range(5):
        assert lim.acquire(Tier.CONTROL) is None
    d = lim.acquire(Tier.CONTROL)
    assert (
        d is not None and d.code is Code.DENY_RATE_LIMIT and "SOAR_MAX_TIER3_PER_HOUR=5" in d.reason
    )
    assert lim.acquire(Tier.HIGH_RISK) is not None  # shares the tier-3 window
    assert lim.acquire(Tier.DOCUMENTATION) is None  # tier 1 is uncapped
    assert lim.acquire(Tier.READ) is None


def test_tier2_cap_is_separate(tmp_path: Path):
    lim = Limits(_settings(tmp_path, SOAR_MAX_TIER2_PER_HOUR="2"), clock=Clock())
    assert lim.acquire(Tier.MODIFICATION) is None and lim.acquire(Tier.MODIFICATION) is None
    d = lim.acquire(Tier.MODIFICATION)
    assert d is not None and "SOAR_MAX_TIER2_PER_HOUR=2" in d.reason
    assert lim.acquire(Tier.CONTROL) is None


def test_window_recovers_after_an_hour(tmp_path: Path):
    clock = Clock()
    lim = Limits(_settings(tmp_path, SOAR_MAX_TIER3_PER_HOUR="1"), clock=clock)
    assert lim.acquire(Tier.CONTROL) is None
    assert lim.acquire(Tier.CONTROL) is not None
    clock.t += 3601
    assert lim.acquire(Tier.CONTROL) is None


def test_mutations_per_call_cap(tmp_path: Path):
    lim = Limits(_settings(tmp_path), clock=Clock())
    assert lim.check_mutations_per_call(Tier.MODIFICATION, 1) is None
    d = lim.check_mutations_per_call(Tier.MODIFICATION, 2)
    assert d is not None and d.code is Code.DENY_MUTATION_CAP and "Tier-5" in d.reason
    assert lim.check_mutations_per_call(Tier.READ, 50) is None


# ------------------------------------------------------- persistence


def _record(event: str, tier: int, age_seconds: float, now: datetime) -> str:
    ts = (
        (now - timedelta(seconds=age_seconds))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    return json.dumps({"event": event, "tier": tier, "ts": ts})


def test_counters_survive_restart(tmp_path: Path):
    now = datetime.now(UTC)
    log = tmp_path / "audit.jsonl"
    lines = [
        _record("MUTATION_COMMITTED", 3, 60, now),
        _record("MUTATION_FAILED", 3, 120, now),
        _record("MUTATION_COMMITTED", 3, 4000, now),  # older than the window: ignored
        _record("MUTATION_PENDING", 3, 10, now),  # not a counted event
        _record("DECISION_DENIED", 3, 10, now),
        _record("MUTATION_COMMITTED", 2, 30, now),
        '{"event": "MUTATION_COMMITTED", "tier": "three", "ts": "x"}',  # garbage ignored
        "not json",
        "",
    ]
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    lim = Limits.from_audit_log(
        _settings(tmp_path, SOAR_MAX_TIER3_PER_HOUR="3"),
        clock=Clock(),
        wall=lambda: now.timestamp(),
    )
    assert lim.tier3.remaining() == 1 and lim.tier2.remaining() == 24
    assert lim.acquire(Tier.CONTROL) is None
    assert lim.acquire(Tier.CONTROL) is not None  # budget consumed across the restart


def test_seed_returns_count_and_iter_jsonl_missing(tmp_path: Path):
    lim = Limits(_settings(tmp_path), clock=Clock(), wall=lambda: 1_700_000_000.0)
    assert (
        lim.seed_from_records(
            [
                {"event": "MUTATION_COMMITTED", "tier": 2, "ts": "2023-11-14T22:13:00Z"},
                {"event": "MUTATION_COMMITTED", "tier": 9, "ts": "2023-11-14T22:13:00Z"},
                {"event": "MUTATION_COMMITTED", "tier": 2, "ts": "bad"},
            ]
        )
        == 1
    )
    assert list(iter_jsonl(tmp_path / "missing.jsonl")) == []


# --------------------------------------------- replay of PENDING / terminal pairs
# What the registry writes for one Tier-2 call (tools/registry.py steps 9-11): PENDING,
# then COMMITTED or FAILED, or a cap refusal when the hourly window is full.
NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
RID_A, RID_B = "a" * 32, "b" * 32  # the uuid4().hex shape audit.new_request_id writes


def rec(event: str, request_id: Any = RID_A, *, age: float = 30, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "event": event,
        "tool": "soar_update_incident",
        "tier": 2,
        "ts": (NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z"),
    }
    if request_id is not None:
        out["request_id"] = request_id
    if event == "DECISION_DENIED":
        out["decision"] = "DENY_RATE_LIMIT"
    out.update(extra)
    return out


def _replay(tmp_path: Path, records: list[dict[str, Any]]) -> tuple[int, Limits]:
    lim = Limits(_settings(tmp_path, SOAR_MAX_TIER2_PER_HOUR="10"), wall=NOW.timestamp)
    return lim.seed_from_records(records), lim


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        pytest.param([rec("MUTATION_PENDING"), rec("MUTATION_COMMITTED")], 1, id="committed"),
        pytest.param([rec("MUTATION_PENDING"), rec("MUTATION_FAILED")], 1, id="failed"),
        pytest.param([rec("MUTATION_PENDING")], 1, id="terminal-record-lost"),
        pytest.param([rec("MUTATION_PENDING"), rec("DECISION_DENIED")], 0, id="cap-refused"),
        # Older logs: a terminal record without an id still counts; a PENDING without
        # one is skipped, since its terminal record (if any) already counts.
        pytest.param([rec("MUTATION_COMMITTED", None)], 1, id="legacy-terminal"),
        pytest.param(
            [rec("MUTATION_PENDING", None), rec("MUTATION_COMMITTED", None)], 1, id="legacy-pair"
        ),
        # Outside the hour: nothing counts, open or settled.
        pytest.param([rec("MUTATION_PENDING", age=3601)], 0, id="expired-pending"),
        pytest.param(
            [rec("MUTATION_PENDING", age=4000), rec("MUTATION_COMMITTED", age=3990)],
            0,
            id="expired-pair",
        ),
    ],
)
def test_each_request_counts_exactly_once_or_not_at_all(
    tmp_path: Path, records: list[dict[str, Any]], expected: int
):
    counted, lim = _replay(tmp_path, records)
    assert counted == expected and lim.tier2.remaining() == 10 - expected


@pytest.mark.parametrize(
    "bad_id",
    [["x"], {"id": RID_A}, 42, True, "", "A" * 32, RID_A + "0", " " + RID_A[1:]],
    ids=["list", "dict", "int", "bool", "empty", "upper", "long", "space"],
)
def test_a_malformed_request_id_never_raises_and_never_frees_a_slot(tmp_path: Path, bad_id: Any):
    """An id that cannot be a real one: a PENDING carrying it counts (it can never be
    settled), and a terminal record carrying it settles nothing but itself counts."""
    assert _replay(tmp_path, [rec("MUTATION_PENDING", bad_id)])[0] == 1
    assert _replay(tmp_path, [rec("MUTATION_PENDING"), rec("DECISION_DENIED", bad_id)])[0] == 1
    assert _replay(tmp_path, [rec("MUTATION_PENDING"), rec("MUTATION_COMMITTED", bad_id)])[0] == 2
    assert _replay(tmp_path, [rec("DECISION_DENIED", bad_id)])[0] == 0


@pytest.mark.parametrize(
    "terminal",
    [
        pytest.param(rec("DECISION_DENIED", RID_B), id="other-request"),
        pytest.param(rec("DECISION_DENIED", decision="DENY_DISABLED"), id="not-a-cap-refusal"),
        pytest.param(rec("DECISION_DENIED", decision=["DENY_RATE_LIMIT"]), id="garbled-decision"),
        pytest.param(rec("DECISION_DENIED", tool="soar_add_comment"), id="other-tool"),
        pytest.param(rec("DECISION_DENIED", tier=3), id="other-tier"),
    ],
)
def test_a_record_for_something_else_cannot_settle_a_pending_write(
    tmp_path: Path, terminal: dict[str, Any]
):
    counted, _ = _replay(tmp_path, [rec("MUTATION_PENDING"), terminal])
    assert counted == 1


def test_order_and_duplicates_cannot_free_a_slot(tmp_path: Path):
    # A refusal written before the PENDING it names settles nothing.
    assert _replay(tmp_path, [rec("DECISION_DENIED"), rec("MUTATION_PENDING")])[0] == 1
    # Two PENDINGs under one id need two settlements; one COMMITTED leaves one open.
    assert (
        _replay(
            tmp_path, [rec("MUTATION_PENDING"), rec("MUTATION_PENDING"), rec("MUTATION_COMMITTED")]
        )[0]
        == 2
    )
    # A second refusal cannot settle what is already settled, nor a later PENDING twice.
    assert (
        _replay(
            tmp_path,
            [
                rec("MUTATION_PENDING"),
                rec("DECISION_DENIED"),
                rec("DECISION_DENIED"),
                rec("MUTATION_PENDING"),
            ],
        )[0]
        == 1
    )


@pytest.mark.parametrize(
    "junk",
    [
        {"event": ["MUTATION_COMMITTED"], "tier": 2},
        {"event": {"x": 1}},
        {"event": None},
        {"event": "MUTATION_COMMITTED", "tier": True, "ts": NOW.isoformat()},
        {"event": "MUTATION_COMMITTED", "tier": 2, "ts": "0001-01-01T00:00:00-23:59"},
        {"event": "MUTATION_COMMITTED", "tier": 2, "ts": "9999-12-31T23:59:59+14:00"},
        {"event": "MUTATION_PENDING", "request_id": RID_A, "tier": [2], "ts": {}},
    ],
)
def test_garbled_records_are_skipped_without_raising(tmp_path: Path, junk: dict[str, Any]):
    counted, _ = _replay(tmp_path, [rec("MUTATION_PENDING", RID_B), junk])
    assert counted == 1  # the valid open PENDING; junk neither raises nor settles it


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda inner: (
        st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=3)
    ),
    max_leaves=6,
)
_JUNK = st.fixed_dictionaries(
    {},
    optional={
        "event": st.sampled_from(
            ["MUTATION_PENDING", "MUTATION_COMMITTED", "MUTATION_FAILED", "DECISION_DENIED"]
        )
        | _JSON,
        "request_id": _JSON,
        "tool": _JSON,
        "tier": _JSON,
        "ts": _JSON,
        "decision": _JSON,
    },
)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(junk=st.lists(_JUNK, max_size=8), positions=st.lists(st.integers(0, 4), max_size=8))
def test_adding_malformed_records_never_lowers_the_count(
    junk: list[dict[str, Any]], positions: list[int], tmp_path_factory: pytest.TempPathFactory
):
    """Restart is fail closed: whatever malformed records a damaged log adds around a
    valid one, replay never raises and never counts fewer writes than the valid log."""
    valid = [
        rec("MUTATION_PENDING", RID_A),
        rec("MUTATION_COMMITTED", RID_A),
        rec("MUTATION_PENDING", RID_B),  # lost terminal record
        rec("MUTATION_COMMITTED", None),  # legacy
    ]
    base, _ = _replay(tmp_path_factory.mktemp("base"), list(valid))
    mixed = list(valid)
    for record, at in zip(junk, positions + [len(mixed)] * len(junk), strict=False):
        mixed.insert(min(at, len(mixed)), record)
    counted, _ = _replay(tmp_path_factory.mktemp("mixed"), mixed)
    assert base == 3 and counted >= base


def test_restart_over_a_damaged_log_keeps_the_cap(tmp_path: Path):
    """End to end through from_audit_log: garbage lines, unhashable ids and a lost
    terminal record in the file; the server still starts and the cap still holds."""
    lines = [
        json.dumps(rec("MUTATION_PENDING", RID_A)),  # SOAR applied it; COMMITTED lost
        json.dumps(rec("MUTATION_PENDING", ["x"])),  # unhashable id: counts
        json.dumps(rec("DECISION_DENIED", {"id": RID_A})),  # cannot settle RID_A
        json.dumps({"event": ["MUTATION_COMMITTED"]}),
        "not json",
        "[1, 2]",
    ]
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    lim = Limits.from_audit_log(
        _settings(tmp_path, SOAR_MAX_TIER2_PER_HOUR="3"), clock=Clock(), wall=NOW.timestamp
    )
    assert lim.tier2.remaining() == 1
    assert lim.acquire(Tier.MODIFICATION) is None
    denied = lim.acquire(Tier.MODIFICATION)
    assert denied is not None and denied.code is Code.DENY_RATE_LIMIT


# ---------------------------------------------------------- breaker


def test_breaker_trips_after_three_consecutive_tier2_failures(tmp_path: Path):
    lim = Limits(_settings(tmp_path), clock=Clock())
    assert lim.check_breaker(Tier.MODIFICATION) is None
    assert lim.record_result(Tier.MODIFICATION, success=False) is False
    assert lim.record_result(Tier.CONTROL, success=False) is False
    assert lim.record_result(Tier.MODIFICATION, success=False) is True  # third → tripped
    assert lim.breaker_tripped
    d = lim.check_breaker(Tier.MODIFICATION)
    assert d is not None and d.code is Code.DENY_BREAKER and str(BREAKER_THRESHOLD) in d.reason
    assert lim.check_breaker(Tier.CONTROL) is not None
    assert lim.check_breaker(Tier.DOCUMENTATION) is None and lim.check_breaker(Tier.READ) is None
    assert lim.record_result(Tier.MODIFICATION, success=False) is False  # already tripped


def test_breaker_resets_on_success_and_ignores_low_tiers(tmp_path: Path):
    lim = Limits(_settings(tmp_path), clock=Clock())
    lim.record_result(Tier.MODIFICATION, success=False)
    lim.record_result(Tier.MODIFICATION, success=False)
    assert lim.record_result(Tier.MODIFICATION, success=True) is False
    lim.record_result(Tier.MODIFICATION, success=False)
    lim.record_result(Tier.MODIFICATION, success=False)
    assert not lim.breaker_tripped
    for _ in range(5):
        assert lim.record_result(Tier.DOCUMENTATION, success=False) is False
    assert not lim.breaker_tripped


# ------------------------------------------------------ kill switch


def test_kill_switch_denies_next_mutation_and_recovers_without_restart(tmp_path: Path):
    lim = Limits(_settings(tmp_path), clock=Clock())
    assert lim.check_kill_switch(Tier.DOCUMENTATION) is None
    (tmp_path / "HALT").write_text("")
    d = lim.check_kill_switch(Tier.DOCUMENTATION)
    assert d is not None and d.code is Code.DENY_KILL_SWITCH and "HALT" in d.reason
    assert lim.check_kill_switch(Tier.READ) is None  # reads keep working
    (tmp_path / "HALT").unlink()
    assert lim.check_kill_switch(Tier.CONTROL) is None


def test_kill_switch_unreadable_counts_as_engaged(tmp_path: Path, monkeypatch):
    lim = Limits(_settings(tmp_path), clock=Clock())

    def boom(self):
        raise PermissionError("no")

    monkeypatch.setattr(Path, "exists", boom)
    assert lim.kill_switch_active() is True
    assert lim.check_kill_switch(Tier.DOCUMENTATION) is not None


def test_describe(tmp_path: Path):
    d = Limits(_settings(tmp_path), clock=Clock()).describe()
    assert d["tier3_per_hour"] == {"limit": 5, "remaining": 5}
    assert d["max_mutations_per_call"] == 1 and d["breaker_tripped"] is False
    assert d["kill_switch"]["active"] is False
