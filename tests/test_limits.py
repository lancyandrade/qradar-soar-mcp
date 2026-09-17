"""P1-07: per-tier caps persisted through the audit log, one-per-call, breaker, kill switch."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
