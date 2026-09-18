"""Blast-radius caps (P1-07; 02 §5): per-tier hourly windows persisted through
the audit log, one mutation per call, a circuit breaker, and the kill switch.

A failure to *check* a limit counts as the limit being hit.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qradar_soar_mcp.config import Settings
from qradar_soar_mcp.security.permissions import Code, Decision, deny
from qradar_soar_mcp.security.tiers import MUTATING_FROM, Tier

BREAKER_THRESHOLD = 3  # consecutive Tier ≥ 2 failures ⇒ Tier ≥ 2 disabled for the process
WINDOW_SECONDS = 3600.0
COUNTED_EVENTS = frozenset({"MUTATION_COMMITTED", "MUTATION_FAILED"})


class SlidingWindow:
    def __init__(
        self, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit = max(0, int(limit))
        self.window = float(window_seconds)
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self._events and self._events[0] <= cutoff:
            self._events.popleft()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._events) >= self.limit:
                return False
            self._events.append(now)
            return True

    def seed(self, age_seconds: float) -> None:
        """Record an event that happened ``age_seconds`` ago (audit replay)."""
        with self._lock:
            self._events.append(self._clock() - max(0.0, age_seconds))
            self._events = deque(sorted(self._events))

    def remaining(self) -> int:
        with self._lock:
            self._prune(self._clock())
            return max(0, self.limit - len(self._events))


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


class Limits:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self._wall = wall
        self.tier2 = SlidingWindow(settings.max_tier2_per_hour, WINDOW_SECONDS, clock)
        self.tier3 = SlidingWindow(settings.max_tier3_per_hour, WINDOW_SECONDS, clock)
        self.max_mutations_per_call = settings.max_mutations_per_call
        self.kill_switch_file: Path = settings.kill_switch_file
        self._consecutive_failures = 0
        self.breaker_tripped = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------ persist
    def seed_from_records(self, records: Iterable[Mapping[str, Any]]) -> int:
        """Replay COMMITTED/FAILED mutations from the last hour so a restart
        does not reset the budget (02 §5). Returns how many were counted."""
        now = self._wall()
        counted = 0
        for record in records:
            if record.get("event") not in COUNTED_EVENTS:
                continue
            ts = record.get("ts")
            tier = record.get("tier")
            if not isinstance(ts, str) or not isinstance(tier, int):
                continue
            try:
                when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                continue
            age = now - when.astimezone(UTC).timestamp()
            if age < 0 or age > WINDOW_SECONDS:
                continue
            window = self._window_for(Tier(tier)) if 0 <= tier <= 5 else None
            if window is None:
                continue
            window.seed(age)
            counted += 1
        return counted

    @classmethod
    def from_audit_log(
        cls,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> Limits:
        limits = cls(settings, clock=clock, wall=wall)
        limits.seed_from_records(iter_jsonl(settings.audit_log_path))
        return limits

    # ------------------------------------------------------------- gates
    def _window_for(self, tier: Tier) -> SlidingWindow | None:
        if tier == Tier.MODIFICATION:
            return self.tier2
        if tier >= Tier.CONTROL:
            return self.tier3
        return None

    def kill_switch_active(self) -> bool:
        try:
            return self.kill_switch_file.exists()
        except OSError:
            return True  # cannot tell → assume engaged

    def check_kill_switch(self, tier: Tier) -> Decision | None:
        if tier >= MUTATING_FROM and self.kill_switch_active():
            return deny(
                Code.DENY_KILL_SWITCH,
                f"kill switch engaged: {self.kill_switch_file} exists; remove it to resume",
                tier,
            )
        return None

    def check_mutations_per_call(self, tier: Tier, mutations: int) -> Decision | None:
        if tier >= MUTATING_FROM and mutations > self.max_mutations_per_call:
            return deny(
                Code.DENY_MUTATION_CAP,
                f"this call would mutate {mutations} objects; SOAR_MAX_MUTATIONS_PER_CALL is "
                f"{self.max_mutations_per_call} (bulk mutation is a Tier-5 non-goal)",
                tier,
            )
        return None

    def check_breaker(self, tier: Tier) -> Decision | None:
        if tier >= Tier.MODIFICATION and self.breaker_tripped:
            return deny(
                Code.DENY_BREAKER,
                f"circuit breaker tripped after {BREAKER_THRESHOLD} consecutive Tier>=2 "
                "failures; Tier>=2 stays disabled until the server restarts",
                tier,
            )
        return None

    def acquire(self, tier: Tier) -> Decision | None:
        """Consume one slot of the hourly window for this tier (02 §5)."""
        window = self._window_for(tier)
        if window is None:
            return None
        if not window.try_acquire():
            name = (
                "SOAR_MAX_TIER2_PER_HOUR"
                if tier == Tier.MODIFICATION
                else "SOAR_MAX_TIER3_PER_HOUR"
            )
            return deny(
                Code.DENY_RATE_LIMIT,
                f"hourly cap reached for tier {int(tier)} ({name}={window.limit}); wait and retry",
                tier,
            )
        return None

    def record_result(self, tier: Tier, *, success: bool) -> bool:
        """Feed the breaker. Returns True when this call tripped it."""
        if tier < Tier.MODIFICATION:
            return False
        with self._lock:
            if success:
                self._consecutive_failures = 0
                return False
            self._consecutive_failures += 1
            if self._consecutive_failures >= BREAKER_THRESHOLD and not self.breaker_tripped:
                self.breaker_tripped = True
                return True
            return False

    def describe(self) -> dict[str, Any]:
        return {
            "tier2_per_hour": {"limit": self.tier2.limit, "remaining": self.tier2.remaining()},
            "tier3_per_hour": {"limit": self.tier3.limit, "remaining": self.tier3.remaining()},
            "max_mutations_per_call": self.max_mutations_per_call,
            "breaker_tripped": self.breaker_tripped,
            "kill_switch": {
                "path": str(self.kill_switch_file),
                "active": self.kill_switch_active(),
            },
        }
