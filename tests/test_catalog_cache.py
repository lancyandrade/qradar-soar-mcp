"""P2-01: the TTL cache in front of a catalog backend (04 §1; 08 §25).

Time is an injected clock: no test here sleeps.
"""

from __future__ import annotations

import asyncio

import pytest

from qradar_soar_mcp.catalog import Catalog, CatalogService
from qradar_soar_mcp.errors import SoarMalformedResponseError, SoarTimeoutError
from tests.test_catalog_models import full_catalog


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class CountingBackend:
    def __init__(self, source: str = "collections", label: str | None = None) -> None:
        self.source = source
        self.label = label or source
        self.loads = 0
        self.fail: Exception | None = None

    async def load(self) -> Catalog:
        self.loads += 1
        if self.fail is not None:
            raise self.fail
        return full_catalog(source=self.label, soar_version=f"load-{self.loads}")


@pytest.fixture
def clock() -> Clock:
    return Clock()


def service(backend: CountingBackend, clock: Clock, ttl: int = 300) -> CatalogService:
    return CatalogService(backend, ttl_seconds=ttl, clock=clock)  # type: ignore[arg-type]


async def test_first_read_loads_and_a_second_read_inside_the_ttl_does_not(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    assert svc.cached() is None
    first = await svc.get()
    clock.now += 299.9
    assert await svc.get() is first
    assert backend.loads == 1 and svc.cached() is first


async def test_a_stale_read_reloads(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    first = await svc.get()
    clock.now += 300  # age == ttl is stale
    assert svc.cached() is None
    second = await svc.get()
    assert backend.loads == 2 and second is not first
    assert second.soar_version == "load-2"
    clock.now += 1
    assert await svc.get() is second  # and the reload restarted the clock


async def test_explicit_refresh_reloads_inside_the_ttl(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    first = await svc.get()
    refreshed = await svc.refresh()
    assert backend.loads == 2 and refreshed is not first
    assert await svc.get() is refreshed  # the refreshed catalog is the cached one now
    assert backend.loads == 2


async def test_a_ttl_of_zero_never_reuses(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock, ttl=0)
    await svc.get()
    await svc.get()
    assert backend.loads == 2 and svc.cached() is None


async def test_a_failed_refresh_keeps_the_good_catalog_and_manufactures_nothing(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    good = await svc.get()
    backend.fail = SoarTimeoutError("Timeout waiting for SOAR on GET /rest/const")
    with pytest.raises(SoarTimeoutError):
        await svc.refresh()
    # Still inside the TTL: the catalog that was good is still the one handed out.
    assert svc.cached() is good and await svc.get() is good
    assert backend.loads == 2


async def test_a_failed_reload_of_a_stale_catalog_raises_instead_of_serving_it(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    await svc.get()
    clock.now += 301
    backend.fail = SoarTimeoutError("Timeout waiting for SOAR on GET /rest/const")
    with pytest.raises(SoarTimeoutError):
        await svc.get()
    with pytest.raises(SoarTimeoutError):
        await svc.get()  # every read tries again; nothing stale and nothing empty comes back
    assert backend.loads == 3 and svc.cached() is None
    backend.fail = None
    assert (await svc.get()).soar_version == "load-4"


async def test_a_first_load_that_fails_leaves_the_cache_empty(clock: Clock):
    backend = CountingBackend()
    backend.fail = SoarTimeoutError("Timeout waiting for SOAR on GET /rest/const")
    svc = service(backend, clock)
    with pytest.raises(SoarTimeoutError):
        await svc.get()
    assert svc.cached() is None


async def test_a_catalog_cached_under_one_source_is_not_reused_for_another(clock: Clock):
    collections = CountingBackend("collections")
    svc = service(collections, clock)
    first = await svc.get()
    assert first.source == "collections"
    export = CountingBackend("export")
    svc.backend = export  # type: ignore[assignment]
    assert svc.source == "export" and svc.cached() is None  # well inside the TTL
    second = await svc.get()
    assert second.source == "export" and export.loads == 1
    svc.backend = collections  # type: ignore[assignment]
    assert svc.cached() is None  # the export entry is not a collections catalog either


async def test_a_backend_that_mislabels_its_catalog_is_refused(clock: Clock):
    backend = CountingBackend("export", label="collections")
    svc = service(backend, clock)
    with pytest.raises(SoarMalformedResponseError, match="labelled collections"):
        await svc.get()
    assert svc.cached() is None


async def test_queued_refreshes_share_a_load_that_started_after_they_asked(clock: Clock):
    """A burst of refreshes costs SOAR two loads, not one each: the one in flight, which
    may predate the requests, and one more that all the waiters share."""
    gate = asyncio.Event()

    class SlowBackend(CountingBackend):
        async def load(self) -> Catalog:
            await gate.wait()
            return await super().load()

    backend = SlowBackend()
    svc = service(backend, clock)
    in_flight = asyncio.create_task(svc.refresh())
    await asyncio.sleep(0)  # let it take the lock and start loading
    waiters = [asyncio.create_task(svc.refresh()) for _ in range(5)]
    await asyncio.sleep(0)
    gate.set()
    first = await in_flight
    results = await asyncio.gather(*waiters)
    assert backend.loads == 2
    assert all(r is results[0] for r in results) and results[0] is not first
    assert results[0].soar_version == "load-2"  # newer than anything the waiters asked for
    # A refresh made after that still reloads: nothing is reused across separate requests.
    assert (await svc.refresh()).soar_version == "load-3"


async def test_a_waiting_refresh_is_not_served_by_a_failed_load(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    await svc.get()
    backend.fail = SoarTimeoutError("Timeout waiting for SOAR on GET /rest/const")
    results = await asyncio.gather(svc.refresh(), svc.refresh(), return_exceptions=True)
    assert all(isinstance(r, SoarTimeoutError) for r in results) and backend.loads == 3


async def test_the_age_of_a_catalog_counts_from_the_start_of_its_load(clock: Clock):
    class TakesAMinute(CountingBackend):
        async def load(self) -> Catalog:
            catalog = await super().load()
            clock.now += 60
            return catalog

    svc = service(TakesAMinute(), clock, ttl=100)
    await svc.get()
    clock.now += 39
    assert svc.cached() is not None  # 99 seconds since the load began
    clock.now += 1
    assert svc.cached() is None


async def test_concurrent_first_reads_load_once(clock: Clock):
    backend = CountingBackend()
    svc = service(backend, clock)
    results = await asyncio.gather(*(svc.get() for _ in range(5)))
    assert backend.loads == 1 and all(r is results[0] for r in results)
