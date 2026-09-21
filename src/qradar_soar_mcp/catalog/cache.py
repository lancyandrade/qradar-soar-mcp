"""The in-process TTL cache in front of a catalog backend (P2-01; 04 §1; 08 §25).

* :meth:`CatalogService.get` hands out the cached catalog while it is younger than
  ``SOAR_CATALOG_TTL_SECONDS`` and reloads it once it is not (``0`` reloads every time).
* :meth:`CatalogService.refresh` always reloads: what ``soar_refresh_catalog`` calls.
  Refreshes that queue up behind one another share a load, provided it *started* after
  they asked, so a burst of refreshes costs SOAR one load, and nobody is handed data
  older than their own request.
* A load that fails raises, and leaves the cache exactly as it was. Nothing partial or
  made up is ever stored, and a stale catalog is never handed out in place of the error.
* An entry remembers the source it came from. A catalog is used only for the backend that
  is configured now, and a backend that labels its catalog with another source is refused.

Time comes from an injected monotonic clock, so none of this needs a test that sleeps.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from qradar_soar_mcp.catalog.backends import CatalogBackend, build_backend
from qradar_soar_mcp.catalog.models import Catalog
from qradar_soar_mcp.errors import SoarMalformedResponseError

if TYPE_CHECKING:
    from qradar_soar_mcp.client.base import SoarClient
    from qradar_soar_mcp.config import Settings


@dataclass(frozen=True, slots=True)
class _Entry:
    source: str
    catalog: Catalog
    loaded_at: float  # when the load began: the catalog is at least this old
    sequence: int


class CatalogService:
    def __init__(
        self,
        backend: CatalogBackend,
        *,
        ttl_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.backend = backend
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._entry: _Entry | None = None
        self._lock = asyncio.Lock()
        self._loads_started = 0

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        client: SoarClient,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> CatalogService:
        return cls(
            build_backend(settings.catalog_source, client),
            ttl_seconds=settings.catalog_ttl_seconds,
            clock=clock,
        )

    @property
    def source(self) -> str:
        return self.backend.source

    def cached(self) -> Catalog | None:
        """The catalog ``get`` would hand out now without loading, if there is one."""
        entry = self._entry
        if entry is None or entry.source != self.backend.source:
            return None
        if self._clock() - entry.loaded_at >= self.ttl_seconds:
            return None
        return entry.catalog

    async def get(self) -> Catalog:
        async with self._lock:
            return self.cached() or await self._load()

    async def refresh(self) -> Catalog:
        asked_at = self._loads_started
        async with self._lock:
            entry = self._entry
            if (
                entry is not None
                and entry.sequence > asked_at
                and entry.source == self.backend.source
            ):
                return entry.catalog  # loaded, from start to end, after this call was made
            return await self._load()

    async def _load(self) -> Catalog:
        backend = self.backend
        self._loads_started += 1
        sequence, began = self._loads_started, self._clock()
        catalog = await backend.load()  # raises: the entry below is then left untouched
        if catalog.source != backend.source:
            raise SoarMalformedResponseError(
                f"Malformed response: the {backend.source} catalog backend returned a "
                f"catalog labelled {catalog.source}"
            )
        self._entry = _Entry(backend.source, catalog, began, sequence)
        return catalog
