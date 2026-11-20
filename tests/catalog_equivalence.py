"""P2-01 / D26 (b): compare two catalogs as the backend-equivalence AC needs.

``06 P2-01``: "both backends produce an equivalent ``Catalog`` for the lab". This module
fixes what *equivalent* means so the lab-marked test and its offline tests agree:

- **normalised** = ``Catalog.model_dump(mode="json")`` without the two keys that
  describe the load rather than the appliance: ``source`` (which backend) and
  ``fetched_at`` (when). Nothing else is dropped, sorted away or tolerated;
- **equivalent** = the two normalised documents are equal.

Any further tolerated difference (a section one backend cannot observe, a text the
export words differently) is an owner decision recorded with evidence, added here as a
named, tested exception, never a silent widening.

Differences are reported as JSON paths only (``fields.incident.name.label``), never as
values, so a failing lab test cannot print configuration content.
"""

from __future__ import annotations

from typing import Any

from qradar_soar_mcp.catalog import Catalog

LOAD_METADATA: frozenset[str] = frozenset({"source", "fetched_at"})
MAX_REPORTED = 50


def normalise(catalog: Catalog) -> dict[str, Any]:
    doc = catalog.model_dump(mode="json")
    return {k: v for k, v in doc.items() if k not in LOAD_METADATA}


def differences(a: Any, b: Any, path: str = "") -> list[str]:
    """Paths at which ``a`` and ``b`` differ; ``[]`` when equal. Values are never included."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in sorted(set(a) | set(b), key=str):
            where = f"{path}.{key}" if path else str(key)
            if key not in a:
                out.append(f"{where} (only in the second)")
            elif key not in b:
                out.append(f"{where} (only in the first)")
            else:
                out.extend(differences(a[key], b[key], where))
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path or '<root>'} (length {len(a)} != {len(b)})"]
        out = []
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            out.extend(differences(x, y, f"{path}[{i}]"))
        return out
    if type(a) is not type(b) or a != b:
        return [path or "<root>"]
    return []


def catalog_differences(first: Catalog, second: Catalog) -> list[str]:
    return differences(normalise(first), normalise(second))


def describe(diffs: list[str]) -> str:
    shown = diffs[:MAX_REPORTED]
    more = f" (+{len(diffs) - MAX_REPORTED} more)" if len(diffs) > MAX_REPORTED else ""
    return f"{len(diffs)} difference(s): " + "; ".join(shown) + more
