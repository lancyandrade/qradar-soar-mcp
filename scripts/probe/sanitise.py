"""Shape extraction, sanitisation and verification for P2-00 probe output.

Nothing captured from an appliance may reach the repository as a *value*. The
probe therefore commits **shapes**: key names and JSON types, never strings or
numbers from the appliance. Three layers, all in this file so they can be
reviewed together:

1. ``shape_of``      reduces a JSON document to keys and types. Dictionaries
                     keyed by administrator-chosen names (custom fields, types,
                     data tables) are collapsed to a single ``<name>`` entry, so
                     those names never appear either.
2. ``EnumCollector`` keeps the values of a short allow-list of IBM schema enum
                     keys (for example ``input_type``); every retained value
                     must look like a schema token.
3. ``verify_clean``  REJECTS text that still contains anything environment
                     specific: the literal connection values, IP addresses,
                     e-mail addresses, internal host names, URLs, UUIDs or
                     long tokens. A rejected artefact is not written.

Usage::

    uv run python scripts/probe/sanitise.py --check tests/fixtures/soar/verified/*.json

The check never echoes the offending text (it could be a secret); it reports
the file, the line and the category.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

# Keys whose values are IBM schema enums, safe and useful to keep.
ENUM_STR_KEYS = frozenset(
    {"input_type", "object_type", "format", "status", "activation_type", "plan_status", "method"}
)
ENUM_INT_KEYS = frozenset({"type_id", "export_format_version"})
ENUM_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")  # one token: no spaces, no prose
MAX_ENUM_VALUES = 12  # a schema enum is small; more distinct values means it is not one

# Dictionaries under these keys are keyed by names an administrator chose.
NAME_KEYED_CONTAINERS = frozenset({"properties", "fields", "types", "cells", "field_values"})
NAME_PLACEHOLDER = "<name>"
SCHEMA_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
ID_LIKE_KEY = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})$")
MAP_LIKE_MIN_KEYS = 8

Shape = Any


class EnumCollector:
    """Values seen under the allow-listed enum keys, vetted one by one."""

    def __init__(self) -> None:
        self.values: dict[str, set[str | int]] = {}
        self.rejected: dict[str, int] = {}
        self.not_enums: set[str] = set()

    def offer(self, key: str | None, value: object) -> None:
        if key is None or key in self.not_enums:
            return
        if isinstance(value, bool):
            return
        if key in ENUM_INT_KEYS and isinstance(value, int) and 0 <= value < 10_000:
            self._keep(key, value)
        elif key in ENUM_STR_KEYS and isinstance(value, str):
            if ENUM_TOKEN.match(value) and not _generic_violations(value):
                self._keep(key, value)
            else:
                self.rejected[key] = self.rejected.get(key, 0) + 1

    def _keep(self, key: str, value: str | int) -> None:
        bucket = self.values.setdefault(key, set())
        bucket.add(value)
        if len(bucket) > MAX_ENUM_VALUES:  # free text or names, not an enum: keep nothing
            del self.values[key]
            self.not_enums.add(key)

    def to_json(self) -> dict[str, list[str | int]]:
        return {k: sorted(v, key=str) for k, v in sorted(self.values.items())}


def _map_like(value: Mapping[str, Any]) -> bool:
    """True when a dict is a lookup table rather than a DTO."""
    if not value:
        return False
    keys = list(value)
    if all(ID_LIKE_KEY.match(str(k)) for k in keys):
        return True
    if len(keys) < MAP_LIKE_MIN_KEYS or not all(isinstance(v, Mapping) for v in value.values()):
        return False
    signatures: dict[frozenset[str], int] = {}
    for v in value.values():
        sig = frozenset(map(str, v))
        signatures[sig] = signatures.get(sig, 0) + 1
    return max(signatures.values()) >= 0.8 * len(keys)


def merge_shapes(shapes: Iterable[Shape]) -> Shape:
    """Union of several shapes. Keys absent from some members get a ``?`` suffix."""
    items = list(shapes)
    if not items:
        return "unknown"
    if all(isinstance(s, dict) for s in items):
        all_keys: set[str] = set()
        for s in items:
            all_keys.update(k.rstrip("?") for k in s)
        merged: dict[str, Shape] = {}
        for key in sorted(all_keys):
            present = [s[k] for s in items for k in (key, key + "?") if k in s]
            optional = len(present) < len(items) or any(key + "?" in s for s in items)
            merged[key + "?" if optional else key] = merge_shapes(present)
        return merged
    if all(isinstance(s, list) for s in items):
        inner = [x for s in items for x in s]
        return [merge_shapes(inner)] if inner else []
    if all(isinstance(s, str) for s in items):
        parts: set[str] = set()
        for s in items:
            parts.update(s.split("|"))
        return "|".join(sorted(parts))
    unique: list[Shape] = []
    for s in items:
        if s not in unique:
            unique.append(s)
    return {"<anyOf>": unique}


def shape_of(
    value: object,
    *,
    key: str | None = None,
    enums: EnumCollector | None = None,
    name_keyed: bool = False,
) -> Shape:
    """Reduce ``value`` to keys and JSON types. No appliance value survives."""
    if enums is not None:
        enums.offer(key, value)
    if isinstance(value, bool):
        return "bool"
    if value is None:
        return "null"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        if not value:
            return []
        # Scalars in a list still belong to ``key`` (enum collection); a dict element is a
        # DTO in its own right and must NOT inherit the container's name, or a row under a
        # list called "fields"/"types" would be mistaken for a name-keyed map.
        return [
            merge_shapes(
                shape_of(v, key=None if isinstance(v, Mapping) else key, enums=enums) for v in value
            )
        ]
    if isinstance(value, Mapping):
        if name_keyed or key in NAME_KEYED_CONTAINERS or _map_like(value):
            if not value:
                return {}
            return {
                NAME_PLACEHOLDER: merge_shapes(shape_of(v, enums=enums) for v in value.values())
            }
        out: dict[str, Shape] = {}
        for k in sorted(value, key=str):
            name = str(k)
            safe = name if SCHEMA_KEY.match(name) and not _generic_violations(name) else "<key>"
            shaped = shape_of(value[k], key=name, enums=enums)
            out[safe] = merge_shapes([out[safe], shaped]) if safe in out else shaped
        return out
    return "unknown"


# --------------------------------------------------------------------- verifier
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d]|\.\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
_INTERNAL_HOST = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(internal|corp|lan|local|intranet|home|lab)\b", re.I
)
_URL = re.compile(r"https?://([A-Za-z0-9.-]+)", re.I)
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}(?![A-Za-z0-9+/_=-])")

DOCUMENTATION_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")
SAFE_IPS = frozenset({"127.0.0.1", "0.0.0.0"})  # noqa: S104 - named so they can be allowed
SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.internal")
SAFE_URL_HOSTS = frozenset(
    {"soar.example.internal", "example.com", "www.ibm.com", "ibm.com", "github.com"}
)
SAFE_HOST_SUFFIXES = (".example.internal", ".example.com")


def _generic_violations(text: str) -> list[str]:
    found: list[str] = []
    for m in _IPV4.finditer(text):
        ip = m.group(0)
        octets_ok = all(int(g) <= 255 for g in m.groups())
        if octets_ok and ip not in SAFE_IPS and not ip.startswith(DOCUMENTATION_NETS):
            found.append("ip address")
    for m in _EMAIL.finditer(text):
        if not m.group(0).lower().endswith(SAFE_EMAIL_DOMAINS):
            found.append("e-mail address")
    for m in _INTERNAL_HOST.finditer(text):
        if not m.group(0).lower().endswith(SAFE_HOST_SUFFIXES):
            found.append("internal host name")
    for m in _URL.finditer(text):
        host = m.group(1).lower().rstrip(".")
        if host not in SAFE_URL_HOSTS and not host.endswith(SAFE_HOST_SUFFIXES):
            found.append("url")
    if _UUID.search(text):
        found.append("uuid")
    if any(_secret_shaped(m.group(0)) for m in _LONG_TOKEN.finditer(text)):
        found.append("long token")
    return found


def _secret_shaped(token: str) -> bool:
    """32+ characters that look like key material rather than words.

    Base64/base64url blobs mix upper case, lower case and digits; hashes are long
    hex. A snake_case key name or a documented URL path is neither. The literal
    connection values are matched separately and exactly, whatever their shape.
    """
    if re.search(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])", token):
        return True
    has = (any(c.isupper() for c in token), any(c.islower() for c in token),
           any(c.isdigit() for c in token))  # fmt: skip
    return all(has)


def _literal_violations(text: str, literals: Mapping[str, str]) -> list[str]:
    found: list[str] = []
    lowered = text.lower()
    for label, literal in literals.items():
        if not literal:
            continue
        if literal.isdigit():
            if re.search(rf"(?<![0-9]){re.escape(literal)}(?![0-9])", text):
                found.append(f"literal {label}")
        elif len(literal) >= 3 and literal.lower() in lowered:
            found.append(f"literal {label}")
    return found


def violations(text: str, literals: Mapping[str, str] | None = None) -> list[tuple[int, str]]:
    """``(line number, category)`` for everything that must not be published."""
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for category in _generic_violations(line) + _literal_violations(line, literals or {}):
            out.append((lineno, category))
    return out


def safe_keys(value: object) -> list[str]:
    """Top-level key names of ``value`` that are schema keys, via its collapsed shape."""
    shaped = shape_of(value)
    if not isinstance(shaped, dict):
        return []
    return sorted(k.rstrip("?") for k in shaped if not k.startswith("<"))


def safe_keys_matching(value: object, pattern: str) -> list[str]:
    """Schema key names anywhere in ``value`` matching ``pattern``.

    Walks the collapsed *shape*, never the raw document, so a custom field or a data
    table whose name happens to match can not be reported.
    """
    rx, found = re.compile(pattern, re.I), set()

    def walk(node: Shape) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                name = k.rstrip("?")
                if not name.startswith("<") and rx.search(name):
                    found.add(name)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(shape_of(value))
    return sorted(found)


class UnsafeArtefactError(ValueError):
    """Raised instead of writing an artefact that could not be proven safe."""


def verify_clean(text: str, literals: Mapping[str, str] | None = None, *, what: str = "") -> None:
    bad = violations(text, literals)
    if bad:
        summary = ", ".join(sorted({c for _, c in bad}))
        raise UnsafeArtefactError(
            f"{what or 'artefact'} rejected: {len(bad)} finding(s): {summary}"
        )


def safe_text(text: str, literals: Mapping[str, str] | None = None) -> str:
    """For the terminal: a line that fails verification is withheld, never shown."""
    lines = []
    for line in text.splitlines() or [""]:
        bad = _generic_violations(line) + _literal_violations(line, literals or {})
        lines.append("[withheld: " + ", ".join(sorted(set(bad))) + "]" if bad else line)
    return "\n".join(lines)


def dump_verified(
    path: Path, document: Mapping[str, Any], literals: Mapping[str, str] | None = None
) -> None:
    """Serialise, verify, and only then write. Nothing unsafe reaches the disk."""
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    verify_clean(text, literals, what=path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))  # bytes: LF on every platform, no translation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify that probe artefacts are publishable.")
    parser.add_argument("--check", nargs="+", metavar="FILE", required=True)
    args = parser.parse_args(argv)

    literals: dict[str, str] = {}
    try:
        from probe_env import load_env

        literals = load_env(required=False).literals()
    except Exception as exc:
        print(f"note: connection values unavailable ({type(exc).__name__})")
    if literals:
        print(f"literal checks: {len(literals)} connection value(s) loaded (not shown)")
    else:
        print("literal checks: SKIPPED (no connection values available); generic patterns only")

    failed = 0
    files = [Path(p) for pattern in args.check for p in sorted(Path().glob(pattern))] or [
        Path(p) for p in args.check
    ]
    for path in files:
        if not path.is_file():
            print(f"{path}: missing")
            failed += 1
            continue
        bad = violations(path.read_text(encoding="utf-8"), literals)
        if bad:
            failed += 1
            for lineno, category in bad[:20]:
                print(f"{path}:{lineno}: {category}")
        else:
            print(f"{path}: clean")
    print(f"{len(files)} file(s) checked, {failed} rejected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
