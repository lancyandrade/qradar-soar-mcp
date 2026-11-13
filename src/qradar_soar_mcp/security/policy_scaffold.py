"""A deny-everything action policy built from a catalog, for a human to edit (P2-06; 08 §34).

:func:`build_scaffold` turns the ``rules`` section of a :class:`Catalog` (the manual and
automatic actions of 05 §2) into the text of an ``action_policy.yaml`` in which:

* ``default`` is Tier 5 / ``deny``, and **every** entry is ``tier: 5``, ``decision: deny``
  and ``destructive: true``. Nothing the scaffold writes makes anything reachable: an
  operator has to change an entry to allow it, and the destructive gate stays on until
  they turn it off;
* above each entry a comment gives a *suggested* tier and why. The suggestion comes from
  fixed keywords in the action's name (:data:`KEYWORD_TIERS`), is never applied, and says
  nothing about what the action does: only a human who knows the action can classify it.

The text is built for a hostile catalog. Names are attacker-influenced data (anyone who
can create a rule names it), so a name is written only as a YAML scalar by
``yaml.safe_dump`` and never into a comment: a comment holds only text from this module,
numbers and the keyword from :data:`KEYWORD_TIERS` that matched. The finished text is
parsed back and validated with :class:`ActionPolicy` before it is returned, and is refused
unless it denies everything, has one entry per action and fits the policy size limit.

Functions are not entries. The policy classifies the actions an incident offers, by the
action's name or id (``ActionPolicy.classify``); a function is never invoked by name
through this server, and an entry named after one would only match an action that
happens to share the name. Their count is reported so the omission is visible.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import yaml

from qradar_soar_mcp.catalog.models import Catalog, RuleSpec, SectionState
from qradar_soar_mcp.security.action_policy import MAX_POLICY_BYTES, ActionPolicy, PolicyError
from qradar_soar_mcp.security.tiers import Tier

__all__ = [
    "KEYWORD_TIERS",
    "ScaffoldError",
    "ScaffoldResult",
    "Suggestion",
    "build_scaffold",
    "suggest_tier",
]

SCAFFOLD_REASON = "scaffold entry, not reviewed: classify this action before relying on it"

# Highest tier first; the first keyword found wins, so a name that says both "enrich" and
# "delete" is suggested Tier 5. Matched case-insensitively on word boundaries. Tiers per
# 02 §1; Tier 0 (read) is never suggested, an action is at least documentation.
KEYWORD_TIERS: tuple[tuple[Tier, tuple[str, ...]], ...] = (
    (
        Tier.HIGH_RISK,
        (
            "bulk",
            "delete",
            "destroy",
            "disable all",
            "execute script",
            "purge",
            "run script",
            "uninstall",
            "wipe",
        ),
    ),
    (
        Tier.AUTOMATION,
        ("playbook", "rule", "script", "workflow"),
    ),
    (
        Tier.CONTROL,
        (
            "ban",
            "block",
            "contain",
            "disable",
            "isolate",
            "kill",
            "lock",
            "quarantine",
            "reset password",
            "revoke",
            "shutdown",
        ),
    ),
    (
        Tier.MODIFICATION,
        ("assign", "change", "close", "create", "escalate", "set", "severity", "update"),
    ),
    (
        Tier.DOCUMENTATION,
        ("comment", "enrich", "get", "lookup", "look up", "note", "notify", "query", "search"),
    ),
)

_KEYWORD_PATTERNS: tuple[tuple[Tier, str, re.Pattern[str]], ...] = tuple(
    (tier, keyword, re.compile(rf"\b{re.escape(keyword).replace(r'\ ', r'\s+')}\b", re.I))
    for tier, keywords in KEYWORD_TIERS
    for keyword in keywords
)
# Only for the header: anything else is written as "unknown".
_PLAIN_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class ScaffoldError(ValueError):
    """The catalog cannot yield a scaffold, or the built text failed its own check."""


@dataclass(frozen=True, slots=True)
class Suggestion:
    tier: Tier
    keyword: str | None  # None: no keyword recognised, suggested Tier 5

    @property
    def why(self) -> str:
        if self.keyword is None:
            return "no keyword recognised in the name; unknown means Tier 5 (design 02 s1.1)"
        return f'the name contains "{self.keyword}"'


@dataclass(frozen=True, slots=True)
class ScaffoldResult:
    text: str
    entries: int
    actions: int  # catalog rules enumerated (several may share one name entry)
    functions: int  # catalog functions, which get no entry


def suggest_tier(name: str) -> Suggestion:
    """A guess from the name alone. Advisory; the scaffold never applies it."""
    for tier, keyword, pattern in _KEYWORD_PATTERNS:
        if pattern.search(name):
            return Suggestion(tier, keyword)
    return Suggestion(Tier.HIGH_RISK, None)


@dataclass(frozen=True, slots=True)
class _Entry:
    match: dict[str, Any]
    suggestion: Suggestion
    rules: int
    disabled: int


def _entries(rules: Iterable[RuleSpec]) -> list[_Entry]:
    """One entry per distinct name as ``classify`` compares names (stripped, any case);
    a rule without a usable name gets an ``id`` entry. Sorted, so the text is stable."""
    by_name: dict[str, list[RuleSpec]] = {}
    by_id: list[RuleSpec] = []
    for rule in rules:
        key = rule.name.strip().lower()
        if key:
            by_name.setdefault(key, []).append(rule)
        else:
            by_id.append(rule)
    out: list[_Entry] = []
    for key in sorted(by_name):
        group = sorted(by_name[key], key=lambda r: (r.id, r.name))
        suggestion = max(
            (suggest_tier(r.name) for r in group), key=lambda s: (s.tier, s.keyword or "")
        )
        out.append(
            _Entry(
                {"name": group[0].name.strip()},
                suggestion,
                len(group),
                sum(1 for r in group if not r.enabled),
            )
        )
    for rule in sorted(by_id, key=lambda r: r.id):
        out.append(_Entry({"id": rule.id}, suggest_tier(""), 1, 0 if rule.enabled else 1))
    return out


def _plain(value: str) -> str:
    return value if _PLAIN_TOKEN.fullmatch(value) else "unknown"


# Characters YAML treats as line breaks besides "\n" and "\r". PyYAML can emit them raw
# inside a quoted scalar (and does not read U+0085 back unchanged), so a document holding
# one is dumped with every non-ASCII character escaped instead.
_UNICODE_LINE_BREAKS = frozenset("\x85\u2028\u2029")


def _dump(document: Any) -> str:
    text = yaml.safe_dump(
        document, sort_keys=False, allow_unicode=True, default_flow_style=False, width=4096
    )
    if _UNICODE_LINE_BREAKS.isdisjoint(text):
        return text
    return yaml.safe_dump(
        document, sort_keys=False, allow_unicode=False, default_flow_style=False, width=4096
    )


def _entry_text(entry: _Entry) -> str:
    lines = [f"  # suggested tier {int(entry.suggestion.tier)}: {entry.suggestion.why}"]
    if entry.rules > 1:
        lines.append(f"  # {entry.rules} catalog actions share this name; one entry covers all")
    if entry.disabled:
        lines.append(f"  # {entry.disabled} of them disabled in SOAR at catalog time")
    if "id" in entry.match:
        lines.append("  # matched by id: the action has no usable name")
    body = {
        "match": entry.match,
        "tier": int(Tier.HIGH_RISK),
        "decision": "deny",
        "destructive": True,
        "reason": SCAFFOLD_REASON,
    }
    # Split on "\n" only: str.splitlines() also splits on characters inside a scalar.
    for line in _dump([body]).removesuffix("\n").split("\n"):
        lines.append(f"  {line}")
    return "\n".join(lines) + "\n"


def _header(catalog: Catalog, actions: int, functions: int) -> str:
    return "\n".join(
        [
            "# action_policy.yaml scaffold (qradar-soar-policy scaffold; P2-06).",
            "#",
            "# EVERYTHING HERE IS DENIED. Each entry below is tier 5 / deny / destructive, and",
            "# so is the default. Nothing becomes reachable until a human edits an entry.",
            "# The 'suggested tier' comments are guesses from keywords in the name: they say",
            "# nothing about what an action does. Classify each action from what you know of",
            "# it, add constraints.deny_values before any Tier-3 entry (design 02 s3), and",
            "# delete entries you do not need: an action with no entry is denied by default.",
            "# Rules are matched in order and the first match wins.",
            "#",
            f"# catalog: source {catalog.source}, SOAR {_plain(catalog.soar_version)}, "
            f"fetched {catalog.fetched_at.isoformat()}",
            f"# {actions} actions enumerated; {functions} functions have no entry (a policy",
            "# classifies actions, not functions).",
            "",
        ]
    )


def _check(text: str, expected: list[dict[str, Any]]) -> None:
    """Parse the text back and refuse it unless it is a valid deny-everything policy."""
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise ScaffoldError(
            f"the scaffold would be larger than the {MAX_POLICY_BYTES}-byte policy limit"
        )
    try:
        policy = ActionPolicy.from_mapping(yaml.safe_load(text), source="<scaffold>")
    except PolicyError as exc:  # locations and messages only, never a value
        raise ScaffoldError(f"the built scaffold is not a valid policy: {exc}") from None
    except yaml.YAMLError as exc:  # its text would quote the document
        problem = type(exc).__name__
        raise ScaffoldError(f"the built scaffold is not a valid policy: {problem}") from None
    doc = policy.document
    if doc.default.tier != Tier.HIGH_RISK or doc.default.decision != "deny":
        raise ScaffoldError("the built scaffold does not default to tier 5 / deny")
    found = [rule.match.model_dump(exclude_none=True) for rule in doc.actions]
    if found != expected:  # every name read back exactly as written, in order
        raise ScaffoldError("the built scaffold does not have one entry per action")
    for rule in doc.actions:
        if rule.tier != Tier.HIGH_RISK or rule.decision != "deny" or not rule.destructive:
            raise ScaffoldError("the built scaffold has an entry that is not tier 5 / deny")


def build_scaffold(catalog: Catalog) -> ScaffoldResult:
    """The scaffold text for ``catalog``.

    Raises:
        ScaffoldError: if the catalog's ``rules`` section was not loaded (an empty
            section that could not be read says nothing, and a scaffold built from it
            would look complete), or if the built text fails its own check.
    """
    status = catalog.sections["rules"]
    if status.state is not SectionState.LOADED:
        raise ScaffoldError(
            f"the catalog's rules section is {status.state}, so its actions cannot be "
            "enumerated; no scaffold was built"
        )
    entries = _entries(catalog.rules.values())
    actions, functions = len(catalog.rules), len(catalog.functions)
    parts = [_header(catalog, actions, functions), _dump({"version": 1})]
    parts.append(_dump({"default": {"tier": int(Tier.HIGH_RISK), "decision": "deny"}}))
    if entries:
        parts.append("actions:\n")
        parts.extend(_entry_text(e) for e in entries)
    else:
        parts.append("actions: []  # the catalog holds no actions\n")
    text = "".join(parts)
    _check(text, [e.match for e in entries])
    return ScaffoldResult(text=text, entries=len(entries), actions=actions, functions=functions)
