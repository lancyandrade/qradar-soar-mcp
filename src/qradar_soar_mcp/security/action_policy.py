"""The operator's classification of manual actions (P1-06; 02 §3).

Ordered rules, first match wins, unmatched ⇒ the ``default`` (Tier 5 / deny).
Validated at startup against the pydantic schema (``extra="forbid"``); a
malformed policy is a startup failure and never falls back to permissive.

``deny_values`` is the control that matters most: CIDR containment for IPs,
case-insensitive exact match for everything else.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from qradar_soar_mcp.security.permissions import PolicyResult
from qradar_soar_mcp.security.tiers import Tier

__all__ = ["ActionPolicy", "PolicyDocument", "PolicyError", "PolicyResult"]

MAX_POLICY_BYTES = 1_000_000
MAX_REGEX_LENGTH = 200
# A quantified group that itself contains a quantifier or an alternation: the
# classic ReDoS shapes ((a+)+, (a|aa)+).
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*?}|](?:[^()\\]|\\.)*\)\s*[+*{]")

DecisionName = Literal["allow", "deny", "require_approval"]


class PolicyError(ValueError):
    """The policy file is malformed or missing. Fail closed: do not start."""


# ------------------------------------------------------------------ schema
class MatchSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    name_regex: str | None = None
    id: int | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> MatchSpec:
        given = [k for k in ("name", "name_regex", "id") if getattr(self, k) is not None]
        if len(given) != 1:
            raise ValueError("match must have exactly one of name, name_regex, id")
        if self.name is not None and not self.name.strip():
            raise ValueError("match.name must not be empty")
        if self.name_regex is not None:
            pattern = self.name_regex
            if len(pattern) > MAX_REGEX_LENGTH:
                raise ValueError(f"match.name_regex longer than {MAX_REGEX_LENGTH} characters")
            if _NESTED_QUANTIFIER.search(pattern):
                raise ValueError(
                    "match.name_regex has a nested quantifier or quantified alternation "
                    "(catastrophic backtracking); rejected"
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"match.name_regex does not compile: {exc.msg}") from None
        return self

    @property
    def label(self) -> str:
        if self.name is not None:
            return self.name
        if self.name_regex is not None:
            return f"regex:{self.name_regex}"
        return f"id:{self.id}"


class Constraints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_types: list[str] = Field(default_factory=list)
    deny_values: list[str] = Field(default_factory=list)
    allow_values: list[str] = Field(default_factory=list)


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    match: MatchSpec
    tier: int = Field(ge=0, le=5)
    decision: DecisionName
    destructive: bool = False
    reason: str | None = None
    constraints: Constraints = Field(default_factory=Constraints)


class DefaultSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tier: int = Field(default=5, ge=0, le=5)
    decision: DecisionName = "deny"


class PolicyDocument(BaseModel):
    """The JSON Schema of the policy file is emitted from this model."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    default: DefaultSpec = Field(default_factory=DefaultSpec)
    actions: list[RuleSpec] = Field(default_factory=list)


def _value_matches(pattern: str, target: str) -> bool:
    """CIDR containment when both sides parse as IP data; exact (case-insensitive) otherwise."""
    try:
        network = ipaddress.ip_network(pattern.strip(), strict=False)
    except ValueError:
        return pattern.strip().lower() == target.strip().lower()
    try:
        return ipaddress.ip_address(target.strip()) in network
    except ValueError:
        return False


# ------------------------------------------------------------------ policy
class ActionPolicy:
    def __init__(self, document: PolicyDocument, *, source: str) -> None:
        self.document = document
        self.source = source
        self._compiled: list[tuple[RuleSpec, re.Pattern[str] | None]] = [
            (rule, re.compile(rule.match.name_regex) if rule.match.name_regex else None)
            for rule in document.actions
        ]

    # --------------------------------------------------------------- load
    @classmethod
    def load(cls, path: Path | None) -> ActionPolicy:
        if path is None:
            raise PolicyError("SOAR_ACTION_POLICY_FILE is not set")
        if not path.is_file():
            raise PolicyError(f"{path}: policy file does not exist")
        if path.stat().st_size > MAX_POLICY_BYTES:
            raise PolicyError(f"{path}: policy file is larger than {MAX_POLICY_BYTES} bytes")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path}: not valid YAML ({type(exc).__name__})") from None
        return cls.from_mapping(raw, source=str(path))

    @classmethod
    def from_mapping(cls, raw: Any, *, source: str = "<inline>") -> ActionPolicy:
        if raw is None:
            raise PolicyError(f"{source}: policy file is empty")
        if not isinstance(raw, dict):
            raise PolicyError(f"{source}: top level must be a mapping")
        try:
            document = PolicyDocument.model_validate(raw)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in err['loc']) or 'document'}: {err['msg']}"
                for err in exc.errors(include_input=False, include_url=False)
            )
            raise PolicyError(f"{source}: {problems}") from None
        return cls(document, source=source)

    @staticmethod
    def json_schema() -> dict[str, Any]:
        return PolicyDocument.model_json_schema()

    # ----------------------------------------------------------- classify
    def classify(
        self,
        *,
        action_name: str,
        action_id: int | None = None,
        target_values: Iterable[str] = (),
        artifact_type: str | None = None,
    ) -> PolicyResult:
        """First matching rule wins; unmatched ⇒ ``default`` (Tier 5 / deny)."""
        name = action_name.strip()
        targets = [str(t) for t in target_values]
        for rule, regex in self._compiled:
            m = rule.match
            if m.name is not None and m.name.strip().lower() != name.lower():
                continue
            if regex is not None and regex.fullmatch(name) is None:
                continue
            if m.id is not None and m.id != action_id:
                continue
            return PolicyResult(
                tier=Tier(rule.tier),
                decision=rule.decision,
                destructive=rule.destructive,
                rule=m.label,
                reason=rule.reason or f"matched rule {m.label!r}",
                constraint_violation=self._check_constraints(rule, targets, artifact_type),
            )
        default = self.document.default
        return PolicyResult(
            tier=Tier(default.tier),
            decision=default.decision,
            destructive=default.tier >= Tier.HIGH_RISK,
            rule="default",
            reason=(
                f"action {name!r} matches no rule in {self.source}; classify it explicitly "
                "to make it reachable"
            ),
        )

    @staticmethod
    def _check_constraints(
        rule: RuleSpec, targets: list[str], artifact_type: str | None
    ) -> str | None:
        c = rule.constraints
        if c.artifact_types and artifact_type is not None:
            allowed = {t.lower() for t in c.artifact_types}
            if artifact_type.lower() not in allowed:
                return (
                    f"artifact type {artifact_type!r} is not in artifact_types {c.artifact_types}"
                )
        for target in targets:
            for pattern in c.deny_values:
                if _value_matches(pattern, target):
                    return f"target {target!r} is denied by deny_values entry {pattern!r}"
            if c.allow_values and not any(_value_matches(p, target) for p in c.allow_values):
                return f"target {target!r} is not in allow_values"
        return None

    # ----------------------------------------------------------- describe
    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "default": {
                "tier": self.document.default.tier,
                "decision": self.document.default.decision,
            },
            "rules": [
                {
                    "match": rule.match.label,
                    "tier": rule.tier,
                    "decision": rule.decision,
                    "destructive": rule.destructive,
                    "deny_values": len(rule.constraints.deny_values),
                }
                for rule in self.document.actions
            ],
        }
