"""Risk tiers and the capability→tier map (P1-05; 02 §1-2).

Tier 5 has no enabling flag: there is deliberately no ``SOAR_ALLOW_TIER5``.
"""

from __future__ import annotations

from enum import IntEnum


class Tier(IntEnum):
    READ = 0
    DOCUMENTATION = 1
    MODIFICATION = 2
    CONTROL = 3
    AUTOMATION = 4
    HIGH_RISK = 5


# Which flag enables which tier (02 §2). Tier 0 needs no flag; Tier 5 has none.
CAPABILITY_TIERS: dict[str, Tier] = {
    "SOAR_ALLOW_COMMENTS": Tier.DOCUMENTATION,
    "SOAR_ALLOW_ARTIFACTS": Tier.DOCUMENTATION,
    "SOAR_ALLOW_INCIDENT_WRITES": Tier.MODIFICATION,
    "SOAR_ALLOW_TASK_WRITES": Tier.MODIFICATION,
    "SOAR_ALLOW_INCIDENT_CLOSE": Tier.MODIFICATION,
    "SOAR_ALLOW_ACTIONS": Tier.CONTROL,
    "SOAR_ALLOW_DESTRUCTIVE_ACTIONS": Tier.CONTROL,
    "SOAR_ALLOW_PLAYBOOK_DRAFT": Tier.AUTOMATION,
    "SOAR_ALLOW_PLAYBOOK_EXPORT": Tier.AUTOMATION,
    "SOAR_ALLOW_PLAYBOOK_CREATE": Tier.AUTOMATION,
    "SOAR_ALLOW_PLAYBOOK_MODIFY": Tier.AUTOMATION,
    "SOAR_ALLOW_PLAYBOOK_DEPLOY": Tier.AUTOMATION,
    "SOAR_ALLOW_PLAYBOOK_ENABLE": Tier.AUTOMATION,
}

# From this tier up: never over HTTP (01 §2.1), and a human approval by default (02 §4).
HTTP_DENIED_FROM = Tier.CONTROL
APPROVAL_REQUIRED_FROM = Tier.CONTROL
# Kill switch and blast-radius caps apply from here (02 §5).
MUTATING_FROM = Tier.DOCUMENTATION


def tier_of_capability(capability: str) -> Tier:
    try:
        return CAPABILITY_TIERS[capability]
    except KeyError:
        raise ValueError(f"{capability!r} is not a capability flag (02 §2)") from None
