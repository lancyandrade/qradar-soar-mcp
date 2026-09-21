"""The chokepoint (P1-13/P1-14; 01 §4). Every MCP tool is declared with
``@soar_tool`` and executed through :func:`run_pipeline`; nothing else may
reach the SOAR client.

    1. MCP tool invoked
    2. registry: declared tier + capability
    3. config: capability flag              ─┐
    4. action_policy: classify the target    │  security.enforce()
    5. tier gate                              │
    6. transport gate                         │
    7. rate / bulk gates (limits.py)          │
    8. approval: required? issued / verified ─┘
    9. audit: MUTATION_PENDING
   10. client: execute
   11. audit: MUTATION_COMMITTED / MUTATION_FAILED (+ post-image)
   12. redact + project response
   13. return

A tool function looks like::

    @soar_tool(name="soar_get_incident", tier=Tier.READ)
    async def soar_get_incident(rt: Runtime, incident_id: int) -> ToolResult: ...

``rt`` is hidden from the MCP schema; the remaining parameters *are* the schema.
"""

from __future__ import annotations

import inspect
import json
import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp_types import ToolAnnotations

from qradar_soar_mcp.errors import SoarError
from qradar_soar_mcp.logging import redact
from qradar_soar_mcp.security.approvals import APPROVAL_ARG, IN_BAND_DISCLAIMER
from qradar_soar_mcp.security.audit import AuditError, new_request_id
from qradar_soar_mcp.security.permissions import (
    Code,
    Decision,
    Outcome,
    PolicyResult,
    deny,
    enforce,
)
from qradar_soar_mcp.security.tiers import (
    APPROVAL_REQUIRED_FROM,
    CAPABILITY_TIERS,
    MUTATING_FROM,
    Tier,
)
from qradar_soar_mcp.tools.runtime import Runtime

logger = logging.getLogger(__name__)

RUNTIME_PARAM = "rt"
INTERNAL_ERROR_MESSAGE = "internal error; see the server log"

Classifier = Callable[[Runtime, Mapping[str, Any]], Awaitable[PolicyResult]]
Describer = Callable[[Mapping[str, Any], PolicyResult | None], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ToolResult:
    """What a tool body returns: the response data plus what the audit log needs."""

    data: Any
    target: dict[str, Any] = field(default_factory=dict)
    pre_image: Any = None
    post_image: Any = None
    soar_response: Any = None


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    tier: Tier
    capability: str | None
    description: str
    func: Callable[..., Awaitable[ToolResult]]
    mutations: int  # objects this tool may mutate per call (0 for reads)
    classify: Classifier | None = None  # per-target policy classification (invoke_action)
    describe: Describer | None = None  # target + plan for approval requests and audit
    idempotent: bool = False
    unsupported: str | None = None  # fixed refusal: SOAR contract unverified (08 §21)

    @property
    def mutating(self) -> bool:
        return self.tier >= MUTATING_FROM

    @property
    def needs_approval_arg(self) -> bool:
        return self.tier >= APPROVAL_REQUIRED_FROM


TOOL_REGISTRY: dict[str, ToolSpec] = {}


class ToolDefinitionError(TypeError):
    """A tool was declared incorrectly. Raised at import time."""


def soar_tool(
    *,
    name: str,
    tier: Tier,
    capability: str | None = None,
    description: str | None = None,
    mutations: int | None = None,
    classify: Classifier | None = None,
    describe: Describer | None = None,
    idempotent: bool = False,
    unsupported: str | None = None,
    registry: dict[str, ToolSpec] | None = None,
) -> Callable[[Callable[..., Awaitable[ToolResult]]], Callable[..., Awaitable[ToolResult]]]:
    """Declare a tool. Validation here is deliberately strict; it runs at import.

    ``unsupported`` keeps a tool registered, and gated like any other, while
    ``enforce()`` refuses every call to it with that text (08 §21)."""

    def decorate(
        func: Callable[..., Awaitable[ToolResult]],
    ) -> Callable[..., Awaitable[ToolResult]]:
        reg = TOOL_REGISTRY if registry is None else registry
        if not name.startswith("soar_") or not name.islower():
            raise ToolDefinitionError(f"{name}: tool names are lower-case and start with soar_")
        if name in reg:
            raise ToolDefinitionError(f"{name}: duplicate tool name")
        if not inspect.iscoroutinefunction(func):
            raise ToolDefinitionError(f"{name}: tool functions must be async")
        params = list(inspect.signature(func).parameters)
        if not params or params[0] != RUNTIME_PARAM:
            raise ToolDefinitionError(f"{name}: first parameter must be '{RUNTIME_PARAM}'")
        if tier >= Tier.HIGH_RISK:
            raise ToolDefinitionError(f"{name}: Tier 5 tools do not exist (02 §1.2)")
        if tier >= MUTATING_FROM:
            if capability is None:
                raise ToolDefinitionError(
                    f"{name}: tier {int(tier)} tools must declare a capability"
                )
            if capability not in CAPABILITY_TIERS:
                raise ToolDefinitionError(f"{name}: unknown capability {capability!r}")
            if CAPABILITY_TIERS[capability] is not tier:
                raise ToolDefinitionError(
                    f"{name}: capability {capability} is tier {int(CAPABILITY_TIERS[capability])}, "
                    f"tool declares tier {int(tier)}"
                )
        elif capability is not None:
            raise ToolDefinitionError(f"{name}: read tools declare no capability")
        if tier >= APPROVAL_REQUIRED_FROM and APPROVAL_ARG not in params:
            raise ToolDefinitionError(f"{name}: tier {int(tier)} tools must accept {APPROVAL_ARG}")
        if tier >= APPROVAL_REQUIRED_FROM and describe is None:
            raise ToolDefinitionError(f"{name}: tier {int(tier)} tools must provide describe()")
        count = mutations if mutations is not None else (1 if tier >= MUTATING_FROM else 0)
        if tier >= MUTATING_FROM and count < 1:
            raise ToolDefinitionError(f"{name}: a mutating tool mutates at least one object")
        if tier < MUTATING_FROM and count != 0:
            raise ToolDefinitionError(f"{name}: a read tool mutates nothing")
        doc = (description or func.__doc__ or "").strip()
        if not doc:
            raise ToolDefinitionError(f"{name}: a description (docstring) is required")
        if unsupported is not None and not unsupported.strip():
            raise ToolDefinitionError(f"{name}: an unsupported tool needs its refusal text")
        spec = ToolSpec(
            name=name,
            tier=tier,
            capability=capability,
            description=doc,
            func=func,
            mutations=count,
            classify=classify,
            describe=describe,
            idempotent=idempotent,
            unsupported=unsupported,
        )
        reg[name] = spec
        func.__soar_tool__ = spec  # type: ignore[attr-defined]
        return func

    return decorate


# ---------------------------------------------------------------- responses
def _error(request_id: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": False,
        "request_id": request_id,
        "error": {"code": code, "message": message},
    }
    out.update(extra)
    return out


def _redacted(value: Any) -> Any:
    """Step 12: nothing that looks like the credential leaves the process.

    Always round-trips through JSON so the response is JSON-native (tuples
    become lists, non-JSON values become strings) whether or not anything
    was redacted. Every string of the result, keys included, is then redacted as the
    text it is. The serialised document is never redacted as one string: there a
    pattern can run past the end of a value into the JSON around it, which removes
    text that is no credential and can leave a document that no longer parses, and
    JSON escaping can hide a credential that holds a quote or a backslash.
    """
    return _redact_strings(json.loads(json.dumps(value, default=str, ensure_ascii=False)))


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_strings(item) for item in value]
    if isinstance(value, dict):
        return {redact(key): _redact_strings(item) for key, item in value.items()}
    return value


def _audit(rt: Runtime, event: str, **fields: Any) -> None:
    """Best-effort audit for every record except MUTATION_PENDING."""
    if rt.audit is None:
        return
    try:
        rt.audit.append(event, transport=rt.transport, **fields)
    except AuditError as exc:
        logger.error("audit write failed (%s): %s", event, exc)


def _describe(
    spec: ToolSpec, args: Mapping[str, Any], policy: PolicyResult | None
) -> dict[str, Any]:
    if spec.describe is not None:
        return spec.describe(args, policy)
    target = {k: v for k, v in args.items() if k.endswith("_id") and k != APPROVAL_ARG}
    return {"target": target, "plan": f"{spec.name} {json.dumps(target, default=str)}"}


# ----------------------------------------------------------------- pipeline
async def run_pipeline(spec: ToolSpec, rt: Runtime, args: Mapping[str, Any]) -> dict[str, Any]:
    request_id = new_request_id()
    started = time.perf_counter()
    args = dict(args)
    settings = rt.settings

    # Steps 3-6, 8 (pure): is this call permitted at all?
    policy: PolicyResult | None = None
    if (
        settings is not None
        and spec.classify is not None
        and spec.capability
        and settings.capability_enabled(spec.capability)
    ):
        try:
            policy = await spec.classify(rt, args)
        except SoarError as exc:
            logger.info("tool %s: classification failed: %s", spec.name, exc.code)
            return {"ok": False, "request_id": request_id, "error": exc.to_dict()}
    decision = enforce(
        tool=spec.name,
        tier=spec.tier,
        capability=spec.capability,
        config=settings,
        transport=rt.transport,
        policy=policy,
        unsupported=spec.unsupported,
    )
    if decision.denied and decision.code is Code.DENY_CONFIG and rt.config_error:
        decision = deny(Code.DENY_CONFIG, f"{decision.reason}: {rt.config_error}", spec.tier)

    # Step 7: rate / bulk gates, plus the kill switch and breaker (02 §5).
    if not decision.denied and rt.limits is not None:
        limits = rt.limits
        blocked = limits.check_kill_switch(decision.tier)
        if blocked is None:
            blocked = limits.check_breaker(decision.tier)
        if blocked is None:
            blocked = limits.check_mutations_per_call(decision.tier, spec.mutations)
        if blocked is not None:
            decision = blocked

    described = _describe(spec, args, policy)
    target = dict(described.get("target") or {})
    plan = str(described.get("plan") or spec.name)
    common: dict[str, Any] = {
        "tool": spec.name,
        "tier": int(decision.tier),
        "capability": spec.capability,
        "policy_rule": decision.policy_rule,
        "target": target,
        "request_id": request_id,
    }

    if decision.denied:
        logger.info("tool %s denied: %s", spec.name, decision.code)
        _audit(rt, "DECISION_DENIED", decision=str(decision.code), reason=decision.reason, **common)
        return _error(request_id, str(decision.code), decision.reason)

    # Step 8: approval.
    approval_id: str | None = None
    approver: str | None = None
    disclaimer: str | None = None
    if decision.outcome is Outcome.REQUIRE_APPROVAL:
        if settings is None or rt.broker is None:  # unreachable: enforce() denied already
            return _error(request_id, str(Code.DENY_CONFIG), "approval broker unavailable")
        supplied = args.get(APPROVAL_ARG)
        if settings.approval_mode == "in_band":
            if not isinstance(supplied, str) or not supplied:
                token = rt.broker.issue_in_band_token(spec.name, args)
                _audit(rt, "APPROVAL_REQUESTED", decision="in_band", reason=plan, **common)
                return _error(
                    request_id,
                    str(Code.REQUIRE_APPROVAL),
                    "confirmation required: repeat the identical call with approval_id set to the "
                    "confirmation token",
                    approval_id=token,
                    plan=plan,
                    disclaimer=IN_BAND_DISCLAIMER,
                )
            outcome = rt.broker.consume_in_band_token(supplied, spec.name, args)
            if not outcome.ok:
                _audit(
                    rt,
                    "DECISION_DENIED",
                    decision=str(Code.DENY_APPROVAL),
                    reason=outcome.reason,
                    **common,
                )
                return _error(request_id, str(Code.DENY_APPROVAL), outcome.reason)
            approval_id, approver, disclaimer = supplied, "in_band", IN_BAND_DISCLAIMER
        else:
            if not isinstance(supplied, str) or not supplied:
                request = rt.broker.request(
                    tool=spec.name,
                    tier=int(decision.tier),
                    capability=spec.capability,
                    args=args,
                    target=target,
                    plan=plan,
                    action=described.get("action"),
                    transport=rt.transport,
                    destructive=decision.destructive,
                    policy_rule=decision.policy_rule,
                )
                _audit(
                    rt,
                    "APPROVAL_REQUESTED",
                    decision=str(Code.REQUIRE_APPROVAL),
                    approval_id=request.approval_id,
                    reason=plan,
                    **common,
                )
                return _error(
                    request_id,
                    str(Code.REQUIRE_APPROVAL),
                    f"Approval requested. Reference {request.approval_id}. A human must approve "
                    "this out of band. Do not retry; call soar_check_approval to poll, then repeat "
                    "the identical call with approval_id set.",
                    approval_id=request.approval_id,
                    plan=plan,
                    expires_at=request.expires_at,
                )
            outcome = rt.broker.verify_and_consume(supplied, tool=spec.name, args=args)
            if not outcome.ok:
                code = Code.REQUIRE_APPROVAL if outcome.state == "pending" else Code.DENY_APPROVAL
                _audit(
                    rt,
                    "DECISION_DENIED",
                    decision=str(code),
                    approval_id=supplied,
                    reason=outcome.reason,
                    **common,
                )
                return _error(request_id, str(code), outcome.reason, approval_id=supplied)
            approval_id, approver = supplied, outcome.approver
            _audit(
                rt,
                "APPROVAL_CONSUMED",
                decision=str(Code.ALLOW),
                approval_id=approval_id,
                approver=approver,
                **common,
            )

    # Step 9: PENDING before any mutation; an unwritable audit log fails closed.
    if spec.mutating:
        if rt.audit is None:
            return _error(
                request_id, str(Code.DENY_AUDIT), "no audit log is open; mutation refused"
            )
        try:
            rt.audit.append(
                "MUTATION_PENDING",
                transport=rt.transport,
                decision=str(Code.ALLOW),
                approval_id=approval_id,
                approver=approver,
                arguments_hash=None,
                **common,
            )
        except AuditError as exc:
            logger.error("audit PENDING write failed; refusing mutation: %s", exc)
            return _error(
                request_id,
                str(Code.DENY_AUDIT),
                "the audit log cannot be written; mutation refused",
            )
        if rt.limits is not None:
            limited = rt.limits.acquire(decision.tier)
            if limited is not None:
                _audit(
                    rt,
                    "DECISION_DENIED",
                    decision=str(limited.code),
                    reason=limited.reason,
                    **common,
                )
                return _error(request_id, str(limited.code), limited.reason)

    # Step 10: execute.
    try:
        result = await spec.func(rt, **args)
    except SoarError as exc:
        logger.info("tool %s failed: %s", spec.name, exc.code)
        _finish(
            rt,
            spec,
            decision,
            common,
            started,
            success=False,
            soar_response=exc.to_dict(),
            approval_id=approval_id,
            approver=approver,
        )
        return {"ok": False, "request_id": request_id, "error": exc.to_dict()}
    except Exception as exc:
        # Never str(exc) to the client; the redacting log handler sees the traceback.
        logger.exception("tool %s crashed (%s)", spec.name, type(exc).__name__)
        _finish(
            rt,
            spec,
            decision,
            common,
            started,
            success=False,
            soar_response={"exception": type(exc).__name__},
            approval_id=approval_id,
            approver=approver,
        )
        return _error(request_id, "internal", INTERNAL_ERROR_MESSAGE)

    # Step 11: COMMITTED with pre/post images.
    _finish(
        rt,
        spec,
        decision,
        common,
        started,
        success=True,
        pre_image=result.pre_image,
        post_image=result.post_image,
        soar_response=result.soar_response,
        approval_id=approval_id,
        approver=approver,
        target=result.target or target,
    )
    # Step 12: redact + project (projection is the tool's job; redaction is ours).
    response: dict[str, Any] = {
        "ok": True,
        "request_id": request_id,
        "data": _redacted(result.data),
    }
    if approval_id is not None:
        response["approval"] = {"approval_id": approval_id, "approver": approver}
    if disclaimer:
        response["disclaimer"] = disclaimer
    logger.info("tool %s ok", spec.name)
    return response


def _finish(
    rt: Runtime,
    spec: ToolSpec,
    decision: Decision,
    common: Mapping[str, Any],
    started: float,
    *,
    success: bool,
    pre_image: Any = None,
    post_image: Any = None,
    soar_response: Any = None,
    approval_id: str | None,
    approver: str | None,
    target: Mapping[str, Any] | None = None,
) -> None:
    if not spec.mutating:
        return
    fields = dict(common)
    if target is not None:
        fields["target"] = dict(target)
    _audit(
        rt,
        "MUTATION_COMMITTED" if success else "MUTATION_FAILED",
        decision=str(Code.ALLOW),
        approval_id=approval_id,
        approver=approver,
        pre_image=pre_image,
        post_image=post_image,
        soar_response=soar_response,
        duration_ms=int((time.perf_counter() - started) * 1000),
        **fields,
    )
    if rt.limits is not None and rt.limits.record_result(decision.tier, success=success):
        _audit(
            rt,
            "BREAKER_TRIPPED",
            decision=str(Code.DENY_BREAKER),
            reason="three consecutive Tier>=2 failures",
            **common,
        )


# ------------------------------------------------------------------ MCP
def bind(spec: ToolSpec, rt: Runtime) -> Callable[..., Awaitable[dict[str, Any]]]:
    """A callable with the tool's public signature that runs the pipeline."""
    sig = inspect.signature(spec.func, eval_str=True)
    public = [p for p in sig.parameters.values() if p.name != RUNTIME_PARAM]

    async def bound(**kwargs: Any) -> dict[str, Any]:
        return await run_pipeline(spec, rt, kwargs)

    bound.__name__ = spec.name
    bound.__qualname__ = spec.name
    bound.__doc__ = spec.description
    bound.__signature__ = sig.replace(parameters=public, return_annotation=dict[str, Any])  # type: ignore[attr-defined]
    return bound


def register_all(
    server: MCPServer[Any], rt: Runtime, registry: Mapping[str, ToolSpec] | None = None
) -> list[str]:
    reg = TOOL_REGISTRY if registry is None else registry
    names: list[str] = []
    for spec in sorted(reg.values(), key=lambda s: (int(s.tier), s.name)):
        server.add_tool(
            bind(spec, rt),
            name=spec.name,
            description=spec.description,
            annotations=ToolAnnotations(
                title=spec.name,
                read_only_hint=not spec.mutating,
                destructive_hint=spec.tier >= APPROVAL_REQUIRED_FROM,
                idempotent_hint=spec.idempotent,
                open_world_hint=True,
            ),
            structured_output=False,
        )
        names.append(spec.name)
    return names
