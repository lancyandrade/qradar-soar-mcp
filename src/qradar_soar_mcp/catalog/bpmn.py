"""BPMN 2.0 documents to catalog summaries: shared by workflows (P2-04; 08 §29) and
playbooks (P2-05; 08 §30).

On QRadar SOAR 51.0.9.0.20848 both are standard BPMN 2.0 with the same vendor function
element (``p2_04_workflow_xml.json``, ``p2_05_playbook_xml.json``), so both are summarised
by :func:`workflow_xml.summarise` and resolved here the same way: a call's ``uuid``
attribute, exactly as written, against the ``uuid`` of exactly one catalog function. On
that version a playbook's call uuid was observed to equal the uuid of exactly one
function of ``GET /functions``. Pure functions: nothing here reads SOAR or a catalog.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any

from qradar_soar_mcp.catalog import workflow_xml
from qradar_soar_mcp.catalog.models import (
    FunctionSpec,
    WorkflowEdge,
    WorkflowFunctionCall,
    WorkflowNode,
)

logger = logging.getLogger(__name__)


def function_index(
    functions: Mapping[str, FunctionSpec],
) -> tuple[dict[str, str], frozenset[str]]:
    """``uuid -> catalog key`` for every function, and the uuids two functions share,
    which resolve to neither (said per call). Exact strings: nothing is normalised."""
    by_uuid: dict[str, str] = {}
    shared: set[str] = set()
    for key, spec in functions.items():
        if spec.uuid in by_uuid:
            shared.add(spec.uuid)
        by_uuid[spec.uuid] = key
    return by_uuid, frozenset(shared)


def clean_tree(value: Any, clean: Callable[[str], str]) -> Any:
    """``value`` with ``clean`` applied to every string in it, keys excluded."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, list | tuple):
        return [clean_tree(item, clean) for item in value]
    if isinstance(value, Mapping):
        return {key: clean_tree(item, clean) for key, item in value.items()}
    return value


def summarise_bpmn(
    xml: str,
    function_by_uuid: Mapping[str, str],
    ambiguous_uuids: frozenset[str],
    clean: Callable[[str], str] | None,
    *,
    document: str,
    failed: str,
) -> dict[str, Any]:
    """The structure fields of a workflow or playbook summary, from its BPMN XML: either
    ``structure: refused`` with a fixed ``refusal``, or the nodes, edges, annotation count
    and problems, with each function call resolved against the catalog's functions.

    Any unexpected error while summarising refuses this one document (its type is logged,
    never its text), so a caller never fails on a document someone wrote."""
    try:
        if clean:
            graph = workflow_xml.summarise(xml, clean, document=document)
        else:
            graph = workflow_xml.summarise(xml, document=document)
    except workflow_xml.WorkflowXmlRefusedError as refused:
        return {"structure": "refused", "refusal": refused.reason}
    except Exception as exc:
        # Type only: nothing of the document is put into a log line.
        logger.warning("a %s could not be summarised (%s)", document, type(exc).__name__)
        return {"structure": "refused", "refusal": failed}
    nodes: list[WorkflowNode] = []
    for node in graph.nodes:
        call = node.function
        nodes.append(
            WorkflowNode(
                id=node.id,
                type=node.type,
                type_observed=node.type in workflow_xml.OBSERVED_NODE_TYPES,
                name=node.name,
                function=None
                if call is None
                else _function_call(call, function_by_uuid, ambiguous_uuids),
            )
        )
    problems = list(graph.problems)
    for parsed, summary in zip(graph.nodes, nodes, strict=True):
        resolved = summary.function
        if resolved is None or resolved.resolution != "unresolved" or resolved.uuid is None:
            continue
        if parsed.function is not None and not parsed.function.uuid_matchable:
            continue  # the parser has said why it is not matched
        if resolved.uuid in ambiguous_uuids:
            problems.append(
                f"service task {summary.id}: its function uuid is shared by more than one "
                "function in this catalog"
            )
        else:
            problems.append(
                f"service task {summary.id}: its function uuid names no function in this catalog"
            )
    return {
        "structure": "parsed",
        "nodes": tuple(nodes),
        "edges": tuple(
            WorkflowEdge(
                id=edge.id,
                source=edge.source,
                target=edge.target,
                name=edge.name,
                kind="default"
                if edge.default
                else "conditional"
                if edge.conditional
                else "unconditional",
                condition_language=edge.condition_language,
                valid=edge.valid,
            )
            for edge in graph.edges
        ),
        "annotations": graph.annotations,
        "problems": tuple(problems),
    }


def _function_call(
    call: workflow_xml.FunctionCall,
    function_by_uuid: Mapping[str, str],
    ambiguous_uuids: frozenset[str],
) -> WorkflowFunctionCall:
    """Resolved by exact uuid equality with exactly one function of the same catalog, or
    not at all. A uuid cut to the length bound, or shared by two functions, never is."""
    name = (
        function_by_uuid.get(call.uuid)
        if call.uuid is not None and call.uuid_matchable and call.uuid not in ambiguous_uuids
        else None
    )
    return WorkflowFunctionCall(
        uuid=call.uuid,
        resolution="no_uuid" if call.uuid is None else "resolved" if name else "unresolved",
        function=name,
        input_names=call.input_names,
        has_pre_processing_script=call.has_pre_processing_script,
        has_post_processing_script=call.has_post_processing_script,
        result_name=call.result_name,
        settings_parsed=call.payload_parsed,
    )
