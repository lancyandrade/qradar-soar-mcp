"""A synthetic workflow with the structure P2-04 observed (P2-04; 08 §29).

The one read of ``GET /workflows`` on QRadar SOAR 51.0.9.0.20848 kept the *structure* of
one workflow's XML and none of its values (``p2_04_workflow_xml.json``): which elements
occurred in which namespace class, which attribute names each carried, which carried
text, and the key shape of the function element's JSON. This module writes a document
with exactly that structure, filled with made-up values, and
``test_workflow_summary.py`` checks it against the record element by element, so a test
built on it cannot rely on a name the appliance was not seen to use.

What is invented, because the record deliberately holds no value: every id, name, uuid
and text; the exact URI of the vendor namespace (the record keeps only that it is on an
``ibm.com`` host: ``VENDOR_NS`` below is made up on such a host); and the value of the
attributes ``type``, ``language`` and ``targetNamespace``. The standard OMG namespace
URIs are not invented: the record classified them by exact match.
"""

from __future__ import annotations

import json
from typing import Any
from xml.sax.saxutils import escape, quoteattr

BPMN_MODEL = "http://www.omg.org/spec/BPMN/20100524/MODEL"
BPMN_DI = "http://www.omg.org/spec/BPMN/20100524/DI"
OMG_DC = "http://www.omg.org/spec/DD/20100524/DC"
OMG_DI = "http://www.omg.org/spec/DD/20100524/DI"
VENDOR_NS = "http://synthetic-extension.ibm.com/workflow"  # made up, on an ibm.com host
# Namespace classes as the probe named them (scripts/probe/probe_p2_04.py).
NAMESPACE_CLASS = {
    BPMN_MODEL: "bpmn_model",
    BPMN_DI: "bpmn_di",
    OMG_DC: "omg_dc",
    OMG_DI: "omg_di",
    VENDOR_NS: "vendor_ibm",
}

CONDITION_TEXT = "synthetic_condition_text_never_in_a_summary"
DOCUMENTATION_TEXT = "synthetic documentation text"
ANNOTATION_TEXT = "synthetic annotation text"
INPUT_VALUE = "synthetic_input_value_never_in_a_summary"


def function_settings(input_name: str, **overrides: Any) -> dict[str, Any]:
    """The function element's JSON, in the recorded key shape (values made up)."""
    settings: dict[str, Any] = {
        "inputs": {
            input_name: {
                "input_type": "input_type-1",
                "static_input": {"select_value": INPUT_VALUE},
            }
        },
        "post_processing_script": None,
        "post_processing_script_language": None,
        "pre_processing_script": None,
        "pre_processing_script_language": None,
        "result_name": None,
    }
    settings.update(overrides)
    return settings


def workflow_xml(
    function_uuid: str,
    *,
    input_name: str = "input_100",
    settings: dict[str, Any] | None = None,
    process_extra: str = "",
    default_flow: str = "SequenceFlow_3",
    condition_flow: str = "SequenceFlow_4",
) -> str:
    """Start -> function call -> exclusive gateway -> two ends: the default flow to one end,
    a conditional flow to the other. A note is linked to the start event."""
    payload = json.dumps(settings if settings is not None else function_settings(input_name))
    flows = {
        "SequenceFlow_1": ("StartEvent_1", "ServiceTask_1"),
        "SequenceFlow_2": ("ServiceTask_1", "ExclusiveGateway_1"),
        "SequenceFlow_3": ("ExclusiveGateway_1", "EndEvent_1"),
        "SequenceFlow_4": ("ExclusiveGateway_1", "EndEvent_2"),
    }
    flow_xml = []
    for ident, (source, target) in flows.items():
        condition = (
            f'<conditionExpression language="language-1" type="type-1">{escape(CONDITION_TEXT)}'
            "</conditionExpression>"
            if ident == condition_flow
            else ""
        )
        flow_xml.append(
            f'<sequenceFlow id="{ident}" name="flow name {ident[-1]}" sourceRef="{source}" '
            f'targetRef="{target}">{condition}</sequenceFlow>'
        )
    shapes = "".join(
        f'<bpmndi:BPMNShape bpmnElement="{e}" id="Shape_{e}" isMarkerVisible="true">'
        '<omgdc:Bounds height="36" width="36" x="1" y="1"/></bpmndi:BPMNShape>'
        for e in ("StartEvent_1", "ServiceTask_1", "ExclusiveGateway_1", "EndEvent_1")
    )
    edges = "".join(
        f'<bpmndi:BPMNEdge bpmnElement="{e}" id="Edge_{e}"><omgdi:waypoint x="1" y="1"/>'
        '<omgdi:waypoint x="2" y="2"/><bpmndi:BPMNLabel/></bpmndi:BPMNEdge>'
        for e in flows
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<definitions xmlns="{BPMN_MODEL}" xmlns:bpmndi="{BPMN_DI}" xmlns:omgdc="{OMG_DC}" '
        f'xmlns:omgdi="{OMG_DI}" xmlns:vendor="{VENDOR_NS}" '
        'targetNamespace="http://synthetic.example/target">'
        '<process id="process_1" isExecutable="true" name="synthetic process">'
        f"<documentation>{escape(DOCUMENTATION_TEXT)}</documentation>"
        '<startEvent id="StartEvent_1"><outgoing>SequenceFlow_1</outgoing></startEvent>'
        '<serviceTask id="ServiceTask_1" name="synthetic call" type="type-1">'
        "<extensionElements>"
        f"<vendor:function uuid={quoteattr(function_uuid)}>{escape(payload)}</vendor:function>"
        "</extensionElements>"
        "<incoming>SequenceFlow_1</incoming><outgoing>SequenceFlow_2</outgoing>"
        "</serviceTask>"
        f'<exclusiveGateway default="{default_flow}" id="ExclusiveGateway_1">'
        "<incoming>SequenceFlow_2</incoming></exclusiveGateway>"
        '<endEvent id="EndEvent_1"><incoming>SequenceFlow_3</incoming></endEvent>'
        '<endEvent id="EndEvent_2"><incoming>SequenceFlow_4</incoming></endEvent>'
        f"{''.join(flow_xml)}"
        f'<textAnnotation id="TextAnnotation_1"><text>{escape(ANNOTATION_TEXT)}</text>'
        "</textAnnotation>"
        '<association id="Association_1" sourceRef="StartEvent_1" targetRef="TextAnnotation_1"/>'
        f"{process_extra}"
        "</process>"
        '<bpmndi:BPMNDiagram id="Diagram_1">'
        f'<bpmndi:BPMNPlane bpmnElement="process_1" id="Plane_1">{shapes}{edges}'
        "</bpmndi:BPMNPlane></bpmndi:BPMNDiagram>"
        "</definitions>"
    )
