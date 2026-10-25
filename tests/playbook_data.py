"""A synthetic playbook with the structure P2-05 observed (P2-05; 08 §30).

The one read of ``GET /playbooks/{playbook_id}`` on QRadar SOAR 51.0.9.0.20848 kept the
*structure* of the owner's disposable research playbook and none of its values
(``p2_05_playbook.json``, ``p2_05_playbook_xml.json``): which elements occurred in which
namespace class, which attribute names each carried, which carried text, the key shape of
the function element's JSON, and the key shape of the object and its activation
conditions. This module writes a document and an object with exactly that structure,
filled with made-up values; ``test_discovery_playbooks.py`` checks them against the
record element by element and key by key.

What is invented, because the record deliberately holds no value: every id, name, uuid
and text; the vendor namespace URI (the record keeps only that it is on an ``ibm.com``
host); the values of ``type``, ``isExecutable``, ``targetNamespace`` and ``documentation``;
where the empty ``documentation`` element sits (the record keeps that it occurred, not
its parent); and every condition's field name and compared value.
"""

from __future__ import annotations

import json
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from tests.workflow_data import BPMN_DI, BPMN_MODEL, OMG_DC, OMG_DI

VENDOR_NS = "http://synthetic-extension.ibm.com/playbook"  # made up, on an ibm.com host
NAMESPACE_CLASS = {
    BPMN_MODEL: "bpmn_model",
    BPMN_DI: "bpmn_di",
    OMG_DC: "omg_dc",
    OMG_DI: "omg_di",
    VENDOR_NS: "vendor_ibm",
}
# Never to appear in anything this server returns or logs.
CONDITION_VALUE = "synthetic_condition_value_never_shown"
SCRIPT_TEXT = "synthetic_processing_script_never_shown"
RESULT_NAME = "synthetic_result"


def function_settings(**overrides: Any) -> dict[str, Any]:
    """The function element's JSON in the recorded key shape: ``inputs`` was an empty
    object, the scripts and their languages null, ``result_name`` a string."""
    settings: dict[str, Any] = {
        "inputs": {},
        "post_processing_script": None,
        "post_processing_script_language": None,
        "pre_processing_script": None,
        "pre_processing_script_language": None,
        "result_name": RESULT_NAME,
    }
    settings.update(overrides)
    return settings


def playbook_xml(
    function_uuid: str | None,
    *,
    settings: dict[str, Any] | None = None,
    process_extra: str = "",
    end_target: str = "EndPoint_1",
) -> str:
    """Start -> one function call -> end, as the research playbook was built."""
    payload = json.dumps(settings if settings is not None else function_settings())
    uuid_attr = f" uuid={quoteattr(function_uuid)}" if function_uuid is not None else ""
    flows = {
        "Flow_1": ("Start_1", "Function_1"),
        "Flow_2": ("Function_1", end_target),
    }
    flow_xml = "".join(
        f'<sequenceFlow id="{ident}" sourceRef="{source}" targetRef="{target}"/>'
        for ident, (source, target) in flows.items()
    )
    shapes = "".join(
        f'<bpmndi:BPMNShape bpmnElement="{e}" id="Shape_{e}">'
        '<omgdc:Bounds height="36" width="36" x="1" y="1"/></bpmndi:BPMNShape>'
        for e in ("Start_1", "Function_1", "EndPoint_1")
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
        '<process id="playbook_1" isExecutable="true" name="synthetic playbook">'
        "<documentation/>"
        '<startEvent id="Start_1"><outgoing>Flow_1</outgoing></startEvent>'
        '<serviceTask id="Function_1" name="synthetic call" type="type-1">'
        "<extensionElements>"
        f"<vendor:function{uuid_attr}>{escape(payload)}</vendor:function>"
        "</extensionElements>"
        "<incoming>Flow_1</incoming><outgoing>Flow_2</outgoing>"
        "</serviceTask>"
        '<endEvent documentation="synthetic end" id="EndPoint_1">'
        "<incoming>Flow_2</incoming></endEvent>"
        f"{flow_xml}{process_extra}"
        "</process>"
        '<bpmndi:BPMNDiagram id="Diagram_1">'
        f'<bpmndi:BPMNPlane bpmnElement="playbook_1" id="Plane_1">{shapes}{edges}'
        "</bpmndi:BPMNPlane></bpmndi:BPMNDiagram>"
        "</definitions>"
    )


def activation_details(field_name: str, method: str) -> dict[str, Any]:
    """One condition in the recorded key shape, comparing with a sentinel value."""
    return {
        "activation_conditions": {
            "logic_type": "all",
            "conditions": [
                {
                    "field_name": field_name,
                    "method": method,
                    "value": CONDITION_VALUE,
                    "type": None,
                    "evaluation_id": None,
                }
            ],
        }
    }
