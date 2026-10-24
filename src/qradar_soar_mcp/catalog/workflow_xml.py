"""Workflow XML to a bounded structural summary (P2-04; 08 §29).

On QRadar SOAR ``51.0.9.0.20848`` a workflow's definition is the string ``content.xml``
of its row in ``GET /workflows`` (``docs/soar-api-verified.md`` §3.3). One read-only
observation established its structure, and only its structure
(``tests/fixtures/soar/verified/p2_04_workflow_xml.json``):

* standard BPMN 2.0: a ``definitions`` root in the OMG BPMN model namespace, holding a
  ``process``;
* nodes ``startEvent``, ``serviceTask``, ``exclusiveGateway`` and ``endEvent``, each with
  an ``id``; edges ``sequenceFlow`` (``id``, ``name``, ``sourceRef``, ``targetRef``), whose
  references all named element identifiers; a gateway's ``default`` attribute; a
  ``conditionExpression`` (``language``, ``type``, and the condition as text);
* a function call is a ``serviceTask`` whose ``extensionElements`` hold one element named
  ``function``, in a namespace on an ``ibm.com`` host, carrying a ``uuid`` attribute and a
  JSON text with ``inputs`` (keyed by input name), the pre- and post-processing scripts
  and their languages, and ``result_name``;
* ``textAnnotation`` and ``association`` (a note and its link, not flow); ``incoming`` and
  ``outgoing`` children that repeat a node's flows.

What this module keeps is what those facts let it state: node identities and BPMN types,
edges taken from ``sequenceFlow`` only, which edge a gateway names as its default, which
edges carry a condition (its language, never its text), and for a function call the uuid,
the input *names* and whether scripts are present. Condition scripts, processing scripts,
input values, annotation text and documentation are never read into the result.

Whether a function reference names a function is decided by matching its uuid against the
catalog's functions; the uuid's meaning is not assumed. A reference that matches nothing
is reported unresolved.

The parser is defensive by construction: a document that declares a DTD or an entity is
refused before parsing, and without a DTD an entity XML does not predefine is a parse
error, so no entity can expand; nothing external is ever fetched; size and element counts
are bounded. A refusal is a fixed sentence, never a quotation of the document.
"""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET  # input is refused unless entity-free; see parse()

# The one namespace whose elements the summary is built from: the OMG BPMN 2.0 model,
# observed exactly (p2_04_workflow_xml.json, namespace class ``bpmn_model``).
BPMN_MODEL_NS = "http://www.omg.org/spec/BPMN/20100524/MODEL"
# The function element's namespace was observed only as "a URI on an ibm.com host"; its
# exact URI was deliberately not recorded, so it is matched by that class and no more.
VENDOR_HOST = "ibm.com"
FUNCTION_ELEMENT = "function"

# The node types the observation saw. Any other BPMN element with an id inside the
# process is still listed, with ``type_observed`` false and a problem said about it.
OBSERVED_NODE_TYPES = frozenset({"startEvent", "endEvent", "serviceTask", "exclusiveGateway"})
EDGE_ELEMENT = "sequenceFlow"
# Inside a process: not flow, and not a node (an annotation, its link, prose, extensions).
NON_FLOW_ELEMENTS = frozenset(
    {"textAnnotation", "association", "documentation", "extensionElements"}
)
# The keys of the function element's JSON that were observed (its value types were null
# for the scripts and result name, so a non-empty string is the only "present").
PRE_SCRIPT_KEY = "pre_processing_script"
POST_SCRIPT_KEY = "post_processing_script"
INPUTS_KEY = "inputs"
RESULT_NAME_KEY = "result_name"

# Bounds. The one workflow observed was under 10 KB. Exceeding a bound refuses the whole
# summary; a summary is never cut short silently.
MAX_XML_CHARS = 1_000_000
MAX_ELEMENTS = 20_000
MAX_NODES = 2_000
MAX_EDGES = 4_000
MAX_FUNCTION_JSON_CHARS = 200_000
MAX_INPUT_NAMES = 200
# An identifier (element id, reference, uuid) longer than this refuses the document:
# graph checks compare whole identifiers, and a cut one could match another's prefix.
IDENT_LIMIT = 200
TEXT_LIMIT = 300  # characters of a name kept
MAX_PROBLEMS = 50

_DTD_OR_ENTITY = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class WorkflowXmlRefusedError(ValueError):
    """The document is not summarised. ``reason`` is a fixed sentence about why."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class FunctionCall:
    uuid: str | None  # the attribute exactly as written (cut only when over-long)
    input_names: tuple[str, ...]
    has_pre_processing_script: bool
    has_post_processing_script: bool
    result_name: str | None
    payload_parsed: bool
    # False when the uuid was cut to IDENT_LIMIT: a cut value is never matched.
    uuid_matchable: bool = True


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    type: str
    name: str | None
    function: FunctionCall | None = None


@dataclass(frozen=True, slots=True)
class Edge:
    id: str
    source: str
    target: str
    name: str | None
    conditional: bool
    condition_language: str | None
    default: bool = False
    valid: bool = True


def _unchanged(text: str) -> str:
    return text


@dataclass(slots=True)
class Graph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    annotations: int = 0
    problems: list[str] = field(default_factory=list)
    # Applied to each kept text value BEFORE it is cut to its bound, so that a
    # credential straddling the bound is seen whole by the redactor.
    clean: Callable[[str], str] = _unchanged

    def name(self, value: str | None) -> str | None:
        if value is None:
            return None
        text = self.clean(value).strip()
        return text[:TEXT_LIMIT] if text else None

    def problem(self, text: str) -> None:
        if len(self.problems) < MAX_PROBLEMS:
            self.problems.append(text)
        elif len(self.problems) == MAX_PROBLEMS:
            self.problems.append("further problems were not listed")


# ------------------------------------------------------------------ helpers
def _split(tag: Any) -> tuple[str | None, str]:
    """``(namespace URI or None, local name)``. Comments and processing instructions
    have no string tag and are reported as ``(None, "")``."""
    if not isinstance(tag, str):
        return None, ""
    if tag.startswith("{"):
        uri, _, local = tag[1:].partition("}")
        return uri, local
    return None, tag


def _is_bpmn(element: ET.Element, local: str | None = None) -> bool:
    uri, name = _split(element.tag)
    return uri == BPMN_MODEL_NS and (local is None or name == local)


def _is_vendor(uri: str | None) -> bool:
    if not uri:
        return False
    try:
        host = (urlsplit(uri).hostname or "").lower()
    except ValueError:
        return False
    return host == VENDOR_HOST or host.endswith("." + VENDOR_HOST)


def _attr(element: ET.Element, name: str) -> str | None:
    """An attribute by local name, whatever namespace prefix it was written with."""
    for key, value in element.attrib.items():
        if _split(key)[1] == name:
            return value
    return None


def _ident(value: str | None) -> str | None:
    """An identifier exactly as written: never stripped, never cut. One over
    ``IDENT_LIMIT`` refuses the document, since comparing cut identifiers could make a
    dangling reference look valid."""
    if value is None or value == "":
        return None
    if len(value) > IDENT_LIMIT:
        raise WorkflowXmlRefusedError(
            f"an identifier in the workflow XML is longer than {IDENT_LIMIT} characters"
        )
    return value


def parse(xml: str) -> ET.Element:
    """The root element of ``xml``, or :class:`WorkflowXmlRefusedError`.

    ElementTree on CPython's expat neither loads a DTD nor fetches anything; what it
    would still expand is an entity declared in the document. A document that declares
    a DTD or an entity is refused before it is parsed (also when that text sits in a
    comment or CDATA section: refusing too much is the safe side). Without a DTD, an
    entity XML does not predefine is a parse error, so there is nothing to expand, and
    a ``&`` inside CDATA (``a && b`` in a script) is ordinary text.
    """
    if not isinstance(xml, str):
        raise WorkflowXmlRefusedError("the workflow content is not text")
    if len(xml) > MAX_XML_CHARS:
        raise WorkflowXmlRefusedError(f"the workflow XML is longer than {MAX_XML_CHARS} characters")
    if _DTD_OR_ENTITY.search(xml):
        raise WorkflowXmlRefusedError("the workflow XML declares a DTD or an entity")
    try:
        root = ET.fromstring(xml)  # noqa: S314 - DTDs and entities are refused above
    except ET.ParseError:
        raise WorkflowXmlRefusedError("the workflow XML is not well-formed") from None
    for count, _ in enumerate(root.iter(), start=1):
        if count > MAX_ELEMENTS:
            raise WorkflowXmlRefusedError(f"the workflow XML has more than {MAX_ELEMENTS} elements")
    return root


def _function_call(task: ET.Element, graph: Graph, node_id: str) -> FunctionCall | None:
    """The function reference of a ``serviceTask``: its vendor ``function`` element."""
    found: list[ET.Element] = []
    for extensions in task:
        if not _is_bpmn(extensions, "extensionElements"):
            continue
        for child in extensions:
            uri, local = _split(child.tag)
            if local == FUNCTION_ELEMENT and _is_vendor(uri):
                found.append(child)
    if not found:
        graph.problem(f"service task {node_id} carries no function reference")
        return None
    if len(found) > 1:
        graph.problem(f"service task {node_id} carries more than one function reference")
        return None
    element = found[0]
    raw_uuid = _attr(element, "uuid")
    # Matched exactly as written: nothing is stripped, case-folded or cut. One over
    # the bound is not kept at all (never a prefix of it) and is not matched.
    matchable = bool(raw_uuid) and len(raw_uuid or "") <= IDENT_LIMIT
    uuid = raw_uuid if matchable else None
    if not raw_uuid:
        graph.problem(f"service task {node_id}: its function reference has no uuid")
    elif not matchable:
        graph.problem(
            f"service task {node_id}: its function uuid is longer than {IDENT_LIMIT} "
            "characters; it is not kept and not matched"
        )
    payload: Any = None
    text = element.text or ""
    if text.strip():
        if len(text) > MAX_FUNCTION_JSON_CHARS:
            graph.problem(f"service task {node_id}: its function settings are too long to read")
        else:
            try:
                payload = json.loads(text)
            except (ValueError, RecursionError):  # deeply nested JSON recurses
                payload = None
    if not isinstance(payload, Mapping):
        if text.strip():
            graph.problem(f"service task {node_id}: its function settings are not a JSON object")
        return FunctionCall(uuid, (), False, False, None, False, uuid_matchable=matchable)
    inputs = payload.get(INPUTS_KEY)
    names = sorted(graph.name(str(k)) or "" for k in inputs) if isinstance(inputs, Mapping) else []
    if len(names) > MAX_INPUT_NAMES:
        graph.problem(f"service task {node_id}: only the first {MAX_INPUT_NAMES} inputs are named")
    result = payload.get(RESULT_NAME_KEY)
    return FunctionCall(
        uuid=uuid,
        input_names=tuple(n for n in names[:MAX_INPUT_NAMES] if n),
        has_pre_processing_script=_present(payload.get(PRE_SCRIPT_KEY)),
        has_post_processing_script=_present(payload.get(POST_SCRIPT_KEY)),
        result_name=graph.name(result) if isinstance(result, str) else None,
        payload_parsed=True,
        uuid_matchable=matchable,
    )


def _present(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


# ------------------------------------------------------------------- summary
def summarise(xml: str, clean: Callable[[str], str] = _unchanged) -> Graph:
    """The structural summary of one workflow's XML, or :class:`WorkflowXmlRefusedError`.

    ``clean`` (the catalog's credential filter) is applied to every kept text value
    before it is cut to its bound. Identifiers are compared exactly as written and are
    never cut, so the graph checks see the document's real identities; they are
    filtered whole, with everything else, when the summary is finished."""
    root = parse(xml)
    if not _is_bpmn(root, "definitions"):
        raise WorkflowXmlRefusedError("the root element is not a BPMN 2.0 definitions element")
    processes = [child for child in root if _is_bpmn(child, "process")]
    if not processes:
        raise WorkflowXmlRefusedError("the workflow XML has no BPMN process")
    if len(processes) > 1:
        # Only one process per document was observed; how SOAR would relate two is unknown.
        raise WorkflowXmlRefusedError("the workflow XML has more than one BPMN process")
    process = processes[0]
    graph = Graph(clean=clean)
    seen: set[str] = set()
    flows: list[ET.Element] = []
    for element in process:
        uri, local = _split(element.tag)
        if uri != BPMN_MODEL_NS:
            if local:  # not a comment
                graph.problem("an element outside the BPMN model namespace was ignored")
            continue
        if local in NON_FLOW_ELEMENTS:
            graph.annotations += local == "textAnnotation"
            continue
        ident = _ident(_attr(element, "id"))
        if ident is None:
            graph.problem(f"a {local} element without an id was ignored")
            continue
        if ident in seen:
            raise WorkflowXmlRefusedError("two elements of the workflow share one id")
        seen.add(ident)
        if local == EDGE_ELEMENT:
            flows.append(element)
            continue
        if local not in OBSERVED_NODE_TYPES:
            graph.problem(
                f"element {ident} is a {local}, a type not observed on 51.0.9.0.20848; "
                "anything it contains is not summarised"
            )
        graph.nodes.append(
            Node(
                id=ident,
                type=local,
                name=graph.name(_attr(element, "name")),
                function=_function_call(element, graph, ident) if local == "serviceTask" else None,
            )
        )
        if len(graph.nodes) > MAX_NODES:
            raise WorkflowXmlRefusedError(f"the workflow has more than {MAX_NODES} nodes")
    if len(flows) > MAX_EDGES:
        raise WorkflowXmlRefusedError(f"the workflow has more than {MAX_EDGES} sequence flows")
    _edges(graph, flows, process)
    _check(graph)
    return graph


def _edges(graph: Graph, flows: list[ET.Element], process: ET.Element) -> None:
    """Edges from ``sequenceFlow`` only, each reference checked against the nodes."""
    nodes = {node.id for node in graph.nodes}
    defaults: dict[str, str] = {}  # gateway id -> the flow id it names as default
    for element in process:
        local = _split(element.tag)[1]
        if not _is_bpmn(element) or local == EDGE_ELEMENT:
            continue
        ident, default = _ident(_attr(element, "id")), _ident(_attr(element, "default"))
        if ident is None or default is None or ident not in nodes:
            continue
        if local.endswith("Gateway"):
            defaults[ident] = default
        else:
            # Only a gateway's default was observed; another node's is not read.
            graph.problem(
                f"node {ident} is a {local} with a default attribute, which is not read: "
                "only a gateway's default was observed"
            )
    named_defaults = set(defaults.values())
    for element in flows:
        ident = _ident(_attr(element, "id")) or ""
        source, target = _ident(_attr(element, "sourceRef")), _ident(_attr(element, "targetRef"))
        valid = True
        if source is None or source not in nodes:
            graph.problem(f"sequence flow {ident}: its source does not name a node")
            valid = False
        if target is None or target not in nodes:
            graph.problem(f"sequence flow {ident}: its target does not name a node")
            valid = False
        conditions = [c for c in element if _is_bpmn(c, "conditionExpression")]
        if len(conditions) > 1:
            graph.problem(f"sequence flow {ident} has more than one condition")
        language = graph.name(_attr(conditions[0], "language")) if conditions else None
        is_default = ident in named_defaults and defaults.get(source or "") == ident
        if is_default and conditions:
            graph.problem(f"sequence flow {ident} is a default flow and also has a condition")
        graph.edges.append(
            Edge(
                id=ident,
                source=source or "",
                target=target or "",
                name=graph.name(_attr(element, "name")),
                conditional=bool(conditions),
                condition_language=language,
                default=is_default,
                valid=valid,
            )
        )
    flow_sources = {edge.id: edge.source for edge in graph.edges}
    for gateway, flow in defaults.items():
        if flow_sources.get(flow) != gateway:
            graph.problem(f"node {gateway} names a default flow that is not one of its own")


def _check(graph: Graph) -> None:
    """What the editor would also object to, and what makes a graph hard to follow."""
    types = {node.id: node.type for node in graph.nodes}
    outgoing: dict[str, list[Edge]] = {node.id: [] for node in graph.nodes}
    for edge in graph.edges:
        if edge.valid:
            outgoing[edge.source].append(edge)
    for node in graph.nodes:
        out = outgoing[node.id]
        if node.type == "exclusiveGateway" and len(out) > 1:
            for edge in out:
                if not edge.conditional and not edge.default:
                    # The appliance's editor refused to save exactly this (observed in the
                    # UI on 51.0.9.0.20848 while the evidence workflow was built).
                    graph.problem(
                        f"gateway {node.id}: flow {edge.id} has no condition and is not the default"
                    )
        if not out and node.type != "endEvent":
            graph.problem(f"node {node.id} has no outgoing flow and is not an end event")
    starts = [ident for ident, kind in types.items() if kind == "startEvent"]
    if not starts:
        graph.problem("the workflow has no start event")
        return
    reached = set(starts)
    queue = deque(starts)
    while queue:
        for edge in outgoing[queue.popleft()]:
            if edge.target not in reached:
                reached.add(edge.target)
                queue.append(edge.target)
    unreached = sorted(set(types) - reached)
    if unreached:
        graph.problem(
            f"{len(unreached)} node(s) cannot be reached from a start event: "
            + ", ".join(unreached[:10])
        )
