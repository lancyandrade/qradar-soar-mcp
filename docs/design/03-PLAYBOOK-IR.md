# 03 — Playbook Intermediate Representation (IR)

## 1. Why an IR

Claude must never emit SOAR-native automation artifacts directly. SOAR's native
representation of a playbook is a BPMN 2.0 XML document carrying
Resilient-specific extension elements, embedded pre/post-process Python, node
UUIDs and canvas coordinates. Asking a language model to write that produces
output that is (a) unverifiable, (b) silently wrong in ways that only appear at
runtime, and (c) capable of embedding arbitrary Python.

The IR exists to make three things possible:

1. **Verifiability** — a closed, typed schema can be statically checked against
   the live SOAR object catalog before anything is created.
2. **Reviewability** — a human approving a deployment reads 40 lines of YAML,
   not 900 lines of XML.
3. **Containment** — the IR grammar has no expression that can express
   "execute arbitrary Python". Not because we filter it out, but because there
   is no production for it.

The compiler is the only component that emits SOAR-native output, it is
ordinary reviewed Python, and it is covered by golden-file tests.

---

## 2. Schema (`ir_version: 1`)

```yaml
ir_version: 1

metadata:
  name: "Suspicious PowerShell Response"          # required
  display_name: "Suspicious PowerShell Response"
  api_name: "suspicious_powershell_response"      # derived if omitted; [a-z0-9_]
  description: "Enrich, decide, and contain hosts running encoded PowerShell."
  author: "generated-by-claude"
  source_incidents: [2317, 2094, 1876]            # provenance for review
  tags: ["malware", "endpoint", "containment"]

trigger:
  object_type: incident                           # incident | task | artifact | note | milestone
  activation: manual                              # manual | automatic
  conditions:                                     # ANDed
    - field: incident.incident_type_ids
      op: includes
      value: "Malware"
    - field: artifact.type
      op: equals
      value: "Process"
    - field: artifact.value
      op: contains
      value: "powershell.exe"

inputs:                                           # only for activation: manual
  - name: analyst_justification
    type: text
    required: true

local:                                            # named intermediate values
  - name: suspect_ip
    from: incident.properties.source_ip

steps:
  - id: enrich_ip
    type: function
    function: fn_threat_intel_lookup              # SOAR function api_name
    message_destination: fn_threat_intel          # must match the function's MD
    inputs:
      ip: "{{ local.suspect_ip }}"
    outputs:
      reputation_score: "$.results.reputation.score"   # JSONPath into results
      ti_summary: "$.results.summary"
    on_error: halt                                # halt | continue | branch:<id>
    timeout_seconds: 120

  - id: note_enrichment
    type: add_note
    text: "Threat intel: {{ steps.enrich_ip.ti_summary }}"
    after: [enrich_ip]

  - id: decision
    type: condition
    expression:
      all:
        - { left: "{{ steps.enrich_ip.reputation_score }}", op: gt, right: 80 }
        - { left: "{{ incident.severity_code }}", op: in, right: ["High", "Medium"] }
    after: [enrich_ip]

  - id: isolate
    type: function
    function: fn_edr_isolate_endpoint
    message_destination: fn_edr
    inputs:
      hostname: "{{ incident.properties.affected_host }}"
    after: [decision]
    when: decision.true
    risk:
      tier: 3
      destructive: true

  - id: block
    type: function
    function: fn_firewall_block_ip
    message_destination: fn_firewall
    inputs:
      ip: "{{ local.suspect_ip }}"
    after: [decision]
    when: decision.true
    risk:
      tier: 3
      destructive: true

  - id: benign_close
    type: set_field
    field: incident.resolution_id
    value: "Not an Issue"
    after: [decision]
    when: decision.false

approval:
  required_for: [isolate, block]                  # emits a manual gate before these
  approver_group: "SOC Tier 2"                    # SOAR group; validated to exist

risk:
  max_tier: 3                                     # declared; validator recomputes and must agree
  destructive: true

compile:
  target: soar_playbook                           # soar_playbook | soar_workflow
  min_soar_version: "44.0"
```

### 2.1 Step types (closed set)

| `type` | Emits | Tier |
|---|---|---|
| `function` | Function node bound to a message destination | inherited from `action_policy` classification of the function |
| `condition` | Decision node with two named outcomes `<id>.true` / `<id>.false` | 0 |
| `add_note` | Note-add node | 1 |
| `add_artifact` | Artifact-add node | 1 |
| `set_field` | Field assignment node | 2 |
| `create_task` | Task creation node | 2 |
| `set_task_status` | Task status node | 2 |
| `manual_gate` | Human approval / manual task that blocks downstream steps | 0 (it *is* the control) |
| `parallel` | Fan-out to named branches | 0 |
| `join` | Fan-in; `mode: all \| any` | 0 |
| `wait` | Timer node, `duration_seconds` bounded by `SOAR_IR_MAX_WAIT` | 0 |
| `subplaybook` | Invoke another playbook by `api_name` | inherited, transitively |

**Deliberately absent:** `script`, `python`, `exec`, `http_request`, `loop`,
`goto`. There is no way to express arbitrary code or unbounded iteration in IR
v1. `script` may be added in a later IR version only behind
`SOAR_ALLOW_SCRIPT_WRITES` with a separate design review; it is not in scope.

### 2.2 Expression grammar (closed)

```
expression := { all: [expr, …] } | { any: [expr, …] } | { not: expr } | comparison
comparison := { left: operand, op: operator, right: operand }
operand    := literal | "{{ reference }}"
reference  := incident.<field> | artifact.<field> | local.<name>
            | steps.<step_id>.<output_name> | inputs.<name>
operator   := equals | not_equals | contains | not_contains | starts_with
            | ends_with | in | not_in | includes | gt | gte | lt | lte
            | is_null | is_not_null | matches_regex
```

Notes:

- **No arithmetic, no function calls, no string interpolation inside
  comparisons.** `{{ a }} + {{ b }} > 5` is not expressible. If a computation is
  needed, it belongs in a SOAR function written by a human.
- `matches_regex` patterns are compiled at validation time with a length cap and
  a catastrophic-backtracking check (reject nested quantifiers) — a ReDoS in a
  playbook running on every incident is a real availability risk.
- `{{ … }}` references are resolved by the compiler into SOAR's native data
  binding. They are **not** a template engine; the validator rejects anything
  that is not exactly one whitespace-trimmed reference.

### 2.3 Graph rules

- `after` defines edges. A step with no `after` is a root, executed on trigger.
- The graph must be a **DAG**. Cycles are a validation error (`IR-E-CYCLE`).
- `when` may only reference the outcome of a `condition` step listed in `after`.
- Every non-root step must be reachable from a root.
- Steps referenced in `approval.required_for` must exist and must be `function`,
  `set_field`, `set_task_status` or `subplaybook`.
- `subplaybook` recursion is forbidden; the validator walks the transitive
  closure and rejects self-reference (`IR-E-RECURSION`).

### 2.4 Implementation

`playbook/schema.py` defines these as `pydantic` v2 models. The JSON Schema is
emitted from the models (`model_json_schema()`) into `docs/playbook-ir.schema.json`
and published, so it can be used for editor completion and by external tooling.
A CI check fails if the committed schema drifts from the models.

`ir_version` is mandatory and validated. A file with an unknown `ir_version` is
rejected, never best-effort parsed.

---

## 3. Risk classification of an IR document

The validator computes, rather than trusts, the risk of a document:

```
effective_tier(playbook) = max over steps of:
    step.type base tier
    ∪ action_policy.classify(step.function)     for function steps
    ∪ effective_tier(subplaybook)               transitively
```

- If `risk.max_tier` in the document is **lower** than computed, that is a hard
  validation failure (`IR-E-RISK-UNDERSTATED`) — this is the check that catches
  a model quietly declaring a containment playbook as Tier 1.
- If any step classifies as `destructive: true` and it is not listed in
  `approval.required_for`, that is a failure (`IR-E-UNGATED-DESTRUCTIVE`).
- If any function is unknown to `action_policy`, the whole document is Tier 5
  and **cannot be compiled**, only validated and simulated.

---

## 4. Round-tripping

`decompiler.py` converts a SOAR playbook export back into IR for diffing.
It is explicitly **partial**. Output carries:

```yaml
_decompiled:
  source: "playbook:suspicious_powershell_response@v7"
  fidelity: partial
  unrepresentable:
    - "node 4a2f: inline pre-process script (12 lines)"
    - "node 7c1e: layout coordinates discarded"
    - "loop construct between nodes 9a/9b"
```

`soar_diff_playbook` must display `unrepresentable` prominently. A diff that
looks clean but omits an inline script is worse than no diff at all — so if
`unrepresentable` contains anything of category `script` or `loop`, the diff is
marked `REVIEW_UNSAFE` and the approval broker refuses to accept it as evidence
for a modify-deploy of that playbook. Modifying a playbook that contains
constructs we cannot read is not supported; create a new one instead.

---

## 5. Worked example: the brief's YAML, normalised

The example in the brief is valid intent but underspecified for compilation.
Concretely, it omits: message destinations, function input schemas, how
`enrichment.reputation_score` gets from the function result into the condition,
and the DAG edges. The normalised form in §2 makes each of those explicit.

This is the useful property of the IR: **the gaps are visible before anything
touches SOAR.** `soar_validate_playbook` on the brief's version returns:

```json
{
  "valid": false,
  "errors": [
    {"code":"IR-E-MISSING-MD","step":"enrich_ip",
     "message":"function 'threat_intelligence_lookup' requires message_destination; none given",
     "hint":"soar_list_message_destinations"},
    {"code":"IR-E-UNRESOLVED-REF","step":"decision",
     "message":"'enrichment.reputation_score' is not a known reference root",
     "hint":"declare outputs on step 'enrich_ip' and reference steps.enrich_ip.<name>"},
    {"code":"IR-E-NO-EDGES","step":"isolate",
     "message":"'condition: decision.true' given but no 'after' edge to 'decision'"},
    {"code":"IR-E-UNKNOWN-FUNCTION","step":"isolate",
     "message":"'edr_isolate_endpoint' not found in installed functions",
     "hint":"soar_list_functions"}
  ],
  "warnings": [
    {"code":"IR-W-NO-TIMEOUT","step":"enrich_ip",
     "message":"no timeout_seconds; will use SOAR default"}
  ],
  "computed_risk": {"max_tier": 5, "reason": "unknown functions classify as Tier 5"}
}
```

Structured, machine-readable errors with `hint` fields naming the discovery tool
to call next — this is what lets Claude iterate to a valid document without a
human in the loop, while a human stays in the loop for deployment.
