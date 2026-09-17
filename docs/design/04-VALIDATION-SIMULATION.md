# 04 — Validation and Simulation Architecture

## 1. The object catalog

Validation, simulation and compilation all answer questions about the live SOAR
environment. `catalog/` owns that.

```python
@dataclass(frozen=True)
class Catalog:
    fetched_at: datetime
    soar_version: str
    org_id: str
    functions: dict[str, FunctionSpec]          # api_name -> spec
    scripts: dict[str, ScriptSpec]
    message_destinations: dict[str, MDSpec]
    incident_types: dict[str, TypeSpec]
    phases: dict[str, PhaseSpec]
    fields: dict[str, FieldSpec]                # "incident.severity_code", "artifact.type", ...
    datatables: dict[str, DataTableSpec]
    playbooks: dict[str, PlaybookSummary]
    rules: dict[str, RuleSpec]
    workflows: dict[str, WorkflowSummary]
    groups: dict[str, GroupSpec]
    api_key_permissions: frozenset[str]
    installed_apps: dict[str, str]              # app -> version
```

- Populated by the Phase-2 discovery client methods.
- TTL-cached (`SOAR_CATALOG_TTL_SECONDS`, default 300); explicit
  `soar_refresh_catalog` tool for when an operator has just installed an app.
- **Serialisable to and from JSON.** This is what makes the whole validator
  testable offline: CI runs against `tests/fixtures/catalog/lab-v51.json`, a
  sanitised snapshot of the real lab.
- Never contains secrets; the snapshot tool strips API keys and any
  `password`-typed function input defaults.

---

## 2. Validation

`soar_validate_playbook(ir_yaml) -> ValidationReport` — **Tier 0**. It reads the
catalog and nothing else. It must be free to call, or the model will skip it.

### 2.1 Layers

| Layer | Runs | Checks |
|---|---|---|
| **L1 Schema** | offline | `ir_version` known; pydantic model parse; closed step-type set; closed operator set; no unknown keys (`extra="forbid"`) |
| **L2 Structural** | offline | DAG acyclicity; reachability; `when` references a `condition` in `after`; `approval.required_for` targets exist; no `subplaybook` recursion; regex safety; wait bounds |
| **L3 Reference** | catalog | functions exist; scripts exist; message destinations exist **and are the ones the function is bound to**; fields exist and are of a compatible type; incident types exist; datatables exist; phases exist; approver group exists |
| **L4 Contract** | catalog | every required function input is supplied; supplied inputs exist on the function; value types match the input's declared type; `outputs` JSONPaths are syntactically valid |
| **L5 Environment** | catalog | apps providing the referenced functions are installed and their version satisfies any constraint; `min_soar_version` ≤ actual; API key has the permissions the eventual import will need |
| **L6 Risk** | policy | recompute effective tier; declared ≥ computed; destructive steps gated; unknown functions ⇒ Tier 5 ⇒ non-compilable |
| **L7 Compilability** | compiler | dry compile to an in-memory bundle; any construct the compiler cannot represent is an error here, not a surprise at export time |

Layers run in order and **short-circuit at the first layer producing errors** —
reporting L4 contract errors for a document with a cycle is noise. Warnings from
earlier layers are always carried through.

### 2.2 Report shape

```json
{
  "valid": false,
  "ir_version": 1,
  "playbook": "suspicious_powershell_response",
  "layer_reached": "L3",
  "errors":   [ {"code":"…","step":"…","message":"…","hint":"…","path":"steps[3].function"} ],
  "warnings": [ … ],
  "computed_risk": { "max_tier": 3, "destructive": true,
                     "destructive_steps": ["isolate","block"] },
  "catalog": { "fetched_at": "…", "soar_version": "51.0.0", "stale": false },
  "required_capabilities": ["SOAR_ALLOW_PLAYBOOK_CREATE","SOAR_ALLOW_PLAYBOOK_ENABLE"],
  "next_step": "soar_simulate_playbook"
}
```

Error codes are stable, namespaced (`IR-E-*`, `IR-W-*`) and documented in
`docs/error-codes.md`. Stability matters: they end up in prompts, tests and
user runbooks.

---

## 3. Simulation

`soar_simulate_playbook(ir_yaml, scenario) -> SimulationTrace` — **Tier 0**.

### 3.1 What it is not

**QRadar SOAR has no dry-run, what-if, or sandbox-execution API.** There is no
supported way to ask SOAR "what would this playbook do?" without running it.
Any claim to the contrary in this project would be inventing an API.

So simulation is **an offline interpreter of the IR written by us**. It runs the
IR graph in-process. It reads real data (via catalog and, optionally, a real
historical incident) but **executes nothing**: function calls are resolved
against mocks, never dispatched to a message destination.

This has to be stated plainly in tool output, because a model — and a human
reading the model's summary — will otherwise treat a green simulation as proof
the playbook works. It is proof of *logical* soundness only. Add to every
trace:

```json
"disclaimer": "Offline simulation. No SOAR execution occurred. Function results are mocked; real behaviour depends on AppHost function implementations not visible to this server."
```

### 3.2 Scenario sources

| Mode | Input | Use |
|---|---|---|
| `synthetic` | inline JSON incident + artifacts | Fast, deterministic, CI |
| `historical` | `incident_id` — fetched read-only | "Would this have handled incident 2317 correctly?" — the highest-value mode |
| `historical_batch` | search filter, capped at `SOAR_SIM_MAX_INCIDENTS` (default 25) | Coverage: how many of the last 25 malware incidents would this have fired on, and how many would it have isolated? |

`historical_batch` is the one that actually earns confidence, and it directly
answers the brief's "review how similar incidents were handled previously".

### 3.3 Function mocking

Three strategies, in order of preference:

1. **Recorded** — if the function has been invoked on a real incident before,
   the historical result is available (see `05-SOAR-API-SURFACE.md §4.3 —
   REQUIRES VALIDATION` on retrieving function results from incident history).
   Most realistic.
2. **Schema-generated** — synthesise a result matching the function's declared
   output schema, if it declares one. Many community functions do not.
3. **Analyst-supplied** — the scenario supplies `mock_results` per step.

Where a mock is under-determined, the simulator **explores both branches** of
any downstream condition and reports both paths rather than picking one. A
trace showing "if reputation > 80 → isolates HOST-4471; else → closes as Not an
Issue" is far more useful for review than one arbitrary path.

### 3.4 Trace output

```json
{
  "scenario": {"mode":"historical","incident_id":2317},
  "triggered": true,
  "trigger_evaluation": [
    {"condition":"incident.incident_type_ids includes Malware","result":true,
     "actual":"['Malware','Phishing']"},
    {"condition":"artifact.value contains powershell.exe","result":true,
     "actual":"artifact 8821: 'powershell.exe -enc SQBFAFgA…'"}
  ],
  "paths": [
    {
      "branch": "decision.true  (reputation_score=94, mocked: recorded)",
      "probability_note": "recorded result from incident 2094",
      "steps": [
        {"id":"enrich_ip","type":"function","status":"mocked",
         "outputs":{"reputation_score":94}},
        {"id":"note_enrichment","type":"add_note","would_write":"Threat intel: known C2, 94/100"},
        {"id":"isolate","type":"function","status":"BLOCKED_PENDING_APPROVAL",
         "would_invoke":"fn_edr_isolate_endpoint",
         "would_send":{"hostname":"HOST-4471"},
         "risk":{"tier":3,"destructive":true},
         "policy":"require_approval"},
        {"id":"block","type":"function","status":"BLOCKED_PENDING_APPROVAL",
         "would_invoke":"fn_firewall_block_ip",
         "would_send":{"ip":"203.0.113.44"},
         "policy_check":"203.0.113.44 not in deny_values — would proceed"}
      ]
    },
    {"branch":"decision.false","steps":[{"id":"benign_close","would_set":{"incident.resolution_id":"Not an Issue"}}]}
  ],
  "summary": {
    "steps_evaluated": 6, "unreachable_steps": [], "destructive_effects": 2,
    "would_touch": ["HOST-4471 (EDR isolate)","203.0.113.44 (firewall block)"]
  },
  "disclaimer": "Offline simulation. No SOAR execution occurred. …"
}
```

The `would_touch` field is written for the human in the approval flow: it is the
one-line answer to *"what does this thing do to my network?"*

### 3.5 Determinism

The simulator must be deterministic given `(ir, scenario, catalog, mocks)`.
No wall-clock, no RNG, no ordering dependence on dict iteration. Time-dependent
constructs (`wait`) resolve against a scenario-supplied `now`. This makes
golden-file testing possible and makes two runs comparable in a diff.

---

## 4. Diff

`soar_diff_playbook(ir_yaml, target_playbook_api_name)` — **Tier 0**.

```
IR (proposed) ──────────────┐
                            ├──► normalise ──► semantic diff ──► report
SOAR export ──► decompile ──┘
```

Both sides are normalised before comparison: steps sorted topologically then by
id, defaults made explicit, references canonicalised, layout and UUIDs dropped.
Otherwise every diff is 90% noise.

Report categories:

| Category | Meaning | Approval impact |
|---|---|---|
| `added_steps` / `removed_steps` | structural change | shown |
| `changed_inputs` | function called with different data | shown |
| `risk_delta` | **tier increased, or a destructive step added** | **highlighted; requires explicit acknowledgement in the approval CLI** |
| `trigger_delta` | playbook now fires on more/fewer incidents | highlighted — scope expansion is the sneaky one |
| `approval_delta` | a step was removed from `approval.required_for` | highlighted, treated as risk increase |
| `unrepresentable` | decompiler could not read part of the live playbook | if non-empty and of category script/loop ⇒ diff marked `REVIEW_UNSAFE` |

A modify-deploy whose diff is `REVIEW_UNSAFE` is refused by the approval broker
(see `03-PLAYBOOK-IR.md §4`).

---

## 5. Why validation is Tier 0 and export is not

A frequent design error is gating the safe steps. If validation or simulation
required a capability flag, the model — under instruction to produce a working
playbook — would route around them and hand a human an unvalidated document.

So: **authoring, validation, simulation and diff are free. Everything that
produces a file or touches SOAR is gated.** The gradient runs the right way:
the cheapest path to a result for the model is also the safest one for the
operator.
