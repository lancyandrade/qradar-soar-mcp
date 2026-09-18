# 01 — Target Architecture

## 1. Design principles

1. **Deny by default.** Every capability is off until explicitly enabled. A
   missing config value means *no*, never *yes*.
2. **The model proposes, the platform disposes.** Claude never emits SOAR-native
   payloads for automation. It emits IR. Only the compiler emits SOAR objects.
3. **Generation and deployment are different verbs.** Authoring a playbook must
   be safe enough to do freely; deploying it must be hard enough to require a
   human.
4. **One chokepoint.** Every mutating call passes through a single
   `security.enforce()` gate. If a code path can mutate SOAR without going
   through it, that is a bug of the same class as a missing auth check.
5. **Not a REST proxy.** Tools are analyst-shaped, not endpoint-shaped. One tool
   may make three REST calls and return a projection. This is deliberate — a
   150-field DTO dumped into context is worse than useless.
6. **Lossy is fine; silently lossy is not.** IR→SOAR compilation cannot express
   everything SOAR can do. The compiler must *refuse* what it cannot represent
   rather than approximate it.

---

## 2. System context

```text
┌──────────────────────────┐
│ Claude Desktop / Code    │   (primary — stdio, local trust boundary)
└───────────┬──────────────┘
            │ MCP over stdio
┌───────────▼──────────────────────────────────────────────┐
│  qradar-soar-mcp                                          │
│                                                           │
│  tools/  ──►  security/  ──►  client/  ──►  SOAR REST     │
│                  │                                        │
│                  ├─ permissions   (tier gate)             │
│                  ├─ action_policy (per-action classify)   │
│                  ├─ approvals     (confirmation broker)   │
│                  └─ audit         (hash-chained JSONL)    │
│                                                           │
│  playbook/  IR ─► validate ─► simulate ─► diff ─► compile │
└───────────┬───────────────────────────────────────────────┘
            │ HTTPS + API key (Basic)
┌───────────▼──────────────┐
│ QRadar SOAR              │  soar.example.internal, org 201
└───────────┬──────────────┘
            │ message destinations
┌───────────▼──────────────┐
│ AppHost                  │  apphost.example.internal, resilient-circuits function apps
└───────────┬──────────────┘
            │
┌───────────▼──────────────────────────────────────────────┐
│ EDR · Firewall · IAM · Email security · Ticketing         │
└───────────────────────────────────────────────────────────┘
```

**The blast radius is the bottom row, not the SOAR box.** `soar_invoke_action`
looks like a SOAR API call and is in fact a remote-code trigger on the AppHost.
The security model is designed around that fact.

### 2.1 Transport posture

| Transport | Status | Requirements |
|---|---|---|
| **stdio** | Primary | Process-local. Trust = whoever runs the process. |
| **streamable-http** | Secondary, discouraged | Must refuse to start unless: TLS terminating proxy configured, `SOAR_HTTP_AUTH_TOKEN` set, bind address not `0.0.0.0` without explicit `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE=true`. Tier ≥ 3 capabilities **hard-disabled** over HTTP regardless of config. |

---

## 3. Package layout

Matches the brief, with additions marked ✚.

```text
src/qradar_soar_mcp/
├── server.py              # transport, tool registration, lifespan
├── config.py           ✚  # pydantic-settings; typed, validated, frozen
├── auth.py                # credential resolution + redaction primitives
├── errors.py           ✚  # SoarError hierarchy, sanitised for tool output
├── logging.py          ✚  # structured logging + redaction filter
│
├── client/
│   ├── base.py         ✚  # SoarClient core: request, apply_patch, ping
│   ├── incidents.py
│   ├── tasks.py
│   ├── artifacts.py
│   ├── comments.py
│   ├── attachments.py
│   ├── actions.py
│   ├── org.py          ✚  # types, fields, phases, users, datatables
│   └── playbooks.py       # playbooks, workflows, scripts, functions, rules
│
├── tools/
│   ├── registry.py     ✚  # @soar_tool decorator: binds tier + policy
│   ├── incidents.py
│   ├── investigation.py
│   ├── actions.py
│   ├── discovery.py    ✚  # Phase 2 read-only config discovery
│   └── playbooks.py
│
├── playbook/
│   ├── schema.py          # pydantic IR models + JSON Schema emitter
│   ├── generator.py       # NL-assist scaffolding / templates
│   ├── validator.py       # static + live-catalog validation
│   ├── simulator.py       # offline deterministic execution
│   ├── compiler.py        # IR → SOAR export bundle
│   ├── decompiler.py   ✚  # SOAR export → IR (for diff & round-trip)
│   └── diff.py
│
├── security/
│   ├── tiers.py        ✚  # Tier enum + capability→tier mapping
│   ├── permissions.py     # capability flag evaluation
│   ├── action_policy.py   # YAML policy: action/function → tier, allow/deny
│   ├── approvals.py       # confirmation tokens + out-of-band broker
│   └── audit.py           # append-only hash-chained audit log
│
└── catalog/            ✚
    ├── cache.py           # TTL cache of the live SOAR object catalog
    └── models.py          # normalised Function/Script/Field/Type records
```

### 3.1 Why `catalog/` is separate

The validator, simulator and compiler all need the same question answered:
*"does this function/field/datatable/message-destination exist, and what are
its inputs?"* Fetching that per-call is slow and hammers SOAR. Caching it
inside the validator makes the simulator depend on the validator. A separate,
explicitly-refreshable catalog keeps those three components independent and
makes `soar_validate_playbook` testable offline against a frozen catalog
fixture.

### 3.2 Why `decompiler.py` is not in the brief but is needed

`soar_diff_playbook` has to compare *a proposed IR* against *what is actually
in SOAR*. SOAR does not store IR. So either you diff IR-vs-compiled-export
(noisy — layout, UUIDs, ordering) or you normalise the SOAR side back into IR
and diff IR-vs-IR (semantic, reviewable). The second is the only one a human
can meaningfully approve. Decompilation is necessarily partial; constructs it
cannot represent are surfaced as `unrepresentable: [...]` in the diff rather
than dropped.

---

## 4. Request lifecycle

Every tool call follows the same path. No exceptions.

```text
 1. MCP tool invoked
 2. registry: look up declared tier + capability for this tool
 3. config: is the capability flag enabled?              ─┐
 4. action_policy: classify concrete target               │  security.enforce()
    (this action_id / this function / this field)         │
 5. tier gate: effective_tier ≤ max_enabled_tier?         │
 6. transport gate: tier ≥ 3 blocked over HTTP            │
 7. rate/bulk gate: within per-window and per-call caps   │
 8. approval: required? → token issued or verified       ─┘
 9. audit: write PENDING record (pre-image captured)
10. client: execute REST call(s)
11. audit: write COMMITTED / FAILED record + post-image
12. redact + project response
13. return to Claude
```

Steps 2–8 are pure functions of `(tool, args, config, policy)` — which makes
the entire permission matrix table-testable with no network. That property is
the point of the design; see `07-TEST-STRATEGY.md §3`.

---

## 5. Playbook lifecycle

```text
Natural language
   └─► Claude drafts ─────────────► Playbook IR (YAML)      [no SOAR contact]
          │
          ├─► soar_validate_playbook ──► catalog checks, schema, risk classify
          │        └─ FAIL ─► structured errors ─► Claude revises (loop)
          │
          ├─► soar_simulate_playbook ──► offline trace over synthetic or real
          │                              historical incident, side-effect free
          │
          ├─► soar_diff_playbook ──────► IR vs decompiled live playbook
          │
          ├─► HUMAN APPROVAL ══════════ out-of-band by default
          │
          ├─► soar_export_playbook ────► compile IR → .res/.resz bundle on disk
          │                              (still no SOAR mutation)
          │
          ├─► soar_import_playbook ────► two-phase config import, DISABLED state
          │
          └─► soar_enable_playbook ────► separate capability, separate approval
```

**Hard invariants, enforced in code and asserted in tests:**

- `soar_import_playbook` **always** imports in a disabled/inactive state,
  regardless of what the IR says. Enablement is only ever `soar_enable_playbook`.
- `soar_export_playbook` writes to a configured output directory and **never**
  contacts SOAR's import endpoints.
- `soar_validate_playbook` and `soar_simulate_playbook` are Tier 0 — they only
  read the catalog. They must be freely usable, or the model will skip them.
- Every import is preceded by an automatic **full configuration export snapshot**
  to `SOAR_SNAPSHOT_DIR`, because SOAR config imports are not transactional and
  there is no rollback API. See `05-SOAR-API-SURFACE.md §6`.

---

## 6. Two-server posture (recommended deployment)

Because Tier 0–1 is genuinely low-risk and Tier 3+ is genuinely dangerous, the
recommended production deployment is **two processes with two SOAR API keys**:

| Instance | SOAR key permission set | Enabled tiers | Registered in Claude as |
|---|---|---|---|
| `qradar-soar` | read-only | 0–1 | always on |
| `qradar-soar-ops` | read + write + invoke | 0–3 | enabled deliberately, per-engagement |

This puts a real permission boundary in SOAR itself behind the software one.
If `permissions.py` has a bug, the read-only key still cannot close an incident.
Defence in depth against our own code is the correct posture for a project
whose whole job is letting an LLM touch a security platform.

`config.py` should refuse to start if enabled tiers exceed what the API key
can actually do — probe at startup and fail loudly rather than at 03:00.

---

## 7. Phase 6 note: cross-platform QRadar SIEM + SOAR

Out of scope for detailed design here, but the architecture must not preclude
it. Requirement: this server does **not** absorb SIEM functionality. The
existing QRadar SIEM MCP server stays separate; correlation happens in Claude's
context across two servers. The only accommodation needed is that
`soar_get_incident` should surface the QRadar offense linkage fields
(`properties.qradar_id` / the offense-id custom field used by the QRadar
integration — **name is deployment-specific, discover via
`soar_describe_incident_fields`**) so Claude can pivot between servers.
