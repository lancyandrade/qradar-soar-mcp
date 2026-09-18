# 02 — Security, Permission and Approval Model

## 1. Risk tiers

| Tier | Name | Reversible? | Blast radius | Examples |
|---|---|---|---|---|
| **0** | Read | n/a | None | read incidents, artifacts, tasks, playbooks, validate, simulate |
| **1** | Documentation | Trivially | SOAR record only | add comment, add artifact, add investigation notes |
| **2** | SOAR modification | Yes, with effort | SOAR state, analyst workflow | create incident, reassign, change severity, modify fields, task status, close |
| **3** | Security control action | Often **not** | Production infrastructure | block IP, disable user, isolate endpoint, reset password, quarantine email |
| **4** | Automation modification | Yes, but latent | Future incidents, unattended | create/modify playbook, enable/disable playbook, modify scripts or rules |
| **5** | High-risk automation | **No** | Enterprise-wide, unattended | bulk block/disable, arbitrary script execution, AppHost code changes, app installation, destructive automation |

### 1.1 The tier-3 asymmetry

Tier 3 is the sharpest edge and it is easy to under-rate because *the API call
itself is small*. `POST /incidents/{id}/action_invocations {"action_id": 47}` is
one line. What it does is run a `resilient-circuits` function on the AppHost
that may call a firewall API and drop a /24.

Consequences for the design:

- **Tier is a property of the target, not the tool.** `soar_invoke_action` is
  not "a Tier 3 tool" — it is a tool whose tier is determined by *which action*.
  Invoking "Send Analyst Digest Email" is Tier 1. Invoking "Isolate Endpoint"
  is Tier 3. `action_policy.py` resolves this per call.
- **Unknown ⇒ maximum.** An action not present in the policy file is classified
  `Tier 5 / DENY`, not "probably fine". Operators must explicitly classify
  every action they want reachable. This is annoying by design.

### 1.2 Tier 5 is not a permission level

Tier 5 has no enabling flag. There is deliberately no
`SOAR_ALLOW_TIER5=true`. The following are **architectural non-goals** and must
not be implemented as tools at all:

- Arbitrary Python execution in SOAR scripts
- AppHost / Integration Server code modification or app installation
- Unbounded bulk mutation (see §5 caps)
- Deletion of playbooks, rules, workflows, incidents, or configuration

If an operator needs these, they use the SOAR UI or `resilient-sdk` as a human.
"We built a safe way for the model to do it" is not a claim this project should
make.

---

## 2. Capability flags

Deny by default. Absent, empty, or unparseable ⇒ `false`.

```bash
# ── Tier 1 ───────────────────────────────────────────────
SOAR_ALLOW_COMMENTS=false            # add comment / notes
SOAR_ALLOW_ARTIFACTS=false           # add artifact

# ── Tier 2 ───────────────────────────────────────────────
SOAR_ALLOW_INCIDENT_WRITES=false     # create/update/assign/severity/fields
SOAR_ALLOW_TASK_WRITES=false         # task status
SOAR_ALLOW_INCIDENT_CLOSE=false      # separate: closing is workflow-visible

# ── Tier 3 ───────────────────────────────────────────────
SOAR_ALLOW_ACTIONS=false             # invoke manual actions at all
SOAR_ALLOW_DESTRUCTIVE_ACTIONS=false # actions classified destructive in policy
SOAR_ACTION_POLICY_FILE=./config/action_policy.yaml   # REQUIRED if ACTIONS=true

# ── Tier 4 ───────────────────────────────────────────────
SOAR_ALLOW_PLAYBOOK_DRAFT=true       # IR authoring — local only, safe
SOAR_ALLOW_PLAYBOOK_EXPORT=false     # compile to file on disk
SOAR_ALLOW_PLAYBOOK_CREATE=false     # import into SOAR (always disabled state)
SOAR_ALLOW_PLAYBOOK_MODIFY=false     # import over an existing playbook
SOAR_ALLOW_PLAYBOOK_DEPLOY=false     # alias for CREATE|MODIFY reaching SOAR
SOAR_ALLOW_PLAYBOOK_ENABLE=false     # activate a playbook
SOAR_ALLOW_SCRIPT_WRITES=false       # not implemented in v1; reserved, must stay false

# ── Approval ─────────────────────────────────────────────
SOAR_APPROVAL_MODE=out_of_band       # out_of_band | in_band | disabled
SOAR_REQUIRE_ACTION_CONFIRMATION=true
SOAR_REQUIRE_PLAYBOOK_CONFIRMATION=true
SOAR_APPROVAL_BROKER_PATH=/var/lib/qradar-soar-mcp/approvals
SOAR_APPROVAL_TTL_SECONDS=900

# ── Blast-radius caps ────────────────────────────────────
SOAR_MAX_MUTATIONS_PER_CALL=1
SOAR_MAX_TIER2_PER_HOUR=25
SOAR_MAX_TIER3_PER_HOUR=5
SOAR_MAX_RESULTS=50

# ── Audit & safety ───────────────────────────────────────
SOAR_AUDIT_LOG_PATH=/var/log/qradar-soar-mcp/audit.jsonl
SOAR_AUDIT_REQUIRED=true             # refuse to start if audit log unwritable
SOAR_SNAPSHOT_DIR=/var/lib/qradar-soar-mcp/snapshots
SOAR_KILL_SWITCH_FILE=/etc/qradar-soar-mcp/HALT   # exists ⇒ all tiers ≥1 deny

# ── Transport ────────────────────────────────────────────
SOAR_MCP_TRANSPORT=stdio
SOAR_HTTP_AUTH_TOKEN=
SOAR_HTTP_ACKNOWLEDGE_EXPOSURE=false
```

### 2.1 Migration from `SOAR_ALLOW_WRITES`

The legacy flag is honoured for one minor version with a loud deprecation:

| Legacy | Maps to |
|---|---|
| `SOAR_ALLOW_WRITES=true` | `COMMENTS`, `ARTIFACTS`, `INCIDENT_WRITES`, `TASK_WRITES`, `INCIDENT_CLOSE` = true |
| | `SOAR_ALLOW_ACTIONS` = **false** |

The mapping deliberately **drops** action invocation. Anyone who set
`SOAR_ALLOW_WRITES=true` almost certainly did not intend to authorise endpoint
isolation, and a silent upgrade that preserved that would be the worst possible
outcome. The startup log states this explicitly. The flag is removed in the
following minor version.

---

## 3. Action policy file

`action_policy.yaml` is the operator's classification of their own environment.
It is the only place a Tier 3 action becomes reachable.

```yaml
version: 1

# Matched in order; first match wins. Unmatched ⇒ deny at Tier 5.
default:
  tier: 5
  decision: deny

actions:
  - match: { name: "Send Analyst Digest" }
    tier: 1
    decision: allow

  - match: { name: "Enrich Artifact with Threat Intel" }
    tier: 1
    decision: allow
    reason: "Read-only enrichment; no downstream mutation"

  - match: { name_regex: "^Escalate to .*" }
    tier: 2
    decision: allow

  - match: { name: "Firewall — Block IP" }
    tier: 3
    decision: require_approval
    destructive: true
    constraints:
      artifact_types: [ "IP Address" ]
      deny_values:                     # never let the model block these
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "<your egress ranges>"
        - "<your DC subnets>"

  - match: { name: "EDR — Isolate Endpoint" }
    tier: 3
    decision: require_approval
    destructive: true
    constraints:
      deny_values: [ "<domain controller hostnames>", "<hypervisor hosts>" ]

  - match: { name_regex: ".*(Delete|Purge|Wipe|Disable All).*" }
    tier: 5
    decision: deny
    reason: "Bulk/destructive verbs are never model-reachable"
```

**`deny_values` is the control that matters most.** Tier gating stops the model
from acting *at all*; `deny_values` stops the plausible-but-catastrophic action
— blocking your own egress IP because it appeared in a proxy log artifact, or
isolating a domain controller because it was the destination of lateral
movement. Every deployment should populate these before enabling Tier 3.

Policy file is validated at startup against a JSON Schema; a malformed policy
is a **startup failure**, not a warning, and never falls back to permissive.

---

## 4. Approval model

### 4.1 The honest limitation of in-band confirmation

A common pattern is: tool returns `confirmation_token: abc123`, model calls
again with the token, execution proceeds.

**This does not constitute human approval.** The model can read the token from
its own context and echo it back unprompted. In-band confirmation prevents
*accidental* execution and creates an audit artifact. It does not prevent a
confused, jailbroken, or prompt-injected model from proceeding. Prompt
injection is a live concern here specifically: incident artifacts, comments and
attachment filenames are attacker-influenced text that lands in Claude's
context. An attacker who can file a phishing report can write text into the
data the model reads.

Therefore:

| Mode | Mechanism | Real guarantee |
|---|---|---|
| `disabled` | none | Nothing. Lab only. |
| `in_band` | token echoed by model | Prevents accidents. **Does not prevent misuse.** |
| `out_of_band` | token approved by a human via a channel the model cannot reach | Actual human control |

`out_of_band` is the **default** and is mandatory for Tier 3 and Tier 4 in any
non-lab deployment. The config validator refuses to start if
`SOAR_ALLOW_ACTIONS=true` with `SOAR_APPROVAL_MODE=in_band` unless
`SOAR_LAB_MODE=true` is also set.

### 4.2 Out-of-band broker

Deliberately simple, no new infrastructure:

1. Tool call reaches an approval-required decision.
2. Server writes `{approval_id}.request.json` to `SOAR_APPROVAL_BROKER_PATH`
   containing: tool, tier, resolved action name, target incident/artifact,
   full rendered "what will happen" plan, argument hash, expiry.
3. Tool returns immediately to Claude: *"Approval requested. Reference
   `APR-2026-0714-a83f`. A human must approve this out of band. Do not retry;
   call `soar_check_approval` to poll."*
4. A human runs `qradar-soar-approve APR-2026-0714-a83f` (a separate CLI
   entry point in the same package, or a Slack/ticket integration writing the
   same file format). The CLI **prints the full plan and requires typing the
   reference back**.
5. Approval writes `{approval_id}.approved.json`, signed with an HMAC over the
   argument hash using `SOAR_APPROVAL_HMAC_KEY` — a key the MCP process can
   verify but, being in a separate file readable only by the approver's
   account, cannot forge under the recommended file permissions.
6. `soar_check_approval` / the retried tool call verifies HMAC + argument hash
   + TTL, then executes exactly once. The token is consumed atomically
   (rename-based lock) so a replay is impossible.

The argument hash binding is essential: approval is for *this action on this
target*, not a general licence. Changing one argument invalidates it.

### 4.3 Playbook approval is stricter

Playbook deploy/enable approval requests must embed the **full semantic diff**
(`soar_diff_playbook` output) and the **simulation trace**, not just the
playbook name. A human approving "deploy playbook Suspicious PowerShell
Response" without seeing that step 4 calls `EDR — Isolate Endpoint` on every
match is rubber-stamping. The broker refuses to write a playbook approval
request that lacks a diff and a simulation reference.

---

## 5. Blast-radius caps

| Control | Default | Rationale |
|---|---|---|
| `SOAR_MAX_MUTATIONS_PER_CALL` | 1 | No tool may mutate more than one object per invocation. Bulk operations are a Tier 5 non-goal. |
| `SOAR_MAX_TIER3_PER_HOUR` | 5 | Converts a runaway loop from a mass-blocking event into five incidents and an alert. |
| Sliding-window counters | in-memory + persisted to audit log | Survives restart; a restart must not reset the budget. |
| Circuit breaker | 3 consecutive Tier ≥2 failures ⇒ Tier ≥2 disabled for the process lifetime | Repeated failures usually mean the model has the wrong mental model of the environment. |
| Kill switch | file presence check before every Tier ≥1 op | An operator with shell access can stop all mutation in one second without restarting anything. |

---

## 6. Audit log

Append-only JSONL, one record per security decision **and** per mutation
attempt — including denials, which are the interesting ones.

```json
{
  "seq": 1834,
  "ts": "2026-07-29T11:42:07.221Z",
  "prev_hash": "sha256:9f1c…",
  "hash": "sha256:2b7e…",
  "event": "MUTATION_COMMITTED",
  "tool": "soar_invoke_action",
  "tier": 3,
  "capability": "SOAR_ALLOW_DESTRUCTIVE_ACTIONS",
  "decision": "allow",
  "policy_rule": "Firewall — Block IP",
  "approval_id": "APR-2026-0714-a83f",
  "approver": "j.rossi@example.com",
  "target": { "incident_id": 2317, "action_id": 47, "action_name": "Firewall — Block IP" },
  "arguments_hash": "sha256:c0ff…",
  "pre_image": { "…": "…" },
  "post_image": { "…": "…" },
  "soar_response": { "success": true },
  "duration_ms": 412,
  "transport": "stdio",
  "server_version": "0.2.0"
}
```

Requirements:

- **Hash chain** (`prev_hash` → `hash`) so tampering is detectable. Not
  tamper-*proof* — a root-level attacker can rewrite the chain — but it defeats
  selective deletion, which is the realistic threat.
- **Pre-image capture** before every mutation. `apply_patch()` already fetches
  the current DTO; that fetch becomes the audit pre-image at zero extra cost.
  This is what makes manual rollback possible.
- **Denials logged at the same fidelity as successes.** A burst of `DENIED`
  Tier-3 records is the signal that something has gone wrong upstream.
- **`SOAR_AUDIT_REQUIRED=true` ⇒ unwritable audit log is a startup failure**,
  and a mid-session write failure fails the mutation closed.
- Audit records are **never** returned in MCP tool output.

---

## 7. Secret handling

| Control | Implementation |
|---|---|
| `.gitignore` covering `.env`, `*.pem`, `*.key`, `*.resz`, `snapshots/`, `approvals/`, `*.jsonl` | `P1-00` — first commit |
| `.env.example` contains placeholders only, and defaults `SOAR_VERIFY_SSL=true` | `P1-02` |
| Secrets held in a `SecretStr`; `__repr__`/`__str__` render `***` | `P1-03` |
| Redaction filter on the logging handler, applied to message *and* args, matching the live secret value and `Authorization`/`Basic` patterns | `P1-09` |
| `errors.py`: `SoarError` carries a `safe_message` for tool output and a `detail` for the log only. `httpx` exceptions are **never** propagated raw — their `request` object carries headers. | `P1-03` |
| `gitleaks` / `detect-secrets` in pre-commit **and** CI | `P1-12` |
| Startup self-test: assert the secret does not appear in the rendered config repr | `P1-03` |

**A specific bug to avoid:** the current code raises `SoarError` with messages
built from `httpx` responses. `httpx.HTTPStatusError.__str__` includes the
request URL, and some SOAR error bodies echo request context. Every error path
must go through a sanitiser before reaching MCP output, and there must be a
test that injects a known secret value and asserts it appears in no tool
response and no log line.

---

## 8. Threat model summary

| Threat | Control |
|---|---|
| Model hallucinates an action_id and blocks the wrong thing | Policy `constraints` + `deny_values` + approval + pre-image audit |
| Prompt injection via incident artifact/comment/filename text | Out-of-band approval for Tier ≥3; artifacts rendered as untrusted data in tool output; caps limit damage before a human notices |
| Runaway agent loop | Per-hour caps, circuit breaker, kill switch |
| Secret exfiltration through tool output | Error sanitisation, redaction filter, CI secret scan, `SecretStr` |
| Accidental public commit of `.env` | `.gitignore` first, pre-commit hook, CI gate, documented key-rotation runbook |
| HTTP transport exposed without auth | Refuse to start without token; Tier ≥3 hard-disabled over HTTP |
| Playbook deployed with hidden destructive step | Diff + simulation mandatory in approval payload; import always disabled; enable is a separate capability + approval |
| Import corrupts SOAR configuration | Mandatory pre-import full-config snapshot; documented manual restore runbook (no rollback API exists) |
| Our own permission bug | Two-instance deployment with a read-only SOAR API key on the default instance |
