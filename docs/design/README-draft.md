# qradar-soar-mcp

An MCP server that connects Claude to IBM QRadar SOAR (formerly Resilient) for
incident investigation, controlled response actions, and — behind explicit human
approval — playbook authoring and deployment.

> ### ⚠️ Read this before you enable anything
>
> This project lets a language model operate a security orchestration platform.
> Some of its capabilities can, if enabled, reach through SOAR to your EDR,
> firewall and identity provider. Endpoint isolation and IP blocking are not
> reversible with a button.
>
> **Everything except reading is disabled by default and stays disabled until
> you deliberately turn it on, per capability.** Read `docs/threat-model.md`
> before setting any flag above Tier 1. If you are looking for a quick way to
> let Claude "just fix things" in SOAR, this is not that project, on purpose.

---

## What it does

**Investigate** — search and read incidents, artifacts, tasks, comments,
attachment metadata, users, custom field definitions, and historical response
patterns.

**Respond** — add comments and artifacts, assign, update fields, change task
status, close incidents, and invoke pre-classified manual actions. Each is a
separate capability with its own risk tier.

**Author playbooks** *(Phases 3–5, in progress)* — draft a playbook as a
validated intermediate representation, check it against your live SOAR object
catalog, simulate it against historical incidents, diff it against what is
already deployed, and — only after out-of-band human approval — compile, import
(disabled), and separately enable it.

---

## Risk tiers

| Tier | Scope | Default | Flags |
|---|---|---|---|
| 0 | Read, validate, simulate | **on** | — |
| 1 | Comments, artifacts, notes | off | `SOAR_ALLOW_COMMENTS`, `SOAR_ALLOW_ARTIFACTS` |
| 2 | Incident/task modification, close | off | `SOAR_ALLOW_INCIDENT_WRITES`, `SOAR_ALLOW_TASK_WRITES`, `SOAR_ALLOW_INCIDENT_CLOSE` |
| 3 | Security control actions (block, isolate, disable, reset, quarantine) | off | `SOAR_ALLOW_ACTIONS`, `SOAR_ALLOW_DESTRUCTIVE_ACTIONS` + a policy file |
| 4 | Playbook create/modify/deploy/enable | off | `SOAR_ALLOW_PLAYBOOK_*` |
| 5 | Bulk destructive, arbitrary code, AppHost changes | **not implemented, by design** | none — there is no flag |

Tier 5 has no enabling flag and never will. Arbitrary script execution, AppHost
code modification, app installation, bulk mutation and deletion of automation
are architectural non-goals. Use the SOAR UI as a human for those.

**A Tier-3 action's tier is a property of the action, not the tool.** Invoking
"Send Analyst Digest" is Tier 1; invoking "EDR — Isolate Endpoint" is Tier 3.
You classify your own environment in `action_policy.yaml`. Anything you have not
classified is denied.

---

## Quick start (read-only)

```bash
git clone https://github.com/<you>/qradar-soar-mcp && cd qradar-soar-mcp
uv venv && uv pip install -e .
cp .env.example .env          # fill in SOAR_API_KEY_ID / SOAR_API_KEY_SECRET
uv run qradar-soar-mcp --check
```

`--check` exercises the same `query_paged` endpoint the search tool uses, so a
green result means search actually works — not just that TLS handshook.

Create the API key in **Administrator Settings → API Keys**. Start with a
read-only permission set.

### Claude Desktop / Claude Code (stdio — recommended)

```json
{
  "mcpServers": {
    "qradar-soar": {
      "command": "uv",
      "args": ["--directory", "/opt/qradar-soar-mcp", "run", "qradar-soar-mcp"],
      "env": {
        "SOAR_BASE_URL": "https://soar.example.internal",
        "SOAR_ORG_ID": "201",
        "SOAR_API_KEY_ID": "...",
        "SOAR_API_KEY_SECRET": "...",
        "SOAR_VERIFY_SSL": "/etc/pki/ca-trust/source/anchors/soar-ca.pem"
      }
    }
  }
}
```

---

## Recommended deployment: two instances, two keys

| Instance | SOAR key | Tiers | When |
|---|---|---|---|
| `qradar-soar` | read-only permission set | 0–1 | always registered |
| `qradar-soar-ops` | read + write + invoke | 0–3 | registered deliberately, per engagement |

This puts a permission boundary **in SOAR** behind the one in this software. If
our permission code has a bug, the read-only key still cannot close an incident.
For a project whose job is letting an LLM touch a security platform, defending
against your own code is the correct posture.

The server probes its key's capabilities at startup and refuses to run if the
enabled tiers exceed what the key can actually do.

---

## Approval model

Set `SOAR_APPROVAL_MODE=out_of_band` (the default) for anything above Tier 2.

In-band confirmation — where the model receives a token and echoes it back —
**is not human approval**. The model can read the token from its own context.
It prevents accidents and creates an audit record; it does not prevent a
confused or prompt-injected model from proceeding. This matters here because
incident artifacts, comments and attachment filenames are attacker-influenced
text that lands in Claude's context: anyone who can file a phishing report can
write into the data the model reads.

Out-of-band approval works through a file broker the model cannot reach:

```bash
$ qradar-soar-approve APR-2026-0714-a83f
Tool:      soar_invoke_action     Tier 3  (destructive)
Action:    Firewall — Block IP
Target:    incident 2317, artifact 8821, value 203.0.113.44
Effect:    blocks 203.0.113.44 at the perimeter firewall
Requested: 2026-07-14 09:41:02Z   Expires: 09:56:02Z

Type the reference to approve, anything else to reject: _
```

Playbook approvals additionally require a semantic diff and a simulation trace
in the request; the broker refuses requests without them.

---

## Playbook lifecycle

```
natural language → Claude → Playbook IR (YAML)
                              ↓
                        validate  (Tier 0, free)
                              ↓
                        simulate  (Tier 0, free — offline, no SOAR execution)
                              ↓
                        diff      (Tier 0, free)
                              ↓
                    ══ human approval, out of band ══
                              ↓
                        export → import (always DISABLED) → enable (separate)
```

Authoring, validation, simulation and diffing are free so the model always takes
the safe path. Everything that writes a file or touches SOAR is gated.

**Simulation is our own offline interpreter.** QRadar SOAR has no dry-run API. A
green simulation proves the playbook's logic is sound; it does not prove the
AppHost functions it calls behave as expected. Every trace says so.

**Imports always land disabled**, regardless of what the IR says. Enabling is a
separate tool, a separate capability, and a separate approval.

---

## Security controls

| Control | Behaviour |
|---|---|
| Deny by default | Absent, empty or unparseable config ⇒ denied. Never permissive on error. |
| Unknown action ⇒ Tier 5 | Anything absent from `action_policy.yaml` is denied. |
| `deny_values` | Per-action value blocklists — your own egress ranges, DC subnets, hypervisors. The control that stops a plausible-but-catastrophic action. |
| Mutation cap | One object per tool call. Bulk operations are not implemented. |
| Rate limits | Default 5 Tier-3 operations/hour; counters survive restart. |
| Circuit breaker | 3 consecutive Tier ≥2 failures disables Tier ≥2 for the process. |
| Kill switch | `touch /etc/qradar-soar-mcp/HALT` stops all mutation immediately, no restart. |
| Audit log | Hash-chained append-only JSONL; pre- and post-images; denials logged too; `qradar-soar-audit verify`. |
| Fail closed | Unwritable audit log ⇒ refuse to start, and mid-session failure aborts the mutation. |
| Pre-import snapshot | Full config export before every import. SOAR imports have no rollback API. |
| Secret hygiene | `SecretStr`, log redaction, sanitised errors, CI secret scanning. |
| HTTP transport | Refuses to start without a bearer token; Tier ≥3 hard-disabled over HTTP regardless of config. |

### Reporting a vulnerability
See `SECURITY.md`. Please do not open a public issue for anything that could be
used against a live SOAR deployment.

---

## SOAR API behaviours this client handles

1. `handle_format=names` on every request — IDs become labels in both directions.
2. `text_content_output_format=always_text` — flattens rich-text fields.
3. **PATCH is optimistic concurrency, not a merge.** Requires `version` plus
   `old_value`/`new_value` per field; a `success: false` response is raised, not
   swallowed. Silently ignoring it is the classic way a SOAR integration appears
   to work while doing nothing.
4. Custom fields live under `properties.<name>`.
5. Listing uses `POST /incidents/query_paged`. Conditions inside one filter are
   ANDed; separate filters are ORed. Active `"A"`, closed `"C"`.
6. Closing needs `plan_status` + `resolution_id` + `resolution_summary` together
   and fails if any close-required custom field is empty.
7. Incident DTOs have 150+ fields; every read tool projects down to an
   analyst-relevant subset.

Endpoints used for playbook discovery and import are documented with verified
response shapes in `docs/soar-api-verified.md`. Anything not yet verified
against a real appliance is marked as such — this project does not guess at
undocumented APIs.

---

## Known limitations

- No dry-run: simulation is offline and approximate (see above).
- No rollback for configuration imports; restore is a documented manual runbook.
- Playbooks containing inline scripts or loops cannot be fully decompiled, so
  they cannot be safely modified through this server — create a new playbook
  instead.
- New SOAR functions cannot be created here; they come from installed app
  packages. Playbooks may only reference functions that already exist.
- Runtime correctness of a deployed playbook cannot be asserted by this project.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Investigation + controlled actions + security architecture | in progress |
| 2 | Playbook/rule/workflow/function/script discovery | planned |
| 3 | Playbook IR, validation, simulation | planned |
| 4 | Compilation, export, import | planned |
| 5 | Controlled enablement | planned |
| 6 | Cross-platform QRadar SIEM + SOAR | planned |

## License
See `LICENSE`.
