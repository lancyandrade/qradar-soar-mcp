# qradar-soar-mcp

A security-first [MCP](https://modelcontextprotocol.io) server that connects
Claude to IBM QRadar SOAR (formerly Resilient) for incident investigation and
controlled response actions. Playbook authoring and deployment are designed
(see `docs/design/`) and **not in this release**.

> ### ⚠️ Read this before you enable anything
>
> This project lets a language model operate a security orchestration platform.
> Some of its capabilities can, if enabled, reach through SOAR to your EDR,
> firewall and identity provider. Endpoint isolation and IP blocking are not
> reversible with a button.
>
> **Everything except reading is disabled by default and stays disabled until
> you deliberately turn it on, per capability.** Read
> [docs/threat-model.md](docs/threat-model.md) before setting any flag above
> Tier 1. If you are looking for a quick way to let Claude "just fix things" in
> SOAR, this is not that project, on purpose.

This is version **0.2.0** (alpha, pending publication; see
[Release status](#release-status)), the Phase-1 milestone, plus the Phase-2 discovery tools.
Every tool is tested offline against a contract model of the SOAR REST API
(`tests/fake_soar.py`). Separately, owner-approved research runs checked the API
against **one** lab appliance, IBM QRadar SOAR `51.0.9.0.20848`
([docs/soar-api-verified.md](docs/soar-api-verified.md)). Those runs verified the read
surface and the task-status write. The other writes (notes, artifacts, incident
create, update and close) were **not** exercised live: their request bodies follow
the appliance's own reference and the offline model only. No other SOAR version was
tested. See [Confidence in API claims](#confidence-in-api-claims).

---

## What it does

**Investigate (Tier 0, always on)** — search and read incidents, artifacts,
tasks, notes, attachment metadata, users and custom-field definitions; get a
whole incident in one call under a size budget; find incidents that share
artifacts with this one. The server also keeps a cached, read-only catalog of the
SOAR configuration (functions, scripts, rules, playbooks, fields, data tables, …)
and answers discovery questions from it: which functions exist and what inputs each
takes, which scripts and message destinations exist, which incident types, phases and
data tables are defined, which fields an incident, task or artifact has and which
values a picklist accepts, and, read-only and capped, what a script's source says. `soar_refresh_catalog` reloads it. Nothing can write or run a
script.

**Annotate and modify (Tiers 1–2, off by default)** — add notes and artifacts,
create incidents, update fields, assign, close. Each is a separate capability
flag. Opening or closing a task is verified for QRadar SOAR `51.0.9.0.20848` only
and has no protection against a concurrent edit (see
[Known limitations](#known-limitations)).

**Respond (Tier 3, off by default, human-approved)** — invoke a manual action
that *you* classified in a policy file, after a human approves that exact call
out of band. **Not available in this release:** SOAR's invocation contract is
unverified for QRadar SOAR 51.0.9, so `soar_invoke_action` refuses every call
(see [Known limitations](#known-limitations)). The flags, policy and approval
machinery stay in place for when it is verified.

Every tool changes at most one object. There is no delete, no bulk operation,
no script execution and no way to reach a SOAR endpoint the design does not
list.

---

## Risk tiers and flags

Deny by default: an absent, empty or unparseable flag is `false`. Parsing
never fails open.

| Tier | Scope | Default | Flags |
|---|---|---|---|
| 0 | Read, poll approvals | **on** | — |
| 1 | Notes, artifacts | off | `SOAR_ALLOW_COMMENTS`, `SOAR_ALLOW_ARTIFACTS` |
| 2 | Incident/task modification, close | off | `SOAR_ALLOW_INCIDENT_WRITES`, `SOAR_ALLOW_TASK_WRITES`, `SOAR_ALLOW_INCIDENT_CLOSE` |
| 3 | Security control actions (block, isolate, disable, reset, quarantine) | off | `SOAR_ALLOW_ACTIONS`, `SOAR_ALLOW_DESTRUCTIVE_ACTIONS` + `SOAR_ACTION_POLICY_FILE` |
| 4 | Playbook create/modify/deploy/enable — **no tools in this release** | off | `SOAR_ALLOW_PLAYBOOK_DRAFT`, `SOAR_ALLOW_PLAYBOOK_EXPORT`, `SOAR_ALLOW_PLAYBOOK_CREATE`, `SOAR_ALLOW_PLAYBOOK_MODIFY`, `SOAR_ALLOW_PLAYBOOK_DEPLOY`, `SOAR_ALLOW_PLAYBOOK_ENABLE` |
| 5 | Bulk destructive, arbitrary code, AppHost changes | **not implemented, by design** | none — there is no flag |

Tier 5 has no enabling flag and never will. Arbitrary script execution
(`SOAR_ALLOW_SCRIPT_WRITES=true` refuses to start), AppHost code modification,
app installation, bulk mutation and deletion are architectural non-goals. Use
the SOAR UI as a human for those.

**A Tier-3 action's tier is a property of the action, not the tool.** Invoking
"Send Analyst Digest" can be Tier 1; invoking "EDR — Isolate Endpoint" is Tier
3. You classify your own environment in `action_policy.yaml`
([example](config/action_policy.example.yaml),
[schema](docs/action_policy.schema.json)). Anything you have not classified is
denied. `SOAR_ALLOW_ACTIONS=true` without a valid policy file is a startup
failure.

---

## Tools

| Tool | Tier | Flag | What it does |
|---|---|---|---|
| `soar_search_incidents` | 0 | — | `query_paged` search with AND/OR filter groups; projected results |
| `soar_get_incident` | 0 | — | one incident, projected; custom fields only on request |
| `soar_get_incident_full` | 0 | — | incident + tasks + artifacts + notes + attachment metadata, under a size budget |
| `soar_find_similar_incidents` | 0 | — | recent incidents sharing artifact values (client-side composition) |
| `soar_list_artifacts` | 0 | — | artifacts on an incident |
| `soar_list_tasks` | 0 | — | tasks on an incident |
| `soar_list_comments` | 0 | — | notes, flattened with `parent_id` |
| `soar_list_attachments` | 0 | — | attachment **metadata** only; contents are never fetched |
| `soar_list_users` | 0 | — | users in the org |
| `soar_describe_incident_fields` | 0 | — | field definitions incl. custom `properties.*` and close-required flags |
| `soar_list_incident_actions` | 0 | — | manual actions the incident carries, with their policy classification |
| `soar_check_approval` | 0 | — | state of an approval reference (broker files; no SOAR call) |
| `soar_refresh_catalog` | 0 | — | reload the cached catalog of SOAR configuration now; returns source, fetch time, SOAR version and counts, never the objects |
| `soar_list_functions` | 0 | — | functions in the cached catalog: name, id, display name, short description, destination, version, input counts; paged, sorted by name |
| `soar_get_function` | 0 | — | one function from the cached catalog with its inputs: name, label, type, required-ness, and tooltip / placeholder / select values where they cannot hold a credential or a person |
| `soar_list_scripts` | 0 | — | scripts in the cached catalog: metadata only, never a body; paged, sorted by programmatic name |
| `soar_get_script` | 0 | — | one script: catalog metadata plus a safety-filtered representation of its source, read on demand (`GET /scripts/{id}`), read-only: credential-like text may be redacted, then the result is cut at 20,000 characters; `body.redacted`, `body.truncated` and `body.text_is` say which happened; untrusted data, never run |
| `soar_list_message_destinations` | 0 | — | message destinations in the cached catalog; never the API keys or users bound to one |
| `soar_list_incident_types` | 0 | — | incident types in the cached catalog: name, id, uuid, enabled, hidden, system, parent id as SOAR gives it; paged, sorted by name |
| `soar_list_phases` | 0 | — | phases in the cached catalog: name, id, uuid, enabled, order; paged, sorted by order |
| `soar_list_fields` | 0 | — | field definitions of `incident`, `task` or `artifact` from the cached catalog: api name (`properties.<name>` for custom), label, input type, SOAR's raw `required` token, read-only, internal, and picklist values (label and stored value); paged |
| `soar_list_datatables` | 0 | — | data tables (SOAR types with `type_id == 8`) in the cached catalog, with their columns; definitions only, never a row |
| `soar_list_rules` | 0 | — | rules in the cached catalog: name, id, SOAR's rule `type` number, object type, enabled, logic type, condition count, message destinations; paged, sorted by name |
| `soar_get_rule` | 0 | — | one rule from the cached catalog with its conditions as field name and method; never the compared values, the automations or the workflows it starts |
| `soar_list_workflows` | 0 | — | workflows in the cached catalog: identity, object type, the functions each calls and counts of nodes, edges, calls, unresolved calls and structural problems; paged, sorted by programmatic name |
| `soar_get_workflow` | 0 | — | one workflow's structural summary from the cached catalog: nodes, `sequenceFlow` edges, gateway defaults, function calls resolved by uuid, problems; with `include_raw=true` also its XML, read on demand (`GET /workflows`), credential-filtered, cut at 50,000 characters and labelled untrusted |
| `soar_list_playbooks` | 0 | — | playbooks in the cached catalog (SOAR's paged playbook query): API name, id, display name, status token (`enabled`, `draft`, …), activation type, object type, type, version, logical-error, deleted and locked flags; paged, sorted by name |
| `soar_get_playbook` | 0 | — | one playbook, read on demand (`GET /playbooks/{id}`) after the catalog has resolved it: identity, activation conditions as field name and method (never the compared values), the functions it calls resolved by exact uuid, and a structural summary of its BPMN XML; never the XML itself; verified on QRadar SOAR 51.0.9.0.20848 only |
| `soar_add_comment` | 1 | `SOAR_ALLOW_COMMENTS` | one note |
| `soar_add_artifact` | 1 | `SOAR_ALLOW_ARTIFACTS` | one artifact |
| `soar_create_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | one incident |
| `soar_update_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | fields on one incident (optimistic concurrency; closing fields refused) |
| `soar_assign_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | owner of one incident |
| `soar_close_incident` | 2 | `SOAR_ALLOW_INCIDENT_CLOSE` | close with resolution + summary + close-required custom fields |
| `soar_update_task_status` | 2 | `SOAR_ALLOW_TASK_WRITES` | open or close one task of one incident (`status` only; verified on QRadar SOAR 51.0.9, no concurrency protection) |
| `soar_invoke_action` | per policy | `SOAR_ALLOW_ACTIONS` (+ `SOAR_ALLOW_DESTRUCTIVE_ACTIONS`) | **unavailable in this release**: refuses every call as `DENY_UNSUPPORTED` |

Every response is `{"ok": true, "request_id": ..., "data": ...}` or
`{"ok": false, "request_id": ..., "error": {"code": ..., "message": ...}}`. A
denial names the setting that would change it (`DENY_DISABLED`, `DENY_POLICY`,
`DENY_TARGET`, `DENY_TRANSPORT`, `DENY_KILL_SWITCH`, `DENY_RATE_LIMIT`, …).
`DENY_UNSUPPORTED` is the exception: no setting changes it, because the SOAR
request the tool needs has not been verified, and nothing is sent to SOAR.
Audit records never appear in tool output.

### What an incident looks like to the model

Raw SOAR incident DTOs have 150+ fields and are never returned. Every incident
in every tool is projected to exactly these fields:

`id`, `name`, `description`, `plan_status`, `phase_id`, `severity_code`,
`incident_type_ids`, `owner_id`, `discovered_date`, `create_date`,
`start_date`, `due_date`, `inc_last_modified_date`, `resolution_id`,
`resolution_summary`, `vers`

Custom fields (`properties.*`) are returned only when a tool is asked for them
(`custom_fields=[...]`), each trimmed individually. Free text is trimmed with a
visible `… [truncated N chars]` marker: descriptions and resolution summaries
at 2,000 characters, note text at 2,000, artifact values at 1,000, custom
fields at 1,000, attachment names and content types at 300 (the same as other
names). `soar_get_incident_full` keeps its whole payload under
**60,000 characters** (roughly 15k tokens): collections are capped (50 tasks,
100 artifacts, 50 notes, 50 attachments) and halved until the budget fits;
`omitted` reports what was cut. The budget applies to the whole `data` object
the client receives: after redaction, serialised as JSON with ASCII escaping, and
including the `budget` block itself; `budget.chars` is exactly that size. If the
incident still does not fit with one row per collection (only possible with many
`custom_fields`), the call fails with `response_too_large` rather than exceed the
budget. The field list is pinned by a snapshot test;
changing it is a reviewed change.


### What SOAR configuration looks like to the model

The discovery tools answer from the server's cached catalog, a fixed projection of each
SOAR object, never the object itself. A fresh catalog (`SOAR_CATALOG_TTL_SECONDS`) is
reused and costs SOAR nothing; a stale one is reloaded on the next call;
`soar_refresh_catalog` forces it. If the catalog cannot be built (for example
`SOAR_CATALOG_SOURCE=export`), the tools fail with that error; they never fall back to
another source and never answer "empty" for something unknown.

- **Lists** are sorted, and paged with `start` / `length`: at most 100 rows per call
  (fewer if `SOAR_MAX_RESULTS` is lower) and at most 40,000 characters of rows; `more` and
  `next_start` say where to continue. `name_contains` is a plain case-insensitive
  substring. Descriptions are trimmed at 200 characters in a list.
- **Lookups** are exact: a function by `name` or `function_id`, a script by
  `programmatic_name` or `script_id`, a rule by `name` or `rule_id`, a workflow by
  `programmatic_name` or `workflow_id`. Nothing is matched approximately.
- **Function inputs** always carry `name`, `label`, `input_type` and `required`. A
  `password` input carries nothing else; an owner or members input carries no values;
  other inputs add tooltip, placeholder and select values (100 per input, 200 per
  function, the remainder counted in `values_omitted`). `unresolved_inputs` > 0 means the
  input list is known to be incomplete.
- **Fields** (`soar_list_fields`) are listed for exactly one of `incident`, `task` or
  `artifact`; nothing else is accepted, and data-table columns are in
  `soar_list_datatables`. A custom field's `api_name` is `properties.<name>`. A select
  field lists its choices as `label` (what SOAR shows) and `value` (what SOAR stores),
  100 per field, the remainder counted in `values_omitted`; owner, members and
  `password` fields list none. **`required` is SOAR's own token, unchanged**, or null
  when the property was absent. On 51.0.9.0.20848 the literal tokens observed were
  `always` (incident, task, artifact) and `close` (incident). What a token makes SOAR do
  is not documented on the appliance and was not tested (that needs a write), so **no
  required or close-required boolean is derived and no token is interpreted**; every
  answer says so under `required_semantics`. A token not listed there is unknown, and
  neither it nor a null is to be interpreted as optional.
- **Data tables** are definitions only: type name, display name, parent types and
  columns (`name`, `label`, `input_type`, `order`, and SOAR's raw `required`; SOAR sent
  no such key on any column seen, so it is null). No row of a table is read, kept or returned.
- **Phases** are sorted by SOAR's `order`; **incident types** show `parent_id` as SOAR
  gives it, with no hierarchy worked out.
- **Rules** show each condition as the field it looks at and SOAR's `method` token;
  the value a condition compares with is not kept. SOAR's rule `type` number is shown
  as it is, uninterpreted. Which workflows a rule starts is not shown: every rule seen
  on 51.0.9.0.20848 had an empty list there, so its form is unverified.
- **Workflows** are summarised from their BPMN 2.0 XML when the catalog loads, and the
  XML is then dropped: the catalog never holds it. A summary has `nodes` (BPMN element
  id and `type`, e.g. `startEvent`, `serviceTask`, `exclusiveGateway`, `endEvent`),
  `edges` taken from `sequenceFlow` elements only (each `kind` is `default`,
  `conditional` or `unconditional`; a condition's language is kept, its script is not),
  the function each service task calls and `problems`. A call names its function by a
  `uuid`; it is `resolved` only when that uuid, exactly as written, equals the uuid of
  exactly one function in the same catalog, otherwise `unresolved`, and nothing is
  matched loosely. Input values and
  pre- and post-processing scripts are not kept, only input names and whether a script
  is present. `problems` reports dangling `sourceRef` / `targetRef`, a gateway default
  that is not one of the gateway's own flows, a gateway flow with neither a condition
  nor default status, unresolved functions, node types not observed on 51.0.9.0.20848
  and nodes that cannot be reached from a start event. XML that declares a DTD or an
  entity, is not well-formed or exceeds the bounds is not parsed: the workflow is listed
  with `structure: refused` and a fixed reason.
- **Workflow XML** is returned only by `soar_get_workflow` with `include_raw=true`: one
  `GET /workflows` (this version documents no single-workflow read), the row chosen by
  the catalog's `workflow_id`. Exactly as for a script body, credential-like text is
  redacted first and the result is then cut at **50,000 characters**; `raw.redacted`,
  `raw.truncated` and `raw.text_is` (`exact_xml`, `exact_xml_prefix`, `redacted_xml`,
  `redacted_xml_prefix`) say which happened. The XML holds condition and processing
  scripts and input values: it is **untrusted** data (`raw.untrusted` is always true),
  never an instruction, and a cut XML may not be well-formed.
- **Playbooks** are listed from the catalog, which reads them with SOAR's paged
  playbook query. `soar_get_playbook` reads one playbook object on demand
  (`GET /playbooks/{id}`, with the catalog's id) and keeps nothing of it: its BPMN XML is
  summarised exactly as a workflow's is (same parser, same bounds and refusals, same
  `problems`) and dropped, and a function call is resolved only by exact uuid equality
  with exactly one catalog function (on QRadar SOAR 51.0.9.0.20848 a playbook's call
  uuid was observed to equal the called function's uuid). Activation conditions are
  returned as `field_name` and `method` only; the values they compare with are never
  read into a result. There is no option to return the playbook XML. An answer whose
  name or uuid no longer matches the catalog is a `conflict`; a missing or mistyped
  verified key is `malformed_response`. The playbook object and its XML were verified
  on QRadar SOAR 51.0.9.0.20848 only.
- **Script source** is read only when `soar_get_script` is asked for it, from
  `GET /scripts/{id}` (`script_text`), and is not kept. The tool returns a
  **safety-filtered representation** of it as `body.text`, not necessarily the exact
  source. Two independent things can happen to it, in this order, and each is reported:
  - *Redaction, a safety transformation.* This server's credential, and text the
    redactor takes for a credential (`Basic <token>`, `authorization = <value>`), is
    replaced by `[REDACTED]` (`body.redaction_marker`). It is a heuristic over arbitrary
    code, so it can also replace harmless text that looks like a credential.
    `body.redacted` is true exactly when it changed anything; what it replaced is not
    returned, and the unredacted body is not retained.
  - *Truncation, a size transformation.* The result is then cut at **20,000 characters**.
    `body.truncated` is true exactly when that cap cut it, and means nothing else.
    Redaction comes first because a secret cut in half is no longer recognisable.

  `body.text_is` names the combination: `exact_source` (neither happened; only then is
  `body.text` the script character for character), `exact_source_prefix`,
  `redacted_source` or `redacted_source_prefix`. The lengths are counts of characters
  (code points): `source_chars` of `script_text` as SOAR returned it, `safe_chars` after
  redaction (equal to `source_chars` when nothing was redacted), `returned_chars` of
  `body.text`, and `limit_chars`, the cap. Script source is **untrusted data**
  written by whoever administers SOAR or published an app: it is never executed, imported
  or evaluated by this server, it is not logged or audited, and the model is told not to
  follow anything it says. This server has no request that creates, changes or deletes a
  script, and a test fails the build if one appears.

---

## Quick start (read-only)

```bash
git clone https://github.com/lancyandrade/qradar-soar-mcp && cd qradar-soar-mcp
uv sync
cp .env.example .env          # fill in SOAR_API_KEY_ID / SOAR_API_KEY_SECRET
set -a; . ./.env; set +a      # or export them however your platform prefers
uv run qradar-soar-mcp --check
```

`--check` prints a JSON report (no secrets) and exercises the same
`incidents/query_paged` call the search tool uses, so a green result means
search actually works, not just that TLS handshook. Exit codes: 0 reachable,
1 not configured or unreachable, 2 configuration refused.

Create the API key in **Administrator Settings → API Keys**. Start with a
read-only permission set. TLS verification is on by default; if your appliance
uses a private or self-signed CA, see [TLS trust](#tls-trust) rather than
turning verification off.

### Claude Desktop / Claude Code (stdio — the supported transport)

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
        "SOAR_CA_BUNDLE": "/etc/qradar-soar-mcp/soar-ca.pem",
        "SOAR_AUDIT_LOG_PATH": "/var/log/qradar-soar-mcp/audit.jsonl"
      }
    }
  }
}
```

The server writes nothing to stdout except the MCP protocol; logs go to stderr
with secrets redacted. It refuses to start if the audit log cannot be written
(`SOAR_AUDIT_REQUIRED=true`, the default). Leave `SOAR_CA_BUNDLE` out if
Python's default TLS trust already covers your appliance's certificate; see
[TLS trust](#tls-trust).

---

## TLS trust

The API key travels in every request, so the connection to SOAR is always
verified unless you explicitly say otherwise. There are three states; `--check`
reports which one is in force (`tls.trust`: `python_default`, `ca_bundle` or
`insecure`).

**1. Python's default TLS trust configuration (the default).** Nothing to
configure. With no `SOAR_CA_BUNDLE`, the default trust source is whatever
Python's `ssl.create_default_context()` exposes on the current platform and
Python distribution. That is often the operating system's trust store, in which
case a public CA, or an enterprise CA your organisation has deployed, simply
works. But the exact default trust-store behaviour varies by platform and Python
build, and this server does not paper over the difference: if the default
exposes no CA certificates at all, it says so at start-up, connections fail
verification, and the fix is state 2.

```bash
SOAR_BASE_URL=https://soar.example.internal
SOAR_VERIFY_SSL=true        # the default; shown for clarity
```

**2. A private or self-signed CA.** Export the CA certificate (PEM) that issued
the appliance's certificate and point `SOAR_CA_BUNDLE` at it. Verification stays
on. The explicitly supplied bundle is used *instead of* Python's default trust
for this connection, so only that CA is trusted.

```bash
SOAR_BASE_URL=https://soar.example.internal
SOAR_VERIFY_SSL=true
SOAR_CA_BUNDLE=/etc/qradar-soar-mcp/soar-ca.pem
```

A CA bundle changes *whom* the server trusts, never *what* it checks: the host
name in `SOAR_BASE_URL` must still be one the certificate was issued for. If the
certificate names `soar.example.internal`, use that name, not an IP address.
There is no setting that skips the host-name check while keeping the rest.

**3. No verification — lab only.**

> ⚠️ **`SOAR_VERIFY_SSL=false` exposes your SOAR API key to anyone on the network
> path.** It is refused unless `SOAR_LAB_MODE=true` is also set, it is logged as
> a warning on every start, and it has no place outside a throwaway lab. If you
> are reaching for it because of a self-signed certificate, use state 2 instead.

```bash
SOAR_VERIFY_SSL=false
SOAR_LAB_MODE=true          # required; without it the server refuses to start
```

What the server will never do: fall back from verified to unverified TLS, retry
a failed handshake with weaker settings, fetch or pin the appliance's
certificate, trust on first use, ship a certificate of its own, or touch your
operating system's trust store. A `SOAR_CA_BUNDLE` that is missing or is not PEM
refuses to start; it does not quietly revert to Python's default trust.

When verification fails, the tool error says which kind of failure it was and
what to change (an untrusted issuer → `SOAR_CA_BUNDLE`; a host-name mismatch →
the name in `SOAR_BASE_URL`; an expired certificate → the appliance). The
OpenSSL detail is written to the log only. Python 3.13 and later also apply
stricter RFC 5280 checks by default; a certificate they reject needs reissuing,
not a weaker client.

`SOAR_VERIFY_SSL=/path/to/ca.pem`, the form used before `SOAR_CA_BUNDLE`
existed, still works and means the same as state 2; it logs a deprecation
warning.

---

## Recommended deployment: two instances, two keys

Run two separate server processes, each with its own configuration and its own SOAR
API key:

| Instance | SOAR key | Flags | Tiers usable in this release | When |
|---|---|---|---|---|
| `qradar-soar` | read-only permission set | none (the defaults) | 0 | always registered |
| `qradar-soar-ops` | read plus exactly the writes you enable, nothing more | only the Tier 1–2 flags this engagement needs | 0–2 | registered deliberately, per engagement, removed afterwards |

This puts a permission boundary **in SOAR** behind the one in this software. If
our permission code has a bug, the read-only key still cannot close an
incident. For a project whose job is letting an LLM touch a security platform,
defending against your own code is the correct posture.

**The SOAR permission set is your control, not ours.** The server cannot check
which permissions its key has. On 51.0.9.0.20848 no endpoint that a read-only key can
use reports them (`/rest/session` answers with empty permission data; `/permissions`
and `/apikeys` answer 403; [open question Q6](docs/open-questions.md)). Nothing at
start-up warns you that a key can do more than the flags allow. Create the read-only
key with a read-only permission set in SOAR, and give the ops key only the permissions
its enabled tools need. For example, `soar_update_task_status` needs SOAR's task-edit
permission.

**Tier 3 in this release.** `soar_invoke_action` refuses every call
(`DENY_UNSUPPORTED`), so `SOAR_ALLOW_ACTIONS` gives the ops instance nothing it can
use. Leave it `false`. If you do set it, it needs a valid policy file to start, and
under the HTTP transport Tier 3 is refused anyway.

### Keep the two instances independent

Each process holds its own state in files. Nothing locks those files across
processes, so two processes must never share them:

| Setting | Read-only instance | Ops instance | Why separate |
|---|---|---|---|
| `SOAR_API_KEY_ID` / `SOAR_API_KEY_SECRET` | read-only key | narrowly scoped key | the SOAR-side boundary above; rotate each on its own |
| `SOAR_AUDIT_LOG_PATH` | its own file | its own file | each process continues the hash chain from the last line it read at start-up; two writers interleave and break the chain, and the hourly caps are rebuilt from this one file |
| `SOAR_APPROVAL_BROKER_PATH` | its own directory (unused) | its own directory, which the model cannot reach | approval requests are bound to one server's tool calls |
| `SOAR_APPROVAL_PUBLIC_KEY_FILE` | not needed | only if Tier 3 is ever enabled | the server holds only the public key |
| `SOAR_KILL_SWITCH_FILE` | any (it never mutates) | an absolute path the on-call operator can `touch` | stops the ops instance's mutations in one step |
| `SOAR_ACTION_POLICY_FILE` | not set | only if `SOAR_ALLOW_ACTIONS=true` | |

The code defaults for these paths are relative (`audit.jsonl`, `approvals`, `HALT`).
They resolve against the process's working directory, so two instances started from
the same directory would share them. Set absolute paths for both instances.

Register the two as separate MCP servers, each with its own `env` block (or its own
environment file sourced by its own wrapper). The server reads **only its process
environment**; it never reads a `.env` file itself.

```json
{
  "mcpServers": {
    "qradar-soar": {
      "command": "uv",
      "args": ["--directory", "/opt/qradar-soar-mcp", "run", "qradar-soar-mcp"],
      "env": {
        "SOAR_BASE_URL": "https://soar.example.internal",
        "SOAR_ORG_ID": "201",
        "SOAR_API_KEY_ID": "<read-only key id>",
        "SOAR_API_KEY_SECRET": "<read-only key secret>",
        "SOAR_AUDIT_LOG_PATH": "/var/log/qradar-soar-mcp/ro/audit.jsonl",
        "SOAR_APPROVAL_BROKER_PATH": "/var/lib/qradar-soar-mcp/ro/approvals",
        "SOAR_KILL_SWITCH_FILE": "/etc/qradar-soar-mcp/ro/HALT"
      }
    },
    "qradar-soar-ops": {
      "command": "uv",
      "args": ["--directory", "/opt/qradar-soar-mcp", "run", "qradar-soar-mcp"],
      "env": {
        "SOAR_BASE_URL": "https://soar.example.internal",
        "SOAR_ORG_ID": "201",
        "SOAR_API_KEY_ID": "<ops key id>",
        "SOAR_API_KEY_SECRET": "<ops key secret>",
        "SOAR_ALLOW_COMMENTS": "true",
        "SOAR_ALLOW_ARTIFACTS": "true",
        "SOAR_AUDIT_LOG_PATH": "/var/log/qradar-soar-mcp/ops/audit.jsonl",
        "SOAR_APPROVAL_BROKER_PATH": "/var/lib/qradar-soar-mcp/ops/approvals",
        "SOAR_KILL_SWITCH_FILE": "/etc/qradar-soar-mcp/ops/HALT"
      }
    }
  }
}
```

The client's configuration file now holds both API key secrets in plain text. Protect
it like any other secret store, and include it in key rotation
([runbook](docs/runbooks/key-rotation.md)).

Run `--check` with each instance's environment before registering it.
`capabilities` must list exactly the flags you meant (an empty list for the read-only
instance), and `audit.path` must be that instance's own file.

### Warnings

- **Production.** Never set `SOAR_LAB_MODE=true`, `SOAR_APPROVAL_MODE=in_band` or
  `disabled`, `SOAR_VERIFY_SSL=false`, or a confirmation switch
  (`SOAR_REQUIRE_ACTION_CONFIRMATION`, `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION`) to `false`
  on an instance that can reach a production SOAR. They exist for throwaway labs and
  remove guarantees this README relies on; each of them except lab mode itself refuses
  to start without `SOAR_LAB_MODE=true` (approval modes only once actions or a Tier-4
  flag are enabled).
- **HTTP transport.** stdio is the supported transport. `streamable-http` refuses to
  start without `SOAR_HTTP_AUTH_TOKEN`, refuses to bind every interface without
  `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE=true`, and denies Tier 3 regardless of flags. The
  listener itself serves plain HTTP. Off loopback it must sit behind a
  TLS-terminating reverse proxy; the server logs that obligation but cannot check it.
  Anyone holding the one bearer token can use every tier that instance enables. Never
  expose the ops instance over HTTP.
- **One key per instance.** Do not reuse the ops key on the read-only instance "for
  convenience". That removes the SOAR-side boundary, and nothing in this software
  would notice.

---

## Approval model

`SOAR_APPROVAL_MODE=out_of_band` (the default) is required for anything at
Tier 3 outside a lab.

In-band confirmation — where the model receives a token and echoes it back —
**is not human approval**. The model can read the token from its own context.
It prevents accidents and creates an audit record; it does not prevent a
confused or prompt-injected model from proceeding. This matters here because
incident names, descriptions, notes, artifact values and attachment filenames
are attacker-influenced text that lands in Claude's context: anyone who can
file a phishing report can write into the data the model reads. `in_band` and
`disabled` are accepted only with `SOAR_LAB_MODE=true`, and every in-band
response carries a disclaimer saying so.

Out-of-band approval works through a file broker and an Ed25519 signature the
server can verify but cannot forge.

**In this release no tool reaches this step.** Approval is required from Tier 3 up.
The only Tier-3 tool, `soar_invoke_action`, is refused (`DENY_UNSUPPORTED`) before any
approval is requested, and Tiers 1–2 never ask for one. The broker, the signature check
and the replay protection are built and tested offline, and kept for when an
invocation contract is verified. The example below shows how the flow will work.

1. Once, in the approver's environment (not on the MCP host):
   `qradar-soar-approve keygen --private ~/.config/qradar-soar/approval.key --public approval.pub`.
   Give **only** `approval.pub` to the server (`SOAR_APPROVAL_PUBLIC_KEY_FILE`).
   The server never reads a private key.
2. A Tier-3 call returns `REQUIRE_APPROVAL` with a reference and writes
   `APR-….request.json` to `SOAR_APPROVAL_BROKER_PATH`. Claude is told to poll
   `soar_check_approval`, not to retry.
3. A human runs the approver CLI, which prints the plan and requires the
   reference typed back:

   ```text
   $ qradar-soar-approve APR-2026-0917-a83f0c --key ~/.config/qradar-soar/approval.key
   Reference: APR-2026-0917-a83f0c
   Tool:      soar_invoke_action     Tier 3  (destructive)
   Action:    EDR — Isolate Endpoint
   Target:    incident_id 2317, action_id 49
   Requested: 2026-09-17T09:41:02Z   Expires: 2026-09-17T09:56:02Z

   Invoke manual action 'EDR — Isolate Endpoint' (id 49) on incident 2317

   Type the reference to approve, anything else to reject: _
   ```

4. The approval is bound to a hash of the tool name and the exact arguments. It
   expires with the request (`SOAR_APPROVAL_TTL_SECONDS`, 900), and the signature's own
   expiry is never later than the request's. It is consumed atomically on use by
   renaming `….approved.json` to `….consumed.json`, so a replay, a different tool or a
   changed argument is denied (`DENY_APPROVAL`). Typing anything other than the
   reference writes `….rejected.json` and denies the request.

The plan deliberately shows ids and the operator-named action, never incident
text, so an attacker cannot write into the approver's terminal.

`qradar-soar-approve list` shows each request's state (`pending`, `approved`,
`consumed`, `rejected`). The approver's name in the audit record is `--approver`, or
the operating-system user by default. The approver identity is not authenticated
beyond who holds the private key.

---

## Security controls

| Control | Behaviour |
|---|---|
| Deny by default | Absent, empty or unparseable config ⇒ denied. Never permissive on error. |
| One chokepoint | Every tool runs through the same pipeline, in this order: capability flag → policy classification → tier → transport → unsupported-tool refusal (`enforce()`); kill switch → circuit breaker → one-object cap; approval (Tier ≥3); audit `MUTATION_PENDING`; hourly cap; execute; audit `MUTATION_COMMITTED` / `MUTATION_FAILED`; redact and project the response. An AST test fails if anything under `tools/` reaches the client outside it. |
| Unknown action ⇒ deny | Anything absent from `action_policy.yaml` is Tier 5 and denied. |
| `deny_values` | Per-action value blocklists — your own egress ranges, DC subnets, hypervisors. |
| Mutation cap | One object per tool call (`SOAR_MAX_MUTATIONS_PER_CALL` is clamped to 1). |
| Rate limits | `SOAR_MAX_TIER2_PER_HOUR` (25) and `SOAR_MAX_TIER3_PER_HOUR` (5), sliding one-hour windows. The counters are rebuilt from the audit log, so a restart does not reset them; a mutation whose outcome was never recorded still counts. **Tier 1 (notes, artifacts) has no hourly cap.** |
| Circuit breaker | 3 consecutive failed Tier ≥2 calls disable Tier ≥2 until the process restarts. Tier 1 neither feeds nor trips it. |
| Kill switch | `touch $SOAR_KILL_SWITCH_FILE` denies every Tier ≥1 call from the next call on, with no restart; reads continue. If the server cannot tell whether the file exists, it treats the switch as engaged. Remove the file to resume. |
| Audit log | Hash-chained append-only JSONL: one record per denial, approval event, and mutation attempt (pending, then committed or failed, with pre/post images where the tool has them); `qradar-soar-audit verify`. Each string and key of a record is redacted on its own, never the serialised JSON, and the hash is taken over the redacted record, which is exactly the line on disk. Long values are clipped (2,000 characters per string). **Successful reads are not audited.** |
| Fail closed | Unwritable audit log ⇒ refuse to start; a mid-session write failure refuses the mutation before SOAR is called. A record that cannot be redacted without losing a field (two keys equal after redaction) is not written either; when it is the record required before a mutation, the mutation is refused. |
| Secret hygiene | `SecretStr`, a redacting log filter, sanitised errors, a startup self-test, `gitleaks` and a tree scanner in CI; a sentinel-leak test drives every tool through every failure class. |
| HTTP transport | Refuses to start without `SOAR_HTTP_AUTH_TOKEN`; refuses `0.0.0.0` without `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE`; Tier ≥3 is hard-disabled over HTTP regardless of flags. |

The threat model, including what these controls do **not** protect against, is
in [docs/threat-model.md](docs/threat-model.md). Key rotation is in
[docs/runbooks/key-rotation.md](docs/runbooks/key-rotation.md). Report
vulnerabilities per [SECURITY.md](SECURITY.md).

---

## Configuration reference

The server reads `SOAR_*` variables from its **process environment** once, at start-up.
It never reads a `.env` file itself (the quick start sources one into the shell).
Changing any variable takes a restart, except the presence of the kill-switch file,
which is checked on every call. [`.env.example`](.env.example) is the annotated copy.

**Code defaults and example values.** The *Default* column is what the server uses
when a variable is absent. `.env.example` is a separate starting point: it shows every
capability flag, each set to `false` like its code default, keeps both confirmation
switches `true` and `SOAR_LAB_MODE=false`. It differs from the code defaults only in
placeholders and suggested paths: the connection, the absolute state and public-key
locations, and the policy file (read only when actions are enabled). A copied, unedited
file therefore enables nothing, and `--check` lists no capabilities.

**Parsing never fails open.** A boolean is true only for exactly `true`, `1`, `yes`
or `on` (any case, no surrounding spaces), and false for `false`, `0`, `no` or `off`.
Anything else logs a warning naming the variable and resolves to the safe side:
`false` for a **capability** flag, `true` for a **safety switch**. An unparseable or
too-small number falls back to its default, with a warning; a number above its
maximum is clamped to the maximum. The values that refuse to start are named in the
tables; `--check` then exits 2 and names the variable, never a secret.

Kinds: **connection** · **capability** (enables tools of the tier shown; off by
default) · **safety switch** (protective by default; changing it removes a protection) ·
**operational** (sizes, paths, logging) · **transport** · **lab only** · **reserved**
(accepted, used by nothing in this release) · **deprecated**.

### Connection

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_BASE_URL` | — | connection | `https://` URL of the appliance. Plain `http://` only on loopback. A URL with credentials, a query or a fragment refuses to start |
| `SOAR_ORG_ID` | — | connection | organisation id. Unparseable or not positive ⇒ connection disabled, with a warning |
| `SOAR_API_KEY_ID` / `SOAR_API_KEY_SECRET` | — | connection | API key (HTTP Basic). The secret is held as a `SecretStr` and redacted from log lines, errors, tool output and audit records. Without all four connection values every tool that reaches SOAR fails with `not_configured` |
| `SOAR_VERIFY_SSL` | `true` | safety switch | TLS verification. `false` is lab-only: refused without `SOAR_LAB_MODE=true`, and warned about on every start. Anything unrecognised refuses to start. (The path of an existing CA bundle is still accepted here, deprecated.) See [TLS trust](#tls-trust) |
| `SOAR_CA_BUNDLE` | — | connection | PEM CA bundle for a private or self-signed CA. Empty ⇒ Python's default TLS trust configuration; set ⇒ the supplied bundle is used instead of it. Missing or not PEM, or set together with `SOAR_VERIFY_SSL=false` ⇒ refuses to start |
| `SOAR_TIMEOUT` | `30` | operational | request timeout, seconds (minimum 1) |
| `SOAR_MAX_RESULTS` | `50` | operational | page-size cap for search and for similar-incident candidates (1–500); discovery lists use the lower of this and 100 |

### Capabilities

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_ALLOW_COMMENTS` / `SOAR_ALLOW_ARTIFACTS` | `false` | capability, Tier 1 | `soar_add_comment` / `soar_add_artifact` |
| `SOAR_ALLOW_INCIDENT_WRITES` / `SOAR_ALLOW_TASK_WRITES` / `SOAR_ALLOW_INCIDENT_CLOSE` | `false` | capability, Tier 2 | create, update and assign incidents / task status / closing. `soar_update_incident` refuses the closing fields, so the close flag cannot be bypassed |
| `SOAR_ALLOW_ACTIONS` / `SOAR_ALLOW_DESTRUCTIVE_ACTIONS` | `false` | capability, Tier 3 | `soar_invoke_action`, which refuses every call in this release. `true` needs `SOAR_ACTION_POLICY_FILE` to exist and parse, and out-of-band approval unless `SOAR_LAB_MODE=true`; otherwise the server refuses to start. A policy rule marked destructive also needs the second flag |
| `SOAR_ACTION_POLICY_FILE` | — | capability input | your classification of manual actions ([example](config/action_policy.example.yaml), [schema](docs/action_policy.schema.json)). Required when `SOAR_ALLOW_ACTIONS=true`; a malformed file refuses to start. `.env.example` suggests `./config/action_policy.yaml` |
| `SOAR_ALLOW_PLAYBOOK_DRAFT` / `_EXPORT` / `_CREATE` / `_MODIFY` / `_DEPLOY` / `_ENABLE` | `false` | reserved capability, Tier 4 | accepted and reported by `--check`; no tool uses them yet. `.env.example` lists all six, each `false` |
| `SOAR_ALLOW_SCRIPT_WRITES` | `false` | intentionally unsupported | script writes are a non-goal; `true` refuses to start |

### Approval

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_APPROVAL_MODE` | `out_of_band` | safety switch | `out_of_band` \| `in_band` \| `disabled`. Unrecognised ⇒ `out_of_band`. With `SOAR_ALLOW_ACTIONS=true` or any Tier-4 flag, `in_band` and `disabled` refuse to start unless `SOAR_LAB_MODE=true`. Only Tier ≥3 asks for approval, so without those flags the mode has no effect |
| `SOAR_REQUIRE_ACTION_CONFIRMATION` | `true` | safety switch | Tier-3 calls need approval. Garbage ⇒ `true`. `false` drops the approval for a Tier-3 action whose policy rule says `allow` (a `require_approval` rule still asks). `false` refuses to start unless `SOAR_LAB_MODE=true`, whether or not actions are enabled, and is warned about when accepted |
| `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION` | `true` | safety switch | the same for Tier 4, including the lab-mode rule for `false`; reserved, since no Tier-4 tool exists yet |
| `SOAR_APPROVAL_BROKER_PATH` | `approvals` | operational | the broker directory. Put it where the model and its client cannot write |
| `SOAR_APPROVAL_PUBLIC_KEY_FILE` | — | operational | Ed25519 public key. Without it no approval can be verified, and every call that needs one is denied. A key that cannot be loaded, or is not Ed25519, refuses to start |
| `SOAR_APPROVAL_TTL_SECONDS` | `900` | operational | request and signature lifetime, seconds (minimum 10) |

The approver CLI also reads `SOAR_APPROVAL_PRIVATE_KEY_FILE` (or `--key`), in the
approver's environment only. The server never reads that variable. Do not set it on
the MCP host.

### Blast-radius caps, audit and safety

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_MAX_MUTATIONS_PER_CALL` | `1` | safety switch | clamped to 1, with a warning for any other value |
| `SOAR_MAX_TIER2_PER_HOUR` / `SOAR_MAX_TIER3_PER_HOUR` | `25` / `5` | safety switch | sliding one-hour windows, persisted via the audit log; `0` permits none. Tier 1 is not capped |
| `SOAR_AUDIT_LOG_PATH` | `audit.jsonl` | operational | hash-chained audit log; one file per server process |
| `SOAR_AUDIT_REQUIRED` | `true` | safety switch | unwritable log ⇒ refuse to start. `false` starts anyway with reads only: mutations are still refused while no log is open |
| `SOAR_KILL_SWITCH_FILE` | `HALT` | safety switch | while this file exists, every Tier ≥1 call is denied. Use an absolute path |
| `SOAR_LOG_LEVEL` | `INFO` | operational | stderr logging (`DEBUG` … `CRITICAL`; unrecognised ⇒ `INFO`) |
| `SOAR_SIM_MAX_INCIDENTS` | `25` | reserved | Phase 3 |
| `SOAR_SNAPSHOT_DIR` | `snapshots` | reserved | Phase 4 |
| `SOAR_PLAYBOOK_EXPORT_DIR` | `out/playbooks` | reserved | Phase 4 |

### Catalog

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_CATALOG_SOURCE` | `collections` | operational | where the catalog is read from. `collections`: the read-only collection endpoints, verified with a read-only key. `export`: selectable but **unavailable** (the configuration export is unverified: the one attempt was answered HTTP 403 and no export was obtained); every catalog load then fails with `catalog_unavailable`, nothing is sent, and there is no fallback. An unrecognised value warns and uses `collections` |
| `SOAR_CATALOG_TTL_SECONDS` | `300` | operational | how long a loaded catalog is reused; `0` reloads on every read; at most `86400`. `soar_refresh_catalog` ignores it |

### Transport

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_MCP_TRANSPORT` | `stdio` | transport | `stdio` \| `streamable-http` (`http` accepted). Unrecognised ⇒ `stdio`. `--transport` overrides it and goes through the same checks |
| `SOAR_MCP_HOST` / `SOAR_MCP_PORT` | `127.0.0.1` / `8090` | transport | HTTP bind; served at `/mcp` |
| `SOAR_HTTP_AUTH_TOKEN` | — | transport | required for HTTP; sent as `Authorization: Bearer`, compared in constant time, redacted from logs. Exactly one token is accepted |
| `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE` | `false` | transport | required to bind `0.0.0.0` / `::` |

### Lab only and deprecated

| Variable | Default | Kind | Meaning |
|---|---|---|---|
| `SOAR_LAB_MODE` | `false` | lab only | lab acknowledgement. On its own it changes nothing. It is what lets `SOAR_VERIFY_SSL=false` be accepted, `in_band` / `disabled` approval when actions or a Tier-4 flag are enabled, and `SOAR_REQUIRE_ACTION_CONFIRMATION=false` / `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION=false`. Never in production |
| `SOAR_ALLOW_WRITES` | — | deprecated | maps to the five Tier 1–2 flags only, with a warning, and never to `SOAR_ALLOW_ACTIONS`. Removed in the next minor version |

### Command line

| Command | What it does | Exit codes |
|---|---|---|
| `qradar-soar-mcp` | serve over stdio (or `SOAR_MCP_TRANSPORT`); writes nothing to stdout but the protocol | 2 refused configuration |
| `qradar-soar-mcp --transport stdio` (or `streamable-http`) | serve, overriding `SOAR_MCP_TRANSPORT` | as above |
| `qradar-soar-mcp --check` | validate the configuration, send one `incidents/query_paged`, print a JSON report with no secrets (`capabilities`, `tls`, `audit`, `limits`, `approvals`, `ping`, …) | 0 reachable · 1 not configured or unreachable · 2 refused configuration |
| `qradar-soar-mcp --version` | print the version | 0 |
| `qradar-soar-approve keygen --private KEY --public PUB` | new Ed25519 keypair; refuses to overwrite either file | 0 · 1 a file exists |
| `qradar-soar-approve list` | list requests and their state | 0 |
| `qradar-soar-approve APR-… [--key KEY] [--approver NAME] [--ttl SECONDS]` (`approve` may be written before the reference) | print the plan, require the reference typed back, then sign or reject | 0 approved · 3 rejected · 1 no such request, or not pending · 2 malformed reference or no usable key |
| `qradar-soar-audit verify [PATH]` | walk the hash chain (default `$SOAR_AUDIT_LOG_PATH`, else `./audit.jsonl`) | 0 intact · 1 broken, naming the first bad record |

`qradar-soar-approve --broker DIR` (before the subcommand) selects the broker
directory; the default is `$SOAR_APPROVAL_BROKER_PATH`, else `./approvals`.

---

## SOAR API behaviours this client relies on

Every mark below is about **one** appliance, IBM QRadar SOAR `51.0.9.0.20848`, as
recorded in [docs/soar-api-verified.md](docs/soar-api-verified.md). That record wins
wherever it disagrees with this list.

- ✅ **verified live** on that version, by an owner-approved research run (status and
  response shape; a write only where stated).
- ⚠️ **documented, not exercised live**: the appliance's own API reference documents
  it, and the offline contract model encodes it, but it is not yet verified live,
  usually because checking it needs a write. The client relies on it with that caveat.
- ❓ **unverified or unknown**: not relied on. The tool refuses, fails closed, or
  reports "unknown". Open items are in [docs/open-questions.md](docs/open-questions.md).

1. ✅ `handle_format=names` is sent on every request (except the two single-task
   calls): select values such as `severity_code` and `phase_id` come back as label
   strings (Q12). ⚠️ `text_content_output_format=always_text` is accepted everywhere,
   but its effect was not observable: `description` was a plain string either way.
2. ⚠️ `PATCH /incidents/{id}` is optimistic concurrency, not a merge: `version`
   plus `old_value`/`new_value` per field; an HTTP-200 `success: false` is
   raised as `patch_rejected`, never swallowed. ✅ The incident carries `vers`. The
   PatchDTO shape and the stale-version answer are documented, not exercised live.
3. ✅ Custom fields are read under `properties.<name>`, and field definitions mark
   them with `prefix: properties`. ⚠️ The bare name in a PATCH and `properties.<name>`
   in a filter are not exercised live.
4. ✅ Listing is `POST /incidents/query_paged?return_level=normal` (`return_level` is
   optional; `normal` returns the full object), `create_date` is accepted as a sort
   field, and an active incident's `plan_status` is `"A"`. ⚠️ Conditions inside one
   filter are ANDed and separate filters are ORed, per the reference; the research key
   saw no closed incident, so neither that nor `"C"` was distinguishable live (Q14).
5. ⚠️ Closing sends `plan_status` + `resolution_id` + `resolution_summary`
   together. ❓ Whether SOAR rejects a close with an empty close-required field, and
   what the field token `close` enforces, were not tested (that needs a write;
   `soar-api-verified.md` §3.2).
6. ✅ Task status changes follow the contract verified on QRadar SOAR
   `51.0.9.0.20848` (`docs/soar-api-verified.md` §3.1), and only that: read the
   task with `GET /tasks/{id}`, send the **whole** object back with
   `PUT /tasks/{id}` and `status` as the only change, then read it again and fail
   if the status is not there. There is no `PATCH` on a task, and no task version
   was observed or required; `closed_date` is the server's and is never set by this server. ⚠️ Nothing
   protects a task against a concurrent edit (none was ever observed): a
   change someone else makes between the read and the write can be overwritten.
   ❓ Other SOAR versions are unverified.
7. ✅ Manual actions are read from the `actions` list the incident object
   carries (`GET /incidents/{id}`); `GET /incidents/{id}/actions` answers 500
   on 51.0.9 and is not used. ❓ The shape of the list's entries is unverified,
   so only `id` and `name` are used and anything else fails closed. ❓ Invocation
   is unverified, so `soar_invoke_action` refuses every call before approval
   or any request.
8. ✅ `GET /rest/session` answers 200 to an API key on this version, with no
   permission data (Q9). `--check` reports the identity it names. A 403 or 404 from it
   (other versions) is reported as `session: unavailable` and does not fail the check.
9. ✅ The attachment-contents route was verified for one `text/plain` attachment
   (Q7), but this server **never fetches** contents: metadata only. ❓ Artifact hits
   and incident history are not used.
10. ⚠️ `POST /incidents` (Q8), `POST /incidents/{id}/comments` and
    `POST /incidents/{id}/artifacts` are documented by the appliance and modelled
    offline; none was exercised live. That `discovered_date` is the one required field
    of a new incident is the design's reading, not verified.
11. ✅ The catalog is built from read-only collection calls verified on QRadar SOAR
    `51.0.9.0.20848` with a read-only key (`docs/soar-api-verified.md` Q1, Q4, Q5, §2):
    `GET` on `/rest/const`, `functions`, `functions/{id}`, `types/__function/fields`,
    `actions`, `scripts`, `workflows`, `message_destinations`, `incident_types`,
    `phases`, `groups`, `types` and `types/{incident,task,artifact}/fields`, and the
    criteria-only `POST /playbooks/query_paged` (a `GET` on the playbook collection
    answers 500). Data tables are the types with `type_id == 8`; function inputs are
    `view_items` joined to the `__function` fields. A workflow's BPMN XML is
    `content.xml` of its `GET /workflows` row; its structure was verified for one
    workflow (`P2-04`, §3.3), and a key without workflow read is answered `403`.
    ❓ Installed apps and the API key's own permission set have no verified source and
    are reported as unknown, never as empty. ❓ The configuration export is unverified
    and not used. ❓ Other SOAR versions are unverified.

12. ✅ A script body is `script_text` of `GET /scripts/{id}` (`P2-00`, read-only key);
    the list row carries none. It is one of the two calls the discovery tools add to the
    catalog's (the other is item 13). ❓ How large a body SOAR returns, and
    playbook-local scripts, are unverified. No request that creates, changes or deletes a
    script exists in this server (`tests/test_no_script_writes.py`).

13. ✅ A single playbook is `GET /playbooks/{id}` (`P2-00`; `P2-05`, read-only key with
    playbook read): the list row plus `content.xml` (standard BPMN 2.0) and
    `activation_details.activation_conditions`. A function call in it is the vendor
    `function` element's `uuid` attribute, observed to equal the called function's
    `uuid` (`docs/soar-api-verified.md` §3.4). A key without playbook read, or without
    function read, is answered `403`. ❓ One draft playbook with one call was observed;
    other node kinds, manual activation and other SOAR versions are unverified.

### Confidence in API claims

The REST surface `client/` may touch is exactly the set of calls listed in
`docs/design/08-GREENFIELD-AMENDMENTS.md §4` and, for the catalog and discovery, `§25`,
`§26` and `§30`, enforced by an AST test. Nothing else is called.

Two kinds of evidence stand behind the marks, and they are not the same thing:

- **Offline contract model.** `tests/fake_soar.py` (with `respx`) models every call
  above, and the whole test suite runs against it with no network. It shows that the
  client sends what the design says and handles each answer it models. It cannot show
  that SOAR behaves that way. In places it is stricter than the appliance (it requires
  `return_level`, which SOAR does not).
- **Live research runs.** `P2-00`, `P2-00b` and the `P2-03`, `P2-04` and `P2-05`
  addenda read that surface on one lab appliance, `51.0.9.0.20848`, with
  [`scripts/probe/`](scripts/probe/README.md), each run approved by the owner. Only one
  kind of write was sent: four task-status `PUT`s on a disposable task.
  `docs/soar-api-verified.md` records the evidence, with sanitised response shapes in
  `tests/fixtures/soar/verified/`. These were one-off runs, not a test suite: the
  `lab` test markers are registered, but no lab test exists yet, and nothing re-checks
  a newer appliance automatically.

---

## Known limitations

- Live verification covers one appliance version (`51.0.9.0.20848`), the read surface
  and the task-status write. Notes, artifacts, incident create, update and close are
  tested offline only (see [Confidence in API claims](#confidence-in-api-claims)).
  Try them first against a lab or disposable org.
- The server cannot tell what its API key may do in SOAR. There is no start-up
  permission probe, because no endpoint a read-only key can use reports a key's
  permissions (Q6).
- The out-of-band approval flow is built but not reachable: no tool in this release
  asks for an approval (see [Approval model](#approval-model)).
- Successful reads are not written to the audit log; denials and every mutation
  attempt are. Tier-1 writes have no hourly cap and do not feed the circuit breaker.
- `soar_find_similar_incidents` is an N+1 client-side composition over the
  most recent `SOAR_MAX_RESULTS` incidents, not a server-side search.
- No manual action can be invoked: `soar_invoke_action` refuses every call as
  `DENY_UNSUPPORTED` until SOAR's invocation contract is verified.
  The refusal is audited as a denial and sends nothing to SOAR.
- `soar_update_task_status` changes a task's status and nothing else. Its SOAR
  contract is verified on one version (`51.0.9.0.20848`), one custom task and one
  API-key configuration. No task version was observed there, so a concurrent edit
  is neither detected nor prevented; what closing the last required task of a phase
  does was not tested. It refuses a task that is inactive, frozen, already in the
  requested status, or not in the given incident. The `PUT` is sent once and never
  retried; unless it was never sent, or SOAR answers `success: false`, the task is
  read back, and a change that the read-back does not confirm is reported as
  `unverified_write`, never as a success and never as "unchanged". That includes every HTTP error status: no
  status is taken as proof that the task was left alone, so the message names what
  SOAR answered (for example `HTTP 403`). The API key needs SOAR's task-edit
  capability.
- `soar_list_incident_actions` lists the incident's own actions, not those its
  tasks and artifacts carry.
- Attachment contents are never read; there is no text extraction.
- The catalog is verified for QRadar SOAR `51.0.9.0.20848` only, and a load is all or
  nothing: if any of its reads fails (a key that may not read scripts, say), there is
  no catalog, rather than one with a silent gap. It holds what a read-only key was seen
  to return: **not** the key's permission set (successful reads say nothing about what
  a key may write), **not** installed apps, no workflow XML (a workflow is kept as a
  structural summary), no script bodies, no playbook XML and no people (an owner or members field has no
  values in the catalog). `SOAR_CATALOG_SOURCE=export` does not work.
  One load costs one request per function on top of the collections.
- Discovery covers functions, scripts, message destinations, incident types, phases,
  fields, data tables, rules, workflows and playbooks. It reads; nothing creates,
  changes, exports, imports, enables or runs a playbook, workflow or script. The Tier-4
  flags are accepted and unused. `soar_list_playbooks` cannot show which functions a
  playbook calls (only `soar_get_playbook` reads that), and `soar_get_playbook` never
  returns the playbook XML or the values its conditions compare with.
- The workflow summary is verified against the structure of **one** workflow on
  51.0.9.0.20848 (a start event, one function call, one exclusive gateway, two end
  events). Other BPMN node types are listed with `type_observed: false` and their
  contents (a sub-process, say) are not summarised; a document with more than one
  process is refused. That a call's `uuid` is a function's uuid is not documented: a
  call is `resolved` only when the two values are equal in the loaded catalog. Which
  rules start a workflow, in either direction, is not shown. `include_raw` returns at
  most the first 50,000 characters of a workflow's XML.
- `soar_list_fields` reports a field's `required` as SOAR's raw token and derives no
  close-required flag: `always` and `close` were observed on 51.0.9.0.20848, but what
  they enforce is not documented on the appliance and was not tested
  (`docs/soar-api-verified.md §3.2`). `soar_describe_incident_fields` still reports
  `close_required` from the unverified baseline reading (`required == "close"`).
- `soar_get_script` returns at most the first 20,000 characters of a script; there is
  no way to read the rest. Its credential filter is a heuristic: it can replace harmless
  code that looks like a credential (`authorization = settings.value`), always reported
  as `body.redacted`, and it recognises only this server's own credential and those two
  shapes, not every secret a script may hold. A script renamed since the catalog was loaded is reported
  as `conflict` until `soar_refresh_catalog` is called.

## Release status

- **Current version: `0.2.0`, alpha, pending publication.** No `v0.2.0` tag or GitHub
  release exists yet. When it is published, it will be a source-code pre-release only:
  no wheel or sdist is attached and nothing is published to PyPI.
- **Phase 1 is complete in code, with documented deferrals.** Manual-action invocation
  always refuses (`DENY_UNSUPPORTED`), the approval flow is unreachable, and attachment
  hash and text extraction are deferred.
- **Early Phase-2 discovery is included**: 16 read-only tools, for 36 tools in all.
- **`v0.3.0` is not ready.** Phase 2 is incomplete.
- The release gate has not passed. The lab tests (T4–T6) have not run, and the owner
  decided not to waive them: the alpha is published only after they pass
  ([release-readiness §13.3](docs/release-readiness.md#133-verdict),
  [lab-validation plan](docs/lab-validation-plan.md)).

What changed: [CHANGELOG.md](CHANGELOG.md). Release notes:
[docs/releases/v0.2.0-alpha.md](docs/releases/v0.2.0-alpha.md).

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Investigation + controlled actions + security architecture | **v0.2.0 (alpha, pending publication)**; complete in code with documented deferrals |
| 2 | Verify the API surface against a lab; playbook/rule/workflow/function discovery | API verified (`P2-00`, `P2-00b`); catalog foundation in (`P2-01`); function, script and message-destination discovery in (`P2-02`); incident-type, phase, field and data-table discovery in (`P2-03`); rule and workflow discovery in (`P2-04`); playbook discovery in (`P2-05`); the rest (`P2-06`, `P2-07`) planned |
| 3 | Playbook IR, validation, offline simulation | planned |
| 4 | Compilation, export, import (always disabled) | planned |
| 5 | Controlled enablement | planned |
| 6 | Cross-platform QRadar SIEM + SOAR | planned |

## Development

```bash
uv sync --extra dev
uv run pytest                 # offline; no SOAR, no network, no environment needed
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run python scripts/check_no_secrets.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md). The design pack is in `docs/design/`;
`08-GREENFIELD-AMENDMENTS.md` records every decision that departs from it.

Pull requests can opt into an automated Codex review → Claude Code fix → CI →
Codex re-review loop with a fail-closed merge gate. It is off unless configured
and never merges; see [docs/runbooks/review-loop.md](docs/runbooks/review-loop.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
