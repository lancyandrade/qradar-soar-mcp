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

This is version **0.2.0**, the Phase-1 milestone. It has been tested offline
against a contract model of the SOAR REST API (`tests/fake_soar.py`); it has
**not yet** been verified against a live appliance by this repository. See
[Confidence in API claims](#confidence-in-api-claims).

---

## What it does

**Investigate (Tier 0, always on)** — search and read incidents, artifacts,
tasks, notes, attachment metadata, users and custom-field definitions; get a
whole incident in one call under a size budget; find incidents that share
artifacts with this one.

**Annotate and modify (Tiers 1–2, off by default)** — add notes and artifacts,
create incidents, update fields, assign, close. Each is a separate capability
flag. **Changing a task's status is disabled in this release** (see
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
| `soar_add_comment` | 1 | `SOAR_ALLOW_COMMENTS` | one note |
| `soar_add_artifact` | 1 | `SOAR_ALLOW_ARTIFACTS` | one artifact |
| `soar_create_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | one incident |
| `soar_update_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | fields on one incident (optimistic concurrency; closing fields refused) |
| `soar_assign_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | owner of one incident |
| `soar_close_incident` | 2 | `SOAR_ALLOW_INCIDENT_CLOSE` | close with resolution + summary + close-required custom fields |
| `soar_update_task_status` | 2 | `SOAR_ALLOW_TASK_WRITES` | **disabled in this release**: refuses every call as `DENY_UNSUPPORTED` |
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
fields at 1,000. `soar_get_incident_full` keeps its whole payload under
**60,000 characters** (roughly 15k tokens): collections are capped (50 tasks,
100 artifacts, 50 notes, 50 attachments) and halved until the budget fits;
`omitted` reports what was cut. The field list is pinned by a snapshot test;
changing it is a reviewed change.

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

| Instance | SOAR key | Tiers | When |
|---|---|---|---|
| `qradar-soar` | read-only permission set | 0 | always registered |
| `qradar-soar-ops` | read + write (+ invoke) | 0–3 | registered deliberately, per engagement, with its own `.env` |

This puts a permission boundary **in SOAR** behind the one in this software. If
our permission code has a bug, the read-only key still cannot close an
incident. For a project whose job is letting an LLM touch a security platform,
defending against your own code is the correct posture.

The server does **not** yet probe its key's permission set at startup (the
endpoint for that is an open question, `docs/open-questions.md`); the SOAR
permission set is your control, not ours.

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
server can verify but cannot forge. (The example below shows `soar_invoke_action`;
in this release that tool is refused before any approval is requested.)

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

4. The approval is bound to a hash of the exact arguments, expires after
   `SOAR_APPROVAL_TTL_SECONDS` (900), and is consumed atomically on use: a
   replay or a changed argument is denied.

The plan deliberately shows ids and the operator-named action, never incident
text, so an attacker cannot write into the approver's terminal.

---

## Security controls

| Control | Behaviour |
|---|---|
| Deny by default | Absent, empty or unparseable config ⇒ denied. Never permissive on error. |
| One chokepoint | Every tool runs through the same enforce → limits → approval → audit → execute → redact pipeline; an AST test fails if anything under `tools/` reaches the client outside it. |
| Unknown action ⇒ deny | Anything absent from `action_policy.yaml` is Tier 5 and denied. |
| `deny_values` | Per-action value blocklists — your own egress ranges, DC subnets, hypervisors. |
| Mutation cap | One object per tool call (`SOAR_MAX_MUTATIONS_PER_CALL` is clamped to 1). |
| Rate limits | `SOAR_MAX_TIER2_PER_HOUR` (25) and `SOAR_MAX_TIER3_PER_HOUR` (5); counters are rebuilt from the audit log so a restart does not reset them. |
| Circuit breaker | 3 consecutive Tier ≥2 failures disable Tier ≥2 until restart. |
| Kill switch | `touch $SOAR_KILL_SWITCH_FILE` stops all mutation immediately; reads continue. |
| Audit log | Hash-chained append-only JSONL with pre/post images; denials logged too; `qradar-soar-audit verify`. |
| Fail closed | Unwritable audit log ⇒ refuse to start; a mid-session write failure refuses the mutation before SOAR is called. |
| Secret hygiene | `SecretStr`, a redacting log filter, sanitised errors, a startup self-test, `gitleaks` and a tree scanner in CI; a sentinel-leak test drives every tool through every failure class. |
| HTTP transport | Refuses to start without `SOAR_HTTP_AUTH_TOKEN`; refuses `0.0.0.0` without `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE`; Tier ≥3 is hard-disabled over HTTP regardless of flags. |

The threat model, including what these controls do **not** protect against, is
in [docs/threat-model.md](docs/threat-model.md). Key rotation is in
[docs/runbooks/key-rotation.md](docs/runbooks/key-rotation.md). Report
vulnerabilities per [SECURITY.md](SECURITY.md).

---

## Configuration reference

All variables, with defaults. `.env.example` is the annotated copy.

| Variable | Default | Meaning |
|---|---|---|
| `SOAR_BASE_URL` | — | `https://` URL of the appliance (plain `http://` only on loopback) |
| `SOAR_ORG_ID` | — | organisation id (unparseable ⇒ connection disabled, with a warning) |
| `SOAR_API_KEY_ID` / `SOAR_API_KEY_SECRET` | — | API key (Basic auth) |
| `SOAR_VERIFY_SSL` | `true` | TLS verification. `false` is lab-only and refused without `SOAR_LAB_MODE=true`. Anything unrecognised refuses to start. (A CA-bundle path is still accepted here, deprecated.) See [TLS trust](#tls-trust) |
| `SOAR_CA_BUNDLE` | — | PEM CA bundle for a private or self-signed CA. Empty ⇒ Python's default TLS trust configuration; set ⇒ the supplied bundle is used instead of it. Missing or not PEM ⇒ refuses to start |
| `SOAR_TIMEOUT` | `30` | request timeout, seconds |
| `SOAR_MAX_RESULTS` | `50` | page-size cap for search and for similar-incident candidates (max 500) |
| `SOAR_ALLOW_COMMENTS` / `SOAR_ALLOW_ARTIFACTS` | `false` | Tier 1 |
| `SOAR_ALLOW_INCIDENT_WRITES` / `SOAR_ALLOW_TASK_WRITES` / `SOAR_ALLOW_INCIDENT_CLOSE` | `false` | Tier 2 |
| `SOAR_ALLOW_ACTIONS` / `SOAR_ALLOW_DESTRUCTIVE_ACTIONS` | `false` | Tier 3 |
| `SOAR_ACTION_POLICY_FILE` | `./config/action_policy.yaml` | required to exist when `SOAR_ALLOW_ACTIONS=true` |
| `SOAR_ALLOW_PLAYBOOK_DRAFT` / `_EXPORT` / `_CREATE` / `_MODIFY` / `_DEPLOY` / `_ENABLE` | `false` | Tier 4; accepted, no tools use them yet |
| `SOAR_PLAYBOOK_EXPORT_DIR` | `out/playbooks` | reserved for Phase 4 |
| `SOAR_ALLOW_SCRIPT_WRITES` | `false` | reserved; `true` refuses to start |
| `SOAR_APPROVAL_MODE` | `out_of_band` | `out_of_band` \| `in_band` \| `disabled` (the latter two need `SOAR_LAB_MODE=true`) |
| `SOAR_REQUIRE_ACTION_CONFIRMATION` / `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION` | `true` | safety switches; garbage resolves to `true` |
| `SOAR_APPROVAL_BROKER_PATH` | `approvals` | directory the model cannot reach |
| `SOAR_APPROVAL_PUBLIC_KEY_FILE` | — | Ed25519 public key; without it no approval can be verified |
| `SOAR_APPROVAL_TTL_SECONDS` | `900` | request and signature lifetime |
| `SOAR_MAX_MUTATIONS_PER_CALL` | `1` | clamped to 1 |
| `SOAR_MAX_TIER2_PER_HOUR` / `SOAR_MAX_TIER3_PER_HOUR` | `25` / `5` | sliding windows, persisted via the audit log |
| `SOAR_SIM_MAX_INCIDENTS` | `25` | reserved for Phase 3 |
| `SOAR_AUDIT_LOG_PATH` | `audit.jsonl` | hash-chained audit log |
| `SOAR_AUDIT_REQUIRED` | `true` | unwritable log ⇒ refuse to start |
| `SOAR_SNAPSHOT_DIR` | `snapshots` | reserved for Phase 4 |
| `SOAR_KILL_SWITCH_FILE` | `HALT` | exists ⇒ every Tier ≥1 call is denied |
| `SOAR_LOG_LEVEL` | `INFO` | stderr logging |
| `SOAR_CATALOG_SOURCE` / `SOAR_CATALOG_TTL_SECONDS` | `export` / `300` | reserved for Phase 2 |
| `SOAR_MCP_TRANSPORT` | `stdio` | `stdio` \| `streamable-http` |
| `SOAR_MCP_HOST` / `SOAR_MCP_PORT` | `127.0.0.1` / `8090` | HTTP bind |
| `SOAR_HTTP_AUTH_TOKEN` | — | required for HTTP; sent as `Authorization: Bearer` |
| `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE` | `false` | required to bind all interfaces |
| `SOAR_LAB_MODE` | `false` | lab acknowledgement: permits `in_band`/`disabled` approval and `SOAR_VERIFY_SSL=false`, each only when also set explicitly; never in production |
| `SOAR_ALLOW_WRITES` | — | **deprecated**; maps to the Tier 1–2 flags only and never to actions |

Command-line: `qradar-soar-mcp [--check] [--transport stdio|streamable-http]`,
`qradar-soar-approve {keygen,list,approve}`, `qradar-soar-audit verify [path]`.

---

## SOAR API behaviours this client relies on

Confidence marks follow `docs/design/05-SOAR-API-SURFACE.md`: ✅ documented
and long-stable, encoded in the offline contract suite, **not yet verified by
this repository against a live appliance**; ⚠️/❓ open, listed in
[docs/open-questions.md](docs/open-questions.md) and not used.

1. ✅ `handle_format=names` and `text_content_output_format=always_text` on
   every request — ids become labels, rich text is flattened.
2. ✅ `PATCH /incidents/{id}` is optimistic concurrency, not a merge: `version`
   plus `old_value`/`new_value` per field; an HTTP-200 `success: false` is
   raised as `patch_rejected`, never swallowed.
3. ✅ Custom fields live under `properties.<name>` (bare name in a PATCH,
   `properties.<name>` in a filter).
4. ✅ Listing is `POST /incidents/query_paged?return_level=normal`; conditions
   inside one filter are ANDed, separate filters are ORed; `plan_status` is
   `"A"` active / `"C"` closed.
5. ✅ Closing sends `plan_status` + `resolution_id` + `resolution_summary`
   together and SOAR rejects it if a close-required custom field is empty.
6. ❓ Task status changes are **not sent at all**. QRadar SOAR 51.0.9 documents
   `PUT /tasks/{id}` for them (it has no `PATCH` there, and tasks carry no
   version), but the `PUT` request body is unverified and is not guessed, so
   `soar_update_task_status` refuses every call until it is verified.
7. ✅ Manual actions are read from the `actions` list the incident object
   carries (`GET /incidents/{id}`); `GET /incidents/{id}/actions` answers 500
   on 51.0.9 and is not used. ❓ The shape of the list's entries is unverified,
   so only `id` and `name` are used and anything else fails closed. ❓ Invocation
   is unverified, so `soar_invoke_action` refuses every call before approval
   or any request.
8. ✅ `GET /rest/session` may be forbidden to API keys; `--check` reports that
   and does not fail on it.
9. ⚠️ Attachment contents (`…/attachments/{aid}/contents`) are not fetched;
   metadata only. ❓ Artifact hits, incident history and every Phase-2 discovery
   endpoint are not used.

### Confidence in API claims

The REST surface `client/` may touch is exactly the set of calls listed in
`docs/design/08-GREENFIELD-AMENDMENTS.md §4`, enforced by an AST test. Nothing
else is called. When the maintainer's lab access is available (Phase 2,
ticket `P2-00`), every ✅ above is re-verified against a real appliance and
`docs/soar-api-verified.md` records the sanitised evidence.

---

## Known limitations

- No live-appliance verification yet (see above).
- `soar_find_similar_incidents` is an N+1 client-side composition over the
  most recent `SOAR_MAX_RESULTS` incidents, not a server-side search.
- No manual action can be invoked: `soar_invoke_action` refuses every call as
  `DENY_UNSUPPORTED` until SOAR's invocation contract is verified.
- No task can be opened or closed: `soar_update_task_status` refuses every call
  as `DENY_UNSUPPORTED` until the request body of SOAR's `PUT /tasks/{id}` is
  verified. Both refusals are audited as denials and send nothing to SOAR.
- `soar_list_incident_actions` lists the incident's own actions, not those its
  tasks and artifacts carry.
- Attachment contents are never read; there is no text extraction.
- No playbook tools; the Tier-4 flags are accepted and unused.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Investigation + controlled actions + security architecture | **this release, v0.2.0** |
| 2 | Verify the API surface against a lab; playbook/rule/workflow/function discovery | planned |
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

## License

Apache-2.0. See [LICENSE](LICENSE).
