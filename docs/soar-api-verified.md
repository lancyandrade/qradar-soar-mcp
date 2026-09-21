# SOAR API — verified record (tickets P2-00 and P2-00b)

> **Scope. Every statement here is about one appliance: IBM QRadar SOAR
> `51.0.9.0.20848`, probed on 2026-09-18 (`P2-00`) and again from 2026-09-19 to
> 2026-09-21 (`P2-00b`).** The server reported exactly that version
> (`GET /rest/const`) each time. Nothing below is a claim about any other version;
> IBM's configuration API has changed shape across releases.

This is the authoritative record for that version. It supersedes the ⚠️/❓ marks
in [`design/05-SOAR-API-SURFACE.md`](design/05-SOAR-API-SURFACE.md), whose
original research text is kept unchanged as history.

## How the evidence was gathered

| | |
|---|---|
| Credential | A **read-only** API key. Its own permission set turned out not to be readable (see Q6), so "read-only" rests on the operator's key configuration plus the denials recorded here. Capability was never tested by attempting a write. |
| Methods | `GET`, plus three `POST`s that are read-only in effect and were approved by the owner for this research: `incidents/query_paged`, `playbooks/query_paged` (criteria-only bodies, enforced key by key) and one `configurations/exports` attempt. No `PUT`, `PATCH` or `DELETE` was issued. Nothing was refused by the probe's policy because nothing outside it was attempted. |
| Volume | 95 requests in the main pass (34 of them static on-box documentation pages), 3 for the export attempt. Every query asked for one row, except one 10-row id query for the attachment hunt. |
| TLS | Verified: a supplied CA bundle with normal host-name validation. The lab-only pinned mode was never used. See §6. |
| What is stored | **Shapes, not values**: key names, JSON types, status codes, size buckets, booleans. No host, address, org id, object id, user, incident or artifact content. Evidence: [`tests/fixtures/soar/verified/`](../tests/fixtures/soar/verified/) (64 files, each passed `scripts/probe/sanitise.py`), with every request in `_ledger.json`. |
| Tooling | [`scripts/probe/`](../scripts/probe/README.md). Not part of the installed package. |

### P2-00b (2026-09-19 to 2026-09-21)

`P2-00b` closed what `P2-00` had to leave open. It is marked `P2-00b` wherever it
adds to the record below; §3.1 is entirely its work.

| | |
|---|---|
| Reads | The same read-only key, `GET` plus the `query_paged` `POST`s already approved, and **one** owner-approved `POST /playbooks/execution/query_paged` with the exact body `{"filters": [], "start": 0, "length": 1}`. Every search was bounded: at most 10 incidents, pages of at most 10. |
| The appliance's own reference | Read as evidence for request bodies that must not be sent blind: the HTML reference under `/docs/rest-api/` and the Swagger 2.0 description published beside it at `/docs/rest-api/ui/swagger.json` (not linked from the index). Only type names, property names, JSON types, response codes and two flags ("read-only", "create-only") are stored; no prose. |
| Browser observation | The owner watched the web UI change a disposable task and piped **only the request payload** through an offline reducer ([`shape_request.py`](../scripts/probe/shape_request.py)) that keeps key names, JSON types and a few state facts. No cookie, token, header dump, HAR or URL was ever given to the tooling. |
| Writes | **Four `PUT /tasks/{task_id}` requests in total**, in two owner-authorised controlled experiments on one owner-designated disposable custom task of a disposable lab appliance: close then reopen, twice (§3.1). Each experiment was capped at 9 requests, never retried anything, and restored the task. No other write, no `DELETE`, no other `POST`. The read-only probe client still refuses every `PUT`; only [`task_experiment.py`](../scripts/probe/task_experiment.py) can send one. |
| Credential for the writes | An existing lab API key. The experiments ran only once the task's own `perms` map reported `read`, `write` and `close` true for that key (§3.1). This is research access to a test bed and changes nothing about the product's least-privilege model. |
| TLS | Verified only: the CA bundle and normal host-name validation. `P2-00b` never opens an unverified connection, not even to describe the certificate. |
| What is stored | 58 more shape-only files, `p2_00b_*.json`, and `_ledger_00b.json`, all passed by the same verifier. Object ids, the incident phase, timestamps, names and text stayed in memory. |

**How far each `P2-00b` finding goes.** "Verified" below always means *seen live on this
appliance*; a documented finding was read in the appliance's reference and **not**
exercised.

| Status | Findings |
|---|---|
| ✅ Verified experimentally | The task-status `PUT` contract and the documented `GET /tasks/{task_id}` as its source (§3.1); the server's handling of `closed_date`; the `StatusDTO`-compatible success response; attachment content for one attachment (Q7); the execution-query route and its wrapper, with zero rows (Q8); a note row carrying `children` and `parent_id`; the task tree's representation of a task (provenance only). |
| 📄 Documented by the appliance, **not** seen live | The filter logic defaults (`ALL` within a filter, `ANY` across filters); the entry shape of a carried `actions` list (`ActionInfoDTO`); the invoke data types and the one e-mail endpoint that uses them; the execution detail and activity types; the meaning of the `write` and `close` flags of a task's `perms` map; the documented read-only and create-only `TaskDTO` properties. |
| ❓ Unresolved | How a reply to a note is nested; the workflow object; the row shape of an execution and whether function results are retrievable; export contents; action invocation for incidents, tasks and artifacts; conflict (`409`) behaviour; what closing the last required task of a phase does. |

An earlier pass with a different key was halted when that key proved to be
broader than read-only; its output was deleted and is not evidence here. Two
observations from it are mentioned below where useful, and are labelled as such.

**Legend.** ✅ verified live on this version (status and shape) · 📄 documented
by the appliance's own API reference (`/docs/rest-api/`) but **not exercised**,
because it needs a write or a `POST` outside the approved set · 🚫 verified not
to work as assumed · ❓ unresolved.

All paths are relative to `/rest/orgs/{org_id}` unless they start with `/rest/`.

---

## 1. The eight priority questions

### Q1. Playbooks as a REST collection — ✅ yes, by query; 🚫 no `GET` collection

| Request | Result |
|---|---|
| `POST /playbooks/query_paged?return_level=normal`, body `{"filters": [], "start": 0, "length": 1}` | ✅ **200**. `{data: [...], recordsTotal: int, recordsFiltered: int}`. Paging is `start` / `length`. |
| `GET /playbooks/{playbook_id}` | ✅ **200**. The list row plus `content`, `activation_details`, `field_type_handle`. |
| `GET /playbooks` | 🚫 **500** `Internal Server Error`. The reference documents only `POST /playbooks` (create) on this path. |
| `GET /playbooks/query_paged` | 🚫 **404** "Unable to find Playbook with ID query_paged": a `GET` treats the segment as a handle. |
| `GET /playbooks/{playbook_id}/schema`, `…/inputs/schema` | ✅ **200**, JSON-Schema-like (`title`, `type`, `description`, `properties`). |
| `GET /playbooks/{playbook_id}/manual_input_form` | **403** `Forbidden` for this key. |
| `GET /playbooks/utility_functions` | ✅ **200**, `{entities: [...]}`. |

Playbook row (21 keys): `activation_type`, `create_date`, `creator_principal`,
`deployment_id`, `description`, `display_name`, `has_logical_errors`, `id`,
`is_deleted`, `is_locked`, `last_modified_principal`, `last_modified_time`,
`name`, `object_type`, `playbook_change_log_info`, `status`, `tag`, `tags`,
`type`, `uuid`, `version`. The single object adds
`content: {content_version: int, xml: str}` and
`activation_details.activation_conditions: {logic_type, conditions: [{field_name, method, value, type, evaluation_id}]}`.
Enum values seen: `status` = `enabled`; `activation_type` = `automatic`;
`object_type` = `incident`.

**Design impact.** `soar_list_playbooks` = `POST /playbooks/query_paged`;
`soar_get_playbook` = `GET /playbooks/{id}`, which already returns the playbook
XML. The decompiler (`03`) can therefore read a playbook without any export.
The activation conditions use the same `field_name` / `method` / `value`
vocabulary as incident queries.

### Q2. Full configuration export — 🚫 not available to a read-only key

| Request | Result |
|---|---|
| `POST /configurations/exports`, body `{"layouts": true, "actions": true, "phases_and_tasks": true}` — **sent once** | 🚫 **403** `Forbidden` |
| `GET /configurations/exports/history` (requested before and after the attempt) | **403** `Forbidden` both times |
| `GET /configurations/exports/{export_id}` | not reachable: no id obtainable |

The export request was rejected with HTTP 403. No export response or other
evidence of an export being created was observed. Export-history state could
not be independently compared, because the read-only credential also receives
HTTP 403 from the history endpoint. This record therefore makes **no claim**
about whether an export has side effects, and the contents of an export are
**unverified** on this version. (In the halted earlier pass, with a broader
key, the history endpoint answered 200 with a `histories` wrapper; the export
itself was never sent with that key.)

📄 Documented: `POST /configurations/exports`, `POST /configurations/exports/zip`,
`GET|POST /configurations/exports/{export_id}`,
`GET /configurations/exports/history`.

**Design impact — this reverses `05 §2.1`.** The export cannot be the default
catalog backend: it needs a permission a read-only key does not have, and the
recommended deployment gives the default instance a read-only key. The
**`collections` backend becomes the dependency and `export` the optional one.**
Read-only, the collections work: functions (with input fields), rules
(`/actions`), scripts, message destinations, incident types, phases, types
(data tables included), field definitions, playbooks, groups and users.

### Q3. Single-playbook export — 📄 documented, as a `POST`; not exercised

The reference lists `POST /playbooks/exports` and
`POST /playbooks/exports/{export_id}`, and a playbook-scoped import pair:
`POST /playbooks/imports` and `PUT /playbooks/imports/{import_id}/status`.
None is a `GET` and none was in the approved set, so none was called. There is
no `GET` export: `GET /playbooks/exports` resolves `exports` as a playbook
handle.

**Design impact.** Reading does not need export (Q1). For Phase 4 there is a
playbook-scoped import that is separate from `/configurations/imports`; whether
it has the same PENDING → ACCEPTED shape must be established by `P4-00`/`P4-01`
with an appropriately privileged key in a disposable org.

### Q4. Data-table discovery — ✅ `GET /types`, discriminator `type_id == 8`

`GET /types` → **200**: a map **keyed by type name**. Every type has the same 16
keys (`actions`, `display_name`, `fields`, `for_actions`, `for_custom_fields`,
`for_notifications`, `for_workflows`, `id`, `parent_types`, `playbooks`,
`properties`, `scripts`, `tags`, `type_id`, `type_name`, `uuid`). `type_id` 8 is
the only value shared by more than one type, and every such type has a
non-empty `parent_types`. `fields` is a map keyed by field name.

`GET /types/{type}`, `GET /types/{type}/fields`, `GET /types/{type}/schema` →
✅ **200** for a data-table type. `GET /incidents/{incident_id}/table_data` →
✅ **200** (empty for the sampled incident). 📄 `GET …/table_data/{table_id}` and
the row endpoints are documented; not exercised (no table with rows).

**Design impact.** `soar_list_datatables` = filter `GET /types` on
`type_id == 8`. There is no `/datatables` collection.

### Q5. Function input definitions — ✅ available, no special parameter

`GET /functions` → **200** `{entities: [...]}`; `GET /functions/{function_id}` →
**200** with `view_items: [{content, element, field_type, show_if, step_label, show_link_header}]`.
`GET /types/__function/fields` → **200**: a list of field definitions with
`name`, `input_type`, `required` (optional key), `values`, `tooltip`,
`placeholder`, `uuid`. **Every `view_items[].content` of the sampled function
resolved to a `__function` field `uuid` (37 of 37).** Input types seen:
`boolean`, `multiselect`, `number`, `select`, `text`, `textarea`.

The function object also carries `output_json_schema`, `output_json_example`
and `output_description`.

**Design impact.** Phase-3 L3 validation is feasible read-only: join
`view_items.content` to `/types/__function/fields` by `uuid`. No `view=full`
equivalent is needed.

### Q6. The key's own permission set — 🚫 not readable by a read-only key

| Request | Result |
|---|---|
| `GET /rest/session` | ✅ **200** for an API key on this version, but `orgs[].perms` is `null` and `effective_permissions` / `role_handles` are empty. |
| `GET /rest/session/{org_id}/acl` | ✅ **200**, same shape, same empty permission data. |
| `GET /permissions` | **403** |
| `GET /apikeys` | **403** |

(Observation from the halted pass, not committed evidence: a key allowed to
administer API keys gets **200** from `GET /apikeys`, and each entry lists that
key's permissions. So introspection exists, but only for exactly the kind of key
this project should never be given.)

**Fallback, as built:** a harmless-read capability map. The ledger of this run
*is* that map. Reads denied to this key: `permissions`, `apikeys`,
`configurations/exports/history`, `playbooks/{id}/manual_input_form`.
Everything else in §2 returned 200.

**Design impact.** The startup probe of `01 §6` can only be the read map, and a
read map **cannot prove the absence of write permission**. The README must keep
saying that the SOAR permission set is the operator's control. `L5` validation
can check "can this key read what the playbook needs", not "is this key unable
to do harm".

### Q7. Attachment content — ✅ verified for one attachment (`P2-00b`)

📄 `GET /incidents/{inc_id}/attachments/{attach_id}/contents`, the single
metadata read `GET …/attachments/{attach_id}`, the task equivalents under
`/tasks/{task_id}/attachments/…`, and `GET …/artifacts/{artifact_id}/contents`.

Not exercised: the read-only query returned one incident (ceiling: 10), and
neither it nor its first task has an attachment. `GET …/attachments` and
`GET /tasks/{task_id}/attachments` → ✅ **200**, empty lists. The probe requests
the content endpoint for status and headers only and never reads a body.

**`P2-00b`, on an owner-designated disposable incident with one attachment:**

| Request | Result |
|---|---|
| `GET /incidents/{incident_id}/attachments` | ✅ **200**, a bare list. |
| `GET /incidents/{incident_id}/attachments/{attachment_id}` | ✅ **200**, 23 keys, among them `content_type`, `size`, `type`, `name`, `created`, `creator_id`, `inc_id`, `task_id`, `uuid`, `vers`. |
| `GET /incidents/{incident_id}/attachments/{attachment_id}/contents` | ✅ **200**, `Content-Type: text/plain` (the attachment's own media type, not JSON), `Content-Length` present, `Content-Disposition` present, not chunked. |

Only the status and headers of the content request were read: the stream was closed
without reading the body, and nothing was hashed or stored. One attachment of one type
is the whole evidence; other media types and large files are untested.

### Q8. Incident history and past function results — ✅ history exists; 🚫 no function results in it

| Request | Result |
|---|---|
| `GET /incidents/{incident_id}/history` | ✅ **200**: `artifact_history`, `attachment_history`, `data_type_history`, `incident_detail_history`, `milestone_history`, `record_count_history`, `task_history`. No result-like key anywhere. |
| `GET /incidents/{incident_id}/newsfeed` | ✅ **200**: rows of `entry_type`, `object_type`, `object_id`, `before`, `after`, `principal`, `timestamp`, … No function output. |
| `GET /artifacts/{artifact_id}/history` | ✅ **200**, newsfeed-like rows. |
| `GET /incidents/{incident_id}/workflow_instances` | ✅ **200** `{entities: []}` (none here). |
| `GET /playbooks/execution/statistics` | ✅ **200**: counts per `status` (`canceled`, `completed`, `error`, `running`, `suspended`). |

**`P2-00b`.** The reference documents `POST /playbooks/execution/query_paged` as a query
for playbook execution details whose body is the same `QueryPagedDTO` that
`incidents/query_paged` takes (filters, sorts, paging). Sent once, with the owner's
approval and the body `{"filters": [], "start": 0, "length": 1}`: ✅ **200**,
`{data, recordsFiltered, recordsTotal}`, **zero rows** — the appliance has recorded no
playbook execution (`GET /playbooks/execution/statistics` agrees). The route and the
wrapper are verified; the row shape is not. 📄 The documented detail and activity types
(`PlaybookExecutionDetailDTO`, `PlaybookExecutionActivityStatusDTO`) carry a status,
times and status messages, and no function output.

📄 Still not exercised: `POST /playbooks/execution/{execution_id}/activities`
(unapproved, and there is no execution to ask about),
`POST /workflow_instances/{inc_id}/query_paged`, and
`GET /playbooks/execution/{execution_id}/playbook`.

**Design impact.** The "recorded" mocking strategy of `04 §3.3` has no source in
the history endpoints on this version. Default the simulator to
**schema-generated mocks from `output_json_schema` / `output_json_example`**,
which the function object does expose (Q5). Whether playbook-execution
activities expose real results is still ❓: it needs an appliance that has run a
playbook, and the `…/activities` `POST`, which is not approved.

---

## 2. Request ledger

Default query parameters on every request: `handle_format=names`,
`text_content_output_format=always_text`, unless noted. Fixture = file name in
`tests/fixtures/soar/verified/` without `.json`.

| Method | Path | Status | Fixture |
|---|---|---|---|
| GET | `/rest/const` | 200 | `const` |
| GET | `/rest/session` | 200 | `session` |
| GET | `/rest/session/{org_id}/acl` | 200 | `session_acl` |
| GET | `/` (the org) | 200 | `org` |
| GET | `/permissions` | **403** | `permissions` |
| GET | `/apikeys` | **403** | `apikeys` |
| GET | `/playbooks` | **500** | `playbooks` |
| POST | `/playbooks/query_paged?return_level=normal` | 200 | `playbooks_query_paged` |
| GET | `/playbooks/query_paged` | **404** | `playbooks_query_paged_via_get` |
| GET | `/playbooks/{playbook_id}` | 200 | `playbook` |
| GET | `/playbooks/{playbook_id}/schema` | 200 | `playbook_schema` |
| GET | `/playbooks/{playbook_id}/inputs/schema` | 200 | `playbook_inputs_schema` |
| GET | `/playbooks/{playbook_id}/manual_input_form` | **403** | `playbook_manual_input_form` |
| GET | `/playbooks/utility_functions` | 200 | `playbook_utility_functions` |
| GET | `/playbooks/execution/statistics` | 200 | `playbook_execution_statistics` |
| GET | `/configurations/exports/history` | **403** | `export_history`, `export_history_after` |
| POST | `/configurations/exports` | **403** | `export` |
| GET | `/types` | 200 | `types` |
| GET | `/types/{datatable_type}` · `/fields` · `/schema` | 200 | `datatable_type`, `datatable_fields`, `datatable_schema` |
| GET | `/types/__function/fields` | 200 | `function_fields` |
| GET | `/types/incident/fields` · `/types/task/fields` · `/types/artifact/fields` | 200 | `fields_incident`, `fields_task`, `fields_artifact` |
| GET | `/functions` · `/functions/{function_id}` | 200 | `functions`, `function` |
| GET | `/actions` · `/actions/{action_id}` · `/actions/{action_id}/view` | 200 | `actions`, `action`, `action_view` |
| GET | `/workflows` | 200 (0 rows) | `workflows` |
| GET | `/scripts` · `/scripts/{script_id}` | 200 | `scripts`, `script` |
| GET | `/message_destinations` · `/incident_types` · `/phases` · `/groups` · `/users` | 200 | same names |
| POST | `/incidents/query_paged?return_level=normal` | 200 | `incidents_query_paged` |
| POST | `/incidents/query_paged` (no `return_level`) | 200 | `query_no_return_level` |
| POST | `/incidents/query_paged` with `plan_status` filters and a `create_date` sort | 200 | `query_active`, `query_closed`, `query_and`, `query_or`, `query_sorted` |
| GET | `/incidents/{incident_id}` (names · `handle_format=ids` · no parameters) | 200 | `incident`, `incident_handle_format_ids`, `incident_no_params` |
| GET | `/incidents/{incident_id}/tasks` · `/tasks/{task_id}` | 200 | `tasks`, `task` |
| GET | `/incidents/{incident_id}/comments` | 200 (0 rows) | `comments` |
| GET | `/incidents/{incident_id}/artifacts` · `/artifacts/{artifact_id}/history` | 200 | `artifacts`, `artifact_history` |
| GET | `/incidents/{incident_id}/actions` | **500** | `incident_actions` |
| GET | `/incidents/{incident_id}/action_invocations` | 200 (0 rows) | `incident_action_invocations` |
| GET | `/incidents/{incident_id}/table_data` | 200 (empty) | `table_data` |
| GET | `/incidents/{incident_id}/history` · `/newsfeed` · `/workflow_instances` | 200 | `history`, `newsfeed`, `workflow_instances` |
| GET | `/incidents/{incident_id}/attachments` · `/tasks/{task_id}/attachments` | 200 (0 rows) | `attachment_scan`, `task_attachments` |
| GET | `/docs/rest-api/index.html` + 33 resource pages | 200 | `_ledger` → `documented_endpoints` (290 method/path pairs) |

Skipped for lack of an object: `GET /workflows/{workflow_id}` (no workflows in
this org), both attachment-content reads, `GET /configurations/exports/{export_id}`.

Collection wrappers differ: `entities` for functions, actions, workflows,
scripts, message destinations, phases, utility functions, action invocations,
workflow instances; a bare list for users, groups, artifacts, tasks, field
definitions, attachments; `data` + `recordsTotal` + `recordsFiltered` for
`query_paged`; a name-keyed map for `/types` and `/incident_types`.

---

## 3. Phase-1 assumptions against this version

**Research findings only. No application code was changed.** Correction is the
separate ticket `P1-CORR-01` (§8) and must wait for this report to be reviewed.

### Contradicted

| # | Phase-1 assumption (`05 §1`, `08 §4`) | Evidence on 51.0.9.0.20848 | Consequence today |
|---|---|---|---|
| D1 | Task status is changed with `PATCH /tasks/{id}` ("PATCH, not PUT") | 📄 The reference documents `GET`, `PUT` and `DELETE` on `/tasks/{task_id}`; **no `PATCH`**. It does document `PATCH` for incidents, so the omission is not a gap in the reference. ✅ **`P2-00b` verified the `PUT` contract live: §3.1.** | `soar_update_task_status` stays disabled until the verified contract is implemented (`P1-CORR-02`, §8). |
| D2 | A task carries a version (`vers`) for optimistic concurrency | ✅ Neither the rows of `GET /incidents/{id}/tasks` nor `GET /tasks/{task_id}` contain `vers` or any version-like key (41 keys checked). | The client refuses to send a task change without a version, so the tool refuses every time. It fails closed. |
| D3 | `GET /incidents/{id}/actions` lists the manual actions of an incident | 🚫 **500** `Internal Server Error`, and the path is absent from the reference. | `soar_list_incident_actions` fails; `soar_invoke_action` cannot classify its target, so it refuses. It fails closed. |
| D4 | `POST /incidents/{id}/action_invocations` with `{"action_id": N}` invokes an action | The path is absent from the reference. A **`GET` on it returns 200** `{entities: []}`, so the route exists; the `POST` and its body are unverified (a write). The incident, task and artifact objects each carry an `actions` list (empty for this key). | The invocation design needs re-verification before it can be relied on: where the list of available actions really comes from, and the exact invocation contract. |

None of these weakens a control: each makes a tool fail, never succeed wrongly.

### 3.1 Task status change — the verified contract (`P2-00b`, D1)

**Two conclusions, kept apart.**

**A. The `PUT` contract — ✅ verified experimentally**, for this version, one custom
task and one API-key configuration:

| | |
|---|---|
| Request | `PUT /rest/orgs/{org_id}/tasks/{task_id}`, HTTP Basic with an API key, no query string, and the two format controls as headers: `handle_format: ids`, `text_content_output_format: objects_convert`. 📄 The reference documents the body as a `TaskDTO` and the two controls as usable in the query string or as headers. |
| Body | The **full task object**, 41 keys, exactly as a fresh read returned it, with **`status` as the only deliberate change**. It includes every property the reference calls read-only, the create-only `private`, and four keys the reference does not document (`auto_deactivate`, `form`, `task_layout`, `user_notes`). That is also what the web UI was observed to send. |
| Version | **No version field was observed or required in this experiment.** No version, lock or token key appeared in the documented `TaskDTO`, in the live object or in the UI's request. 📄 The `409` "Conflicting PUT" response code is boilerplate: the reference lists it for the `GET` and `DELETE` sections too. A conflict was never observed. |
| Response | **200**, `{success, title, message, hints}` with `success: true` — a subset of the documented `StatusDTO` (`success`, `title`, `message`, `hints`, `error_code`, `error_payload`). |
| `closed_date` | **Server state.** Close: the request carries `closed_date: null`; afterwards the server has set it. Reopen: the request passes the existing value through unchanged; afterwards the server has cleared it. The client never sets, clears or invents it. |
| Result | Close: a fresh read shows `status: "C"`, `closed_date` non-null, the same 41 keys; the only field names that changed are `status` and `closed_date`. Reopen: `status: "O"`, `closed_date` null, and **no field differs from the baseline**. The incident's `phase_id` did not change at any point. |

**B. The source representation — ✅ the documented `GET /tasks/{task_id}` is
round-trippable as it is**, for the same test case. The task was read with
`GET /tasks/{task_id}` (same two format headers), deep-copied, `status` changed, and sent
back; then read again, and the same to reopen. In that representation `task_layout` is an
**empty list**, and it was passed through **unchanged**, both times; after each `PUT` the
documented `GET` still returned an empty list.

So, on this evidence, a client needs only documented endpoints:

```
GET /tasks/{task_id}  →  deep copy  →  change status only  →  PUT /tasks/{task_id}  →  GET to verify
```

and does **not** need the undocumented task tree, any `task_layout` normalisation, a
client-generated `closed_date`, or a version field (none was observed or required in this experiment).

**The task tree (provenance only).** The web UI does not read the task with
`GET /tasks/{task_id}`; it reads `GET /incidents/{incident_id}/tasktree`, in which the same
task has `task_layout: null` — which is why the UI's own `PUT` bodies carry `null` where
the documented `GET` gives `[]`. The first controlled experiment used that representation
and also succeeded. **`tasktree` appears nowhere in the appliance's reference or its
Swagger description (0 of 279 paths): it is UI-internal and undocumented.** It helped the
research; it is not a supported API as far as this record can tell, the recommended
design does not use it, and it is not part of this project's API surface.

**Permissions — what was observed, and no more.** 📄 The reference describes a task's
`perms` map (`TaskPermsDTO`, from `ObjectPermsDTO`) as the permissions of the caller on
that task: `write` is whether the caller may write to the object, `close` whether the
caller may close it. With the read-only key, the designated task reported `write` and
`close` as not both true, and no `PUT` was attempted: a refusal would have verified
nothing. After the owner enabled the key's task-edit capability in the appliance, the same
map reported `read`, `write` and `close` true, and every `PUT` succeeded. Three different
things are in play — the key's configuration, the object's flags, and the outcome of a
`PUT` — and this record observed them agreeing once. It does **not** establish a minimal
permission set, nor that the flags decide the `PUT` on their own.

**Limited evidence, still open.**

- One custom task, one appliance version, one API-key configuration.
- A conflict (`409`) was never observed, so what protects a task against a concurrent
  edit is still unknown; the full-object body makes a lost update possible in principle.
- The task reported `required: true`. IBM's product guide ties a *mandatory* task to
  the incident entering its next phase; whether the API's `required` is that flag is not
  stated anywhere, the phase did not move here, and closing the last required task of a
  phase was **not** tested.
- Whether the UI changes any value other than `status` is unknown: the observation
  records structure, not values. Passing every other value through is the conservative
  reading, and it worked.
- Early in the research the same task's `perms` map read differently in two runs an hour
  apart; that discrepancy was never explained.

Evidence: `p2_00b_task_experiment.json` (task-tree source),
`p2_00b_task_experiment_documented.json` (documented source), `p2_00b_ui_request_close.json`,
`p2_00b_ui_request_reopen.json`, `p2_00b_ui_request_pair.json`, `p2_00b_doc_task_put.json`,
`p2_00b_doc_type_TaskDTO.json`, `p2_00b_doc_swagger_task_put.json`,
`p2_00b_tasktree_task.json`, `p2_00b_designated_task_ui_formats.json`,
`p2_00b_preflight_close.json`.

**D3 and D4 after `P2-00b`.** 📄 The reference documents the carried `actions` list as
`ActionInfoDTO` — `id` (number), `name` (string), `enabled` (boolean) — "available to the
caller", which is consistent with the `id` + `name` reader of `P1-CORR-01`; ❓ every
carried list was still empty for the research keys, so the entry shape is not verified
live. 📄 The reference defines `ActionInvokeDTO` (`action_id`, `properties`,
`type_id_handle`) and `MultipleActionInvokeDTO`, but a sweep of all 57 resource pages and
of the Swagger description finds them used by exactly one endpoint,
`POST /email/messages/action_invocations` (inbox e-mail messages). **No incident, task or
artifact invocation endpoint is documented**, and nothing was invoked. D4 stays
unresolved and `soar_invoke_action` stays disabled.

### Confirmed

- HTTP Basic with API key id/secret; both default query parameters accepted everywhere.
- `handle_format=names`: `severity_code`, `phase_id`, `owner_id`,
  `incident_type_ids` come back as **strings**; with `handle_format=ids` or no
  parameter they are **integers**. `plan_status` is a string (`"A"`) either way.
- `query_paged` returns `data`, `recordsTotal`, `recordsFiltered`.
  `return_level=normal` yields the full object including `properties`, `vers`
  and `perms`. **`return_level` is optional**: without it the row has 12 keys
  (`id`, `name`, `description`, `plan_status`, `phase_id`, `severity_code`,
  `owner_id`, `create_date`, `discovered_date`, `due_date`, `inc_training`,
  `sequence_code`). The offline fake is stricter than the appliance here.
- `create_date` is accepted as a sort field.
- All 16 fields of the Phase-1 incident projection exist; custom fields are
  under `properties`; the incident carries `vers`.
- `GET /users` works for a read-only key and has `id`, `display_name`, `fname`,
  `lname`, `email`, `status`. Artifacts have `id`, `type`, `value`,
  `description`, `created`, `hits`.
- Field definitions have `name`, `text`, `input_type`, `prefix`, `read_only`,
  `internal`, `values[{value, label, enabled, …}]` and an optional `required`.
- `GET /rest/session` is **not** denied to an API key on this version (it
  answers 200 with no permission data).
- 📄 `PATCH /incidents/{inc_id}`, `POST /incidents`, and `GET|POST` on comments
  and artifacts are documented as Phase 1 assumes.

### Not verifiable read-only, or not verified

- The PatchDTO shape, `success:false` on a stale version, and the close
  semantics (writes).
- AND-within / OR-across filter semantics: the queries ran and were consistent,
  but the research key sees **no closed incident**, so the check could not distinguish
  the two. ❓ live. 📄 `P2-00b`: the reference states it — a filter's `logic_type`
  defaults to `ALL` over its conditions, and the query's defaults to `ANY` over its
  filters.
- The effect of `text_content_output_format`: `description` was a plain string
  in all three variants.
- Comment threading: ✅ `P2-00b` saw a note row, with `children` (an empty list) and
  `parent_id` (null) among its 26 keys; ❓ no reply existed, so nesting was not observed.
- The workflow object (`content.xml`): the org has no workflows. ❓
- Attachment metadata keys: ✅ `P2-00b`, Q7.

---

## 4. Documented, not exercised (Phase 3–5 relevant)

From the on-box reference; **none was called**, each needs a write or an
unapproved `POST`. The full list is in `_ledger.json`.

| Area | Documented |
|---|---|
| Configuration import | `POST /configurations/imports`, `PUT /configurations/imports/{import_id}`, `PUT …/{import_id}/status`, `GET /configurations/imports/history` |
| Configuration push | `POST /configurations/push`, `GET /configurations/push/history[/{push_id}[/exports]]` |
| Playbook lifecycle | `POST /playbooks`, `PUT|DELETE /playbooks/{handle}`, `POST …/{handle}/clone`, `POST …/{handle}/change_logs/query_paged`, `POST /playbooks/exports[/{export_id}]`, `POST /playbooks/imports`, `PUT /playbooks/imports/{import_id}/status` |
| Enable / disable | No dedicated verb. The playbook object has `status` (`enabled` seen), so the mechanism is presumably `PUT /playbooks/{handle}`. ❓ Unverified; this is `P5-00`. |
| Playbook executions | `POST /playbooks/execution/query_paged`, `POST …/{execution_id}/activities`, `GET …/{execution_id}/playbook`, `PUT …/{execution_id}/status`, `POST …/cancel` |
| Similar incidents | `POST …/artifacts/{artifact_id}/related_incidents/query_paged`, `POST /artifacts/{artifact_id}/hits/query_paged`, `GET /incidents/{inc_id}/related_ex`; artifacts carry `related_incident_count` and `relating` |
| Other searches | `POST /incidents/{inc_id}/artifacts/query_paged`, `POST …/comments/query`, `POST …/attachments/query`, `POST /users/query_paged`, `POST /apikeys/query_paged` |

The two-phase import of `05 §3.2` is consistent with the reference: an import
is created by `POST`, then its `status` is set by `PUT`.

---

## 5. What a read-only key is denied

`GET /permissions` · `GET /apikeys` · `GET /configurations/exports/history` ·
`POST /configurations/exports` · `GET /playbooks/{id}/manual_input_form` → **403**.

Everything else in §2 → 200, including script bodies (`script_text`) and the
user list. A read-only key can therefore read automation *content*; Phase 2
tools that return scripts or playbook XML must project and cap them like any
other attacker-influenced text.

`500` means "no such `GET` route" on this version (`/playbooks`,
`/incidents/{id}/actions`), not a server fault: both bodies are the generic
error object with `Internal Server Error`.

---

## 6. TLS findings (generic)

- The appliance presents a **self-signed leaf** (RSA-2048, SHA-256), TLS 1.2.
  It is its own trust anchor; no private CA is involved.
- The certificate names a **DNS host only** — no IP entry in the SAN. Reaching
  the appliance by IP literal cannot verify, whatever is trusted.
- Default trust fails both ways: `httpx`'s `certifi` bundle (what the package
  uses today) and the operating-system store.
- Verification **succeeds** with the certificate supplied as a CA bundle **and**
  the certificate's host name in the URL. That is what this research used.

Implication for the package: `SOAR_VERIFY_SSL=<bundle>` works only if
`SOAR_BASE_URL` also uses the certificate's name. The README's advice to point
at the appliance CA is necessary but not sufficient for an appliance reached by
IP. See `P2-TLS` (§8).

---

## 7. Impact on the Phase 3–5 design

1. **Catalog (`P2-01`): make `collections` the default backend**; `export` is
   optional and needs a more privileged key (Q2). This reverses `05 §2.1`.
2. **Playbook discovery (`P2-04`)**: `POST /playbooks/query_paged` +
   `GET /playbooks/{id}`. The XML is in `content.xml`; no export is needed to
   read (Q1, Q3).
3. **Function validation (`P3-03`)**: feasible read-only via `view_items` →
   `/types/__function/fields` (Q5).
4. **Simulation mocks (`P3-06`)**: default to schema-generated mocks from
   `output_json_schema` / `output_json_example`; "recorded" results have no
   verified source (Q8).
5. **Data tables (`P2-02`)**: `GET /types`, `type_id == 8` (Q4).
6. **L5 / key capability**: a read map only; it cannot establish that a key is
   harmless (Q6).
7. **Import (`P4`)**: two candidates now exist — `/configurations/imports` and
   the playbook-scoped `/playbooks/imports`. Both are two-step per the
   reference. Which one Phase 4 uses is a `P4-00`/`P4-01` decision that needs a
   privileged key in a disposable org.
8. **Enable (`P5-00`)**: no dedicated endpoint is documented; still research.
9. **Workflows**: this org has none, so the workflow shape is unverified. On
   this version playbooks are clearly the primary automation object.

---

## 8. Proposed tickets (proposals only — not started)

### P1-CORR-01 — reconcile Phase-1 client semantics with the verified v51 API
> **Status, 2026-09-19:** addressed for D1–D4 only, from this record alone; see
> [`design/08-GREENFIELD-AMENDMENTS.md §21`](design/08-GREENFIELD-AMENDMENTS.md).
> D2 and D3 are resolved. For D1 that ticket had the endpoint and method
> (`PUT /tasks/{task_id}`) but not the request body, so it disabled the tool.
> **`P2-00b` has since supplied the missing contract evidence (§3.1);** the tool stays
> disabled until `P1-CORR-02` below implements it. D4 still fails closed. Of the live
> checks below, (a) is answered by §3.1, (b) is open, (c) was out of scope.

**Separate from P2-00. Not to be implemented until this report is reviewed.**
Scope: D1–D4 of §3. Establish, with a suitably scoped key in a disposable org,
(a) the real task-update contract (`PUT /tasks/{task_id}` with a full object?
what replaces the version check?), (b) the real source of an object's available
manual actions (the `actions` list on the incident/task/artifact object?) and
the exact invocation request, (c) whether `return_level` should be dropped from
searches that only need the 12-key row. Then amend `08 §4`, the offline fake,
the contract tests and the client together, keeping the policy classification
and approval gates exactly as they are. Until then `soar_update_task_status`,
`soar_list_incident_actions` and `soar_invoke_action` should be documented as
**not working on 51.0.9**.

### P2-TLS — portable TLS trust configuration
> **Status, 2026-09-19:** implemented; see
> [`design/08-GREENFIELD-AMENDMENTS.md §22`](design/08-GREENFIELD-AMENDMENTS.md).
> As built, the default trust source is Python's default TLS trust configuration
> (whatever `ssl.create_default_context()` exposes on the platform and Python
> build), not a union with `certifi` as proposed below. No host-name override was
> added: an appliance must be addressed by a name its certificate carries.

Verification on by default; system trust by default, evaluated against the
operating-system store as well as `certifi`; an optional user-supplied CA
bundle; an explicit, loudly warned verification-disabled override for labs
only; no bundled certificates; no assumption about host names or addresses.
Add a clear start-up diagnosis for the two failures seen here (self-signed /
unknown issuer, and "the certificate does not name the host in
`SOAR_BASE_URL`"), and document that an appliance whose certificate has no IP
entry must be addressed by name. Consider whether a host-name override is ever
safe to offer; this research did not need one.

### P2-00b — finish the record
> **Status, 2026-09-21:** done for what the lab could show. Verified: the task-status
> `PUT` contract and its documented source representation (§3.1), attachment content
> for one attachment (Q7), the execution-query route (Q8). Documented but not seen live:
> filter logic, the carried-action entry shape, comment nesting. Unchanged: the workflow
> object (the org has none), export contents (Q2), action invocation (D4).

With owner approval for each: an incident that has an attachment (Q7); one
`POST /playbooks/execution/query_paged` to see whether execution activities
expose function results (Q8); an org with a closed incident, notes and a
workflow (the ❓ items of §3); the export contents, with a key that may export,
in a disposable org (Q2).

### P1-CORR-02 — implement the verified task-status contract (proposal — not started)
**Separate from `P2-00b`, which changed no product code.** Re-enable
`soar_update_task_status` on the contract of §3.1, and nothing wider:

- read the task with the documented `GET /tasks/{task_id}`, immediately before the
  change, with `handle_format: ids` and `text_content_output_format: objects_convert`;
- deep-copy that fresh representation and change **`status` only**; send it with the
  documented `PUT /tasks/{task_id}` and the same two controls;
- no dependency on the undocumented task tree; no `task_layout` normalisation; no
  client-generated `closed_date`; no version field (none was observed or required in the
  experiment);
- keep the single mutation chokepoint and the existing order of flag, configuration,
  tier, transport, approval, rate limit and audit exactly as they are;
- fail closed on permissions: never assume an administrator key, and treat a refusal by
  SOAR as a refusal, with the usual sanitised error;
- verify with a fresh `GET` after the `PUT`, and define the behaviour for `success: false`,
  a non-2xx answer, a `409`, and a task whose state is not the one the change expects
  (already closed, inactive, frozen);
- state the residual lost-update risk of a full-object `PUT` without a version, and keep
  the read and the write adjacent;
- offline tests, and an offline fake, derived from the `P2-00b` fixtures; amend `08 §4`
  and the contract tests with the client;
- replace the refusal texts, docstrings and test comments in `src/` and `tests/` that
  still say the `PUT` body is unverified (`P2-00b` deliberately left them untouched).

---

## 9. Reproducing this

```bash
uv run python scripts/probe/selftest.py                       # offline, must print OK
uv run python scripts/probe/guarded.py tls_check.py           # TLS first
uv run python scripts/probe/guarded.py probe.py --no-docs --only session,apikeys   # is the key read-only?
uv run python scripts/probe/guarded.py probe.py               # the plan
uv run python scripts/probe/guarded.py probe.py --no-docs --with-export \
    --only export_history,export,export_history_after,export_by_id             # once
uv run python scripts/probe/sanitise.py --check "tests/fixtures/soar/verified/*.json"
uv run python scripts/check_no_secrets.py
```

`P2-00b` (verified TLS only; see the probe README for the browser observation):

```bash
uv run python scripts/probe/guarded.py probe_00b.py                       # every read step
uv run python scripts/probe/guarded.py probe_00b.py --designated          # owner-designated objects
uv run python scripts/probe/guarded.py task_experiment.py --source documented            # dry run
uv run python scripts/probe/guarded.py task_experiment.py --source documented --execute  # the experiment
```

The last line changes a task and restores it: it needs a disposable appliance, an
owner-designated disposable task and the owner's explicit approval.

Connection values come from a git-ignored `.env`; see
[`scripts/probe/README.md`](../scripts/probe/README.md).
