# Open questions

What this repository could not settle, and what `P2-00` settled. Nothing here is
implemented on a guess: each item is held back, implemented in the most
conservative documented form, or explicitly deferred.

**`P2-00` ran on 2026-09-18 against IBM QRadar SOAR `51.0.9.0.20848` with a
read-only API key; `P2-00b` finished the record on the same appliance between
2026-09-19 and 2026-09-21.** Their results are in
[`soar-api-verified.md`](soar-api-verified.md), which is authoritative for that
version and for no other. "Resolved" below always means *resolved for
51.0.9.0.20848*.

Marks: ✅ verified live · 📄 documented by the appliance, not exercised · 🚫
verified not to work as assumed · ⚠️ / ❓ still open.

## A. Raised during Phase 1 implementation

| # | Question | Outcome on 51.0.9.0.20848 | Where |
|---|---|---|---|
| Q1 | Does the task DTO in `GET /incidents/{id}/tasks` carry `vers`? | 🚫 **No.** Neither the list rows nor `GET /tasks/{task_id}` has any version key, and the appliance documents `PUT /tasks/{task_id}`, not `PATCH`. **Version question resolved by `P1-CORR-01`** (08 §21): nothing requires a task version and none is invented. ✅ **The task update contract is verified by `P2-00b`** (`soar-api-verified.md §3.1`): the documented `GET /tasks/{task_id}`, deep-copied, with `status` as the only change, sent with `PUT /tasks/{task_id}`, closed and reopened a disposable task with an API key; no version field was observed or required in this experiment, and `closed_date` is the server's. ✅ **Implemented by `P1-CORR-02`** (08 §24): `soar_update_task_status` follows exactly that contract and reads the task back to verify; built and tested offline, with no new live request. ❓ Still unknown: what protects a task against a concurrent edit (no `409` was ever seen; the full-object `PUT` makes a lost update possible in principle), what closing the last required task of a phase does, and any other SOAR version; the evidence is one custom task, one version, one key configuration. | `client/tasks.py` |
| Q2 | Filter syntax for an artifact-value search in `query_paged`? | ❓ Still open; no filter was guessed. 📄 The appliance documents dedicated reads instead: `POST …/artifacts/{artifact_id}/related_incidents/query_paged`, `GET /incidents/{inc_id}/related_ex`, and artifacts carry `related_incident_count`. Not exercised. | `tools/investigation.py` |
| Q3 | Is `create_date` accepted as a `sorts[].field_name`? | ✅ Yes (200). | `tools/investigation.py` |
| Q4 | How is an artifact-scoped manual action invoked? | ❓ Open, and wider than asked: `GET /incidents/{id}/actions` returns **500** and is undocumented; `action_invocations` is undocumented, though a `GET` on it returns 200. The incident, task and artifact objects each carry an `actions` list. Listing no longer uses the 500 route: `P1-CORR-01` reads the incident's own `actions` list. 📄 `P2-00b`: the reference documents its entries as `ActionInfoDTO` (`id`, `name`, `enabled`), consistent with that reader; ❓ every list was still empty for the research keys, so the shape is not verified live. ❓ **Invocation remains open** for every object type: the reference's invoke types (`ActionInvokeDTO`, `MultipleActionInvokeDTO`) are used by exactly one documented endpoint, for inbox e-mail messages, and nothing was invoked; `soar_invoke_action` refuses as `DENY_UNSUPPORTED` until a contract is verified (08 §21). | `tools/actions.py` |
| Q5 | Can the result of an invoked action be observed? | ❓ Open. `GET /incidents/{id}/action_invocations` returns `{entities: []}`; its row shape is unknown (none existed). | `client/actions.py` |
| Q6 | Which endpoint reports an API key's own permission set? | 🚫 **None that a read-only key can use.** `/rest/session` and `/rest/session/{org_id}/acl` answer 200 with empty permission data; `GET /permissions` and `GET /apikeys` are 403. Fallback: a harmless-read capability map, which cannot prove the absence of write permission. | `tools/runtime.py` |
| Q7 | Attachment contents: exact path and behaviour. | ✅ `P2-00b`, for one attachment: `GET /incidents/{inc_id}/attachments/{attach_id}/contents` → 200 with the attachment's own media type (`text/plain`), `Content-Length` and `Content-Disposition`, not chunked; only the headers were read, never the body. ❓ Other media types and large files untested. Still **DEFERRED-P2** in the product. | `client/attachments.py` |
| Q8 | `POST /incidents`: description as TextContentDTO; mandatory fields? | ❓ Open (a write). 📄 The endpoint is documented. | `client/incidents.py` |
| Q9 | `GET /rest/session` for API keys: 403? | ✅ **200** on this version, with `perms: null` and empty permission lists. `--check` will report an identity instead of "unavailable". | `client/base.py` |
| Q10 | Comment threads: `children`, `parent_id`? | ✅ `P2-00b`: a note row carries both keys (`children` an empty list, `parent_id` null). ❓ No reply existed, so how a reply is nested was not observed. | `client/comments.py`, `tools/projection.py` |
| Q11 | Does `GET /users` need more than incident read? | ✅ 200 for the read-only key. | `client/org.py` |
| Q12 | With `handle_format=names`, are select values labels or codes? | ✅ `severity_code`, `phase_id`, `owner_id`, `incident_type_ids` are strings with names and integers without; `plan_status` is a string code (`"A"`) either way. Accepting either, as the client does, is right. | `client/incidents.py` |
| Q13 | *(new)* Is `return_level` required on `query_paged`? | ✅ No. Without it the row has 12 keys; `normal` returns the full object. The offline fake is stricter than the appliance. Not in `P1-CORR-01`, which was scoped to D1–D4; unscheduled. | `client/incidents.py` |
| Q14 | *(new)* AND-within / OR-across filter semantics. | 📄 `P2-00b`: the reference states it (a filter's `logic_type` defaults to `ALL`, the query's to `ANY`). ❓ Still not distinguishable live: the research key sees no closed incident. | `client/incidents.py` |

## B. Carried from the design pack (05 §1.2, §2, §3)

| Item | Outcome on 51.0.9.0.20848 |
|---|---|
| Artifact hits `GET /artifacts/{id}/hits` | 🚫 Not a `GET`. 📄 `POST /artifacts/{artifact_id}/hits/query_paged`; ✅ `GET /artifacts/{artifact_id}/history` works. |
| Incident history `GET /incidents/{id}/history` | ✅ 200; also `/newsfeed`. Neither exposes function results. |
| Rules `GET /actions[/{id}]`, scripts `GET /scripts[/{id}]`, functions `GET /functions[/{id}]` | ✅ 200, `{entities: [...]}`. Function inputs resolve through `view_items` → `GET /types/__function/fields`; no `view=full` parameter exists or is needed. |
| Workflows `GET /workflows` | ✅ 200 but empty in this org; ❓ the object shape (`content.xml`) is unverified. |
| Message destinations, incident types, phases | ✅ 200. |
| Data tables | ✅ `GET /types`, discriminator `type_id == 8`; `GET /types/{type}[/fields|/schema]` work. |
| Playbooks | ✅ `POST /playbooks/query_paged` and `GET /playbooks/{id}` (XML in `content.xml`). 🚫 `GET /playbooks` → 500. |
| Groups `GET /groups` | ✅ 200. |
| Full configuration export | 🚫 The one attempt was rejected with **HTTP 403** for the read-only key; no export response or other evidence of an export being created was observed. Export-history state could not be independently compared, because the same key also receives 403 from the history endpoint. ❓ Contents and side effects unverified. 📄 Import endpoints documented, not exercised. |
| Single-playbook export | 📄 `POST /playbooks/exports[/{export_id}]` and a playbook-scoped `POST /playbooks/imports` + `PUT …/status`. Not exercised (`P4-00`). |
| Playbook enable/disable verb | ❓ No dedicated endpoint documented; presumably `PUT /playbooks/{handle}` with `status`. `P5-00`. |
| Past function results | ❓ Not in history or newsfeed. ✅ `P2-00b`: `POST /playbooks/execution/query_paged` (criteria-only body, sent once) → 200 with the usual paged wrapper and **zero rows**: the appliance has never run a playbook, so the row shape is unknown. 📄 The documented execution and activity types carry status and messages, no function output. `…/activities` was not approved and not called. |

`P2-01` (08 §25) built the catalog on the ✅ rows above and on nothing else: the
collection reads are its default source; the configuration export stays unverified, so
the `export` source is selectable and unavailable; and the key's own permission set
(A-Q6), installed apps and the workflow object are reported as unknown rather than empty.

`P2-02` (08 §26) added the function, script and message-destination tools on that
catalog, and one ✅ call of the row above: `GET /scripts/{id}`, whose `script_text` is
the script body. No evidence gap was met: the recorded shape names the body property.
❓ Not established: how large a body SOAR returns, and the scripts of a playbook.

## C. Decisions that belong to the owner

| # | Decision | Status |
|---|---|---|
| D1 | The original private source pack named the maintainer's lab hosts in the baseline design documents. | **Resolved 2026-09-18** — the baseline was public-sanitised before publication: placeholders only, recorded in 08 §17. The scanner scans those documents like every other file; no path is exempt. |
| D2 | `docs/soar-api-verified.md` did not exist. | **Resolved 2026-09-18** by `P2-00`. `05` points at it; the exception is recorded in 08 §20. |
| D3 | Whether `POST /configurations/exports` is acceptable against the lab appliance. | **Resolved**: approved and attempted once with the read-only key → HTTP 403. Nothing about side effects could be established (the history endpoint is 403 for that key too). |
| D4 | Approve `P1-CORR-01` (reconcile the Phase-1 client with the verified v51 API: tasks, manual actions, `return_level`). Until then three tools do not work on 51.0.9. | **Resolved 2026-09-19** — approved for D1–D4 (08 §21). D2 and D3 are resolved. D1: the method/path is corrected to the verified `PUT`, but task mutation stays disabled until its request body is verified (A-Q1, `P2-00b`). D4: `soar_invoke_action` fails closed; the invocation contract is unresolved (A-Q4). `return_level` was left out (A-Q13). |
| D5 | Approve `P2-TLS` (portable TLS trust). | **Resolved 2026-09-19** — implemented (08 §22, `02 §7.1`): verification on by default against Python's default TLS trust configuration (what `ssl.create_default_context()` exposes on the platform and Python build); an optional `SOAR_CA_BUNDLE`, used instead of it, for a private or self-signed CA; `SOAR_VERIFY_SSL=false` refused without `SOAR_LAB_MODE=true`; the host name is always checked; no fallback, pinning or bundled certificate. |
| D6 | To finish the record (`P2-00b`): the `PUT /tasks/{task_id}` request body, verified live with a suitably scoped key in a disposable org (a write; it is what re-enables `soar_update_task_status`); an incident with an attachment (`P2_PROBE_INCIDENT_ID`); permission for one read-only `POST /playbooks/execution/query_paged`; an org with a closed incident, notes and a workflow; an export-capable key in a disposable org. | **Resolved 2026-09-21 for what the lab could show** — the owner authorised two controlled close/reopen experiments on a designated disposable task, and the one execution query. Verified: the task `PUT` contract and its documented source representation, attachment content, the execution-query route. Not available in the lab, so still open: a closed incident visible to the key, a reply to a note, a workflow, an executed playbook, export contents. |
| D7 | Approve `P1-CORR-02`: implement the verified task-status contract (documented `GET` → deep copy → `status` only → documented `PUT` → verifying `GET`; no task tree, no `task_layout` normalisation, no client-generated `closed_date`; chokepoint, approval, rate and audit order unchanged). | **Resolved 2026-09-21** — implemented (08 §24). `soar_update_task_status` is an ordinary Tier-2 tool behind `SOAR_ALLOW_TASK_WRITES` again; `soar_invoke_action` still refuses every call. Left to the owner: whether the conservative refusals (not reported active and unfrozen, already in the requested status) should stay, and the accepted residual risk of a lost update. |
| D8 | `P2-01` choices left to the owner (08 §25). (a) A catalog load is all or nothing: a key that may not read one collection gets no catalog, not one with a marked gap. (b) Rules, playbooks, functions, groups, phases and incident types are keyed by `name`, and two objects under one key fail the load. (c) `SOAR_CATALOG_TTL_SECONDS` is clamped to 86,400. (d) One load sends one `GET /functions/{id}` per function, because a list row's `view_items` is empty. (e) Verifying the export contract, which needs an export-capable key in a disposable org. (f) An empty `GET /workflows` is recorded as `loaded` with count 0, that is, "SOAR returned none to this key"; a non-empty one as `unverified`. (g) Playbook pages after the first (`start` > 0) were never needed live, so a load whose pages do not add up to `recordsTotal` fails. | **Open.** Implemented as stated; none of it is appliance behaviour, all of it can be relaxed. |
| D9 | `P2-02` choices left to the owner (08 §26). (a) A script body is cut at 20,000 characters, a constant, and there is no way to read beyond it. (b) A script whose `programmatic_name` or `uuid` no longer matches the catalog is refused as `conflict` until the catalog is refreshed. (c) Functions and scripts can be looked up by SOAR id as well as by catalog key. (e) `body.text` is a safety-filtered representation: the credential filter is the repository's general redactor, a heuristic that can replace harmless code shaped like `authorization = <value>` or `Basic <token>` and that knows no secret but this server's own; every change it makes is reported (`redacted`, `text_is`, `source_chars` / `safe_chars`), and the raw source length is disclosed as a count. (f) The pipeline's output redactor now redacts each string of an answer instead of the serialised document (08 §26.3); `security/audit.py` had the same construct; **resolved 2026-09-21 (08 §27)**: an audit record is now redacted string by string, keys included, before it is hashed, through the same primitive (`redaction.py`), and a record in which two keys are equal after redaction is refused (`AuditError`, fail closed) rather than written with one value lost. No audit log needed migrating. Left to the owner: whether the same collision in tool *output*, where the later key still wins, should become an error too. (d) The prohibition on script writes is an AST test over the product code; `client/base.py` was left unchanged, so `request()` itself does not single out script paths. | **Open.** Implemented as stated. |
