# Open questions

What this repository could not settle, and what `P2-00` settled. Nothing here is
implemented on a guess: each item is held back, implemented in the most
conservative documented form, or explicitly deferred.

**`P2-00` ran on 2026-09-18 against IBM QRadar SOAR `51.0.9.0.20848` with a
read-only API key.** Its results are in
[`soar-api-verified.md`](soar-api-verified.md), which is authoritative for that
version and for no other. "Resolved" below always means *resolved for
51.0.9.0.20848*.

Marks: ✅ verified live · 📄 documented by the appliance, not exercised · 🚫
verified not to work as assumed · ⚠️ / ❓ still open.

## A. Raised during Phase 1 implementation

| # | Question | Outcome on 51.0.9.0.20848 | Where |
|---|---|---|---|
| Q1 | Does the task DTO in `GET /incidents/{id}/tasks` carry `vers`? | 🚫 **No.** Neither the list rows nor `GET /tasks/{task_id}` has any version key, and the appliance documents `PUT /tasks/{task_id}`, not `PATCH`. The tool refuses every change (fails closed). → `P1-CORR-01`. | `client/tasks.py` |
| Q2 | Filter syntax for an artifact-value search in `query_paged`? | ❓ Still open; no filter was guessed. 📄 The appliance documents dedicated reads instead: `POST …/artifacts/{artifact_id}/related_incidents/query_paged`, `GET /incidents/{inc_id}/related_ex`, and artifacts carry `related_incident_count`. Not exercised. | `tools/investigation.py` |
| Q3 | Is `create_date` accepted as a `sorts[].field_name`? | ✅ Yes (200). | `tools/investigation.py` |
| Q4 | How is an artifact-scoped manual action invoked? | ❓ Open, and wider than asked: `GET /incidents/{id}/actions` returns **500** and is undocumented; `action_invocations` is undocumented, though a `GET` on it returns 200. The incident, task and artifact objects each carry an `actions` list. → `P1-CORR-01`. | `tools/actions.py` |
| Q5 | Can the result of an invoked action be observed? | ❓ Open. `GET /incidents/{id}/action_invocations` returns `{entities: []}`; its row shape is unknown (none existed). | `client/actions.py` |
| Q6 | Which endpoint reports an API key's own permission set? | 🚫 **None that a read-only key can use.** `/rest/session` and `/rest/session/{org_id}/acl` answer 200 with empty permission data; `GET /permissions` and `GET /apikeys` are 403. Fallback: a harmless-read capability map, which cannot prove the absence of write permission. | `tools/runtime.py` |
| Q7 | Attachment contents: exact path and behaviour. | 📄 Path confirmed by the appliance's reference (`GET /incidents/{inc_id}/attachments/{attach_id}/contents`). ❓ Content type unverified: no attachment existed on the one incident visible. Still **DEFERRED-P2** in the product. | `client/attachments.py` |
| Q8 | `POST /incidents`: description as TextContentDTO; mandatory fields? | ❓ Open (a write). 📄 The endpoint is documented. | `client/incidents.py` |
| Q9 | `GET /rest/session` for API keys: 403? | ✅ **200** on this version, with `perms: null` and empty permission lists. `--check` will report an identity instead of "unavailable". | `client/base.py` |
| Q10 | Comment threads: `children`, `parent_id`? | ❓ Open: the sampled incident has no notes. | `client/comments.py`, `tools/projection.py` |
| Q11 | Does `GET /users` need more than incident read? | ✅ 200 for the read-only key. | `client/org.py` |
| Q12 | With `handle_format=names`, are select values labels or codes? | ✅ `severity_code`, `phase_id`, `owner_id`, `incident_type_ids` are strings with names and integers without; `plan_status` is a string code (`"A"`) either way. Accepting either, as the client does, is right. | `client/incidents.py` |
| Q13 | *(new)* Is `return_level` required on `query_paged`? | ✅ No. Without it the row has 12 keys; `normal` returns the full object. The offline fake is stricter than the appliance. → `P1-CORR-01`. | `client/incidents.py` |
| Q14 | *(new)* AND-within / OR-across filter semantics. | ❓ Not distinguishable: the org has no closed incident. | `client/incidents.py` |

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
| Past function results | ❓ Not in history or newsfeed. 📄 `POST /playbooks/execution/query_paged` and `…/activities` exist; not exercised. |

## C. Decisions that belong to the owner

| # | Decision | Status |
|---|---|---|
| D1 | The original private source pack named the maintainer's lab hosts in the baseline design documents. | **Resolved 2026-09-18** — the baseline was public-sanitised before publication: placeholders only, recorded in 08 §17. The scanner scans those documents like every other file; no path is exempt. |
| D2 | `docs/soar-api-verified.md` did not exist. | **Resolved 2026-09-18** by `P2-00`. `05` points at it; the exception is recorded in 08 §20. |
| D3 | Whether `POST /configurations/exports` is acceptable against the lab appliance. | **Resolved**: approved and attempted once with the read-only key → HTTP 403. Nothing about side effects could be established (the history endpoint is 403 for that key too). |
| D4 | Approve `P1-CORR-01` (reconcile the Phase-1 client with the verified v51 API: tasks, manual actions, `return_level`). Until then three tools do not work on 51.0.9. | **Open** — proposed in `soar-api-verified.md §8`; not started. |
| D5 | Approve `P2-TLS` (portable TLS trust). | **Open** — proposed in `soar-api-verified.md §8`; not started. |
| D6 | To finish the record (`P2-00b`): an incident with an attachment (`P2_PROBE_INCIDENT_ID`); permission for one read-only `POST /playbooks/execution/query_paged`; an org with a closed incident, notes and a workflow; an export-capable key in a disposable org. | **Open** |
