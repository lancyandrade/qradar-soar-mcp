# Open questions

Everything this repository could not settle without a live appliance. Nothing
here is implemented on a guess: each item is either held back, implemented in
the most conservative documented form, or explicitly deferred. Ticket `P2-00`
(read-only probing with the lab key) resolves them; results go to
`docs/soar-api-verified.md`.

Confidence marks follow `design/05-SOAR-API-SURFACE.md`: ⚠️ documented but
version-sensitive or shape-uncertain; ❓ may not exist.

## A. Raised during Phase 1 implementation

| # | Question | Current behaviour | Where |
|---|---|---|---|
| Q1 | ⚠️ Does the task DTO in `GET /incidents/{id}/tasks` carry `vers` on every SOAR version? `GET /tasks/{id}` is not in the known-good list. | The PATCH uses the version from the incident-scoped list; if it is absent the PATCH is refused rather than sent without a version. | `client/tasks.py` |
| Q2 | ⚠️ What is the filter syntax for an artifact-value search in `query_paged` (05 §1.2 calls it a composition but names no field)? | `soar_find_similar_incidents` is a client-side composition: recent candidates (sort `create_date` desc, page size `SOAR_MAX_RESULTS`) then one artifact read per candidate. No filter is sent. | `tools/investigation.py` |
| Q3 | ⚠️ Is `create_date` accepted as a `sorts[].field_name` in `query_paged`? | Assumed yes (standard incident field); if it is rejected the tool returns the SOAR error unchanged. | `tools/investigation.py` |
| Q4 | ⚠️ How is an **artifact-scoped** manual action invoked? The known-good body is `{"action_id": N}` on the incident-scoped endpoint only. | Actions whose `object_type` is not `incident` are listed but refused with a validation error. Policy `constraints` (`artifact_types`, `deny_values`) are therefore only exercised by tests in this release. | `tools/actions.py` |
| Q5 | ⚠️ Can the result of an invoked action be observed (invocation id, status, function output)? | The tool returns "accepted"; nothing is polled. | `client/actions.py` |
| Q6 | ❓ Which endpoint reports an API key's own permission set (05 U12)? | No startup probe. The README tells operators the SOAR permission set is their control. | `tools/runtime.py` |
| Q7 | ⚠️ Attachment contents (`GET …/attachments/{aid}/contents`): exact path and behaviour. | **DEFERRED-P2.** Metadata only; hash and opt-in text extraction (05 U11) are not implemented. | `client/attachments.py` |
| Q8 | ⚠️ Does `POST /incidents` accept `description` as a TextContentDTO (`{"format":"text","content":…}`) with `always_text` set, and which fields are mandatory beyond `name` and `discovered_date`? | Description is sent as a TextContentDTO; only `name` and `discovered_date` are required client-side. | `client/incidents.py` |
| Q9 | ⚠️ `GET /rest/session` for API keys: 403 on most appliances? | Reported as `session: unavailable (403)` by `--check`; never fatal. | `client/base.py` |
| Q10 | ⚠️ Comment threads: is `children` populated on `GET /incidents/{id}/comments`, and does `parent_id` on POST create a reply? | Read side flattens `children` if present; write side sends `parent_id` when given. | `client/comments.py`, `tools/projection.py` |
| Q11 | ⚠️ Does `GET /users` need a permission beyond incident read? | Nothing special assumed; a 403 is returned as `forbidden`. | `client/org.py` |
| Q12 | ⚠️ Are `handle_format=names` select values labels or codes per field? `plan_status` is known to be codes (`A`/`C`). | Select validation accepts either the label or the raw value. | `client/incidents.py` |

## B. Carried from the design pack (05 §1.2, §2, §3)

| Item | Mark | Phase |
|---|---|---|
| Artifact hits / relating incidents `GET /artifacts/{id}/hits` | ❓ | P2-00 |
| Incident history `GET /incidents/{id}/history` | ⚠️ | P2-00 |
| Rules `GET /actions`, workflows `GET /workflows` (BPMN under `content.xml`?), scripts `GET /scripts`, functions `GET /functions` (`view=full` equivalent ❓) | ⚠️ | P2-00 |
| Message destinations, incident types, phases | ⚠️ | P2-00 |
| Data tables via `GET /types` (discriminator ❓) | ⚠️/❓ | P2-00 |
| Playbooks `GET /playbooks` or `POST /playbooks/query_paged` (v44+) | ❓ | P2-00 — the single most important unknown for Phase 3+ |
| Groups `GET /groups` (approver groups) | ❓ | P2-00 |
| Full configuration export/import (`/configurations/exports`, imports, two-step confirm) | ⚠️ | P4 |
| Single-playbook `.resz` export via REST | ❓ | P4 |
| Playbook enable/disable verb | ❓ | P5 |

## C. Decisions that belong to the owner

| # | Decision | Status |
|---|---|---|
| D1 | The original private source pack named the maintainer's lab hosts in the baseline design documents (`docs/design/00-`…`07-`, `docs/ACCESS-CHECKLIST.md`, `CLAUDE-CODE-PROMPT.md`). | **Resolved 2026-09-18** — the baseline was public-sanitised before publication: placeholders only, recorded in 08 §17. The scanner scans those documents like every other file; no path is exempt. |
| D2 | `docs/soar-api-verified.md` is referenced by the README as the Phase-2 evidence file and does not exist yet. | Created by P2-00. |
| D3 | Whether `POST /configurations/exports` is acceptable against the lab appliance (ACCESS-CHECKLIST C1). | Needed before P2-00. |
