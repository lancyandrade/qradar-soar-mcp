# 05 — QRadar SOAR API & SDK Surface

> **Epistemic warning.** Everything below is marked with a confidence level.
> I have not had a SOAR appliance to probe in this session, and IBM's REST API
> for configuration objects has changed shape across v40 → v51. **Nothing marked
> ⚠️ or ❓ may be implemented from this document alone.** Ticket `P2-00` exists
> specifically to replace this file with facts obtained from your lab.
>
> | Mark | Meaning |
> |---|---|
> | ✅ | In use in the current codebase and working against your lab, or long-stable and documented |
> | ⚠️ | Documented but version-sensitive or shape-uncertain — **verify before building on it** |
> | ❓ | **Requires research.** May not exist. Do not implement until confirmed against the appliance and IBM docs. |
> | 🚫 | Known not to be safely/reliably achievable via supported API |

> **Status — P2-00, 2026-09-18.** For QRadar SOAR `51.0.9.0.20848` the marks
> below are superseded by [`../soar-api-verified.md`](../soar-api-verified.md),
> which is the authoritative record for that version. The text of this file is
> kept as the original pre-verification research and is otherwise unchanged;
> where the two disagree (notably §1 on tasks and manual actions, and §2.1 on
> the export backend), the verified record wins for that version.

> **Implementation status — P1-CORR-01, 2026-09-19.** The §1 rows for tasks and
> manual actions no longer describe the client. Tasks: the method/path is
> corrected from the invalid `PATCH` assumption to the verified
> `PUT /tasks/{id}`, but task mutation remains disabled because the `PUT`
> request body has not yet been verified; `soar_update_task_status` refuses
> every call and no task version is required or invented. Manual actions are
> read from the `actions` list the incident object carries. Action invocation is
> not implemented and `soar_invoke_action` refuses every call. Details and the
> remaining open points: `08-GREENFIELD-AMENDMENTS.md §21`.

> **Research status — P2-00b, 2026-09-21.** The `PUT /tasks/{id}` request body is no
> longer unverified: a full task object from the documented `GET /tasks/{id}`, with
> `status` as the only change, closed and reopened a disposable task on
> `51.0.9.0.20848` (`../soar-api-verified.md §3.1`). No product code changed:
> `soar_update_task_status` still refuses every call until `P1-CORR-02` implements that
> contract. See `08-GREENFIELD-AMENDMENTS.md §23`.

> **Implementation status — P1-CORR-02, 2026-09-21.** `soar_update_task_status` now
> implements that verified contract and nothing wider; it is verified for
> `51.0.9.0.20848` only, and nothing is known to protect a task against a concurrent
> edit. `soar_invoke_action` still refuses every call. See
> `08-GREENFIELD-AMENDMENTS.md §24`.

> **Implementation status — P2-01, 2026-09-21.** The catalog is implemented, and the
> recommendation of §2.1 below is **not** what was built: `collections` is the default
> `SOAR_CATALOG_SOURCE`, because `P2-00` verified the read-only collection calls of §2
> and could not obtain an export (the one attempt, with a read-only key, was answered
> HTTP 403). `export` stays selectable and is unavailable until its contract is verified:
> it refuses every load, sends nothing and never falls back. The §2 rows are superseded,
> for `51.0.9.0.20848`, by the calls listed in `08-GREENFIELD-AMENDMENTS.md §25`.

> **Implementation status — P2-02, 2026-09-21.** `soar_list_functions`,
> `soar_get_function`, `soar_list_scripts`, `soar_get_script` and
> `soar_list_message_destinations` are implemented as Tier-0 reads over that catalog. The
> only call they add is the verified `GET /scripts/{id}`, for the script body
> (`script_text`), read on demand, capped and never stored; nothing can write a script.
> See `08-GREENFIELD-AMENDMENTS.md §26`.

All paths are relative to `https://{host}/rest/orgs/{org_id}` unless noted.
Auth: HTTP Basic with API key id/secret. Common params `handle_format=names`
and `text_content_output_format=always_text` as already implemented.

---

## 1. Phase 1 — already exercised

| Purpose | Method + path | Conf. |
|---|---|---|
| Session / server version | `GET /rest/session` | ✅ (may be forbidden to API keys — code already degrades) |
| Incident search | `POST /incidents/query_paged?return_level=normal` | ✅ |
| Incident read | `GET /incidents/{id}` | ✅ |
| Incident create | `POST /incidents` | ✅ |
| Incident update / close / assign | `PATCH /incidents/{id}` (PatchDTO: `version` + `changes[]`) | ✅ |
| Tasks | `GET /incidents/{id}/tasks`, `PATCH /tasks/{id}` | ✅ |
| Artifacts | `GET /incidents/{id}/artifacts`, `POST /incidents/{id}/artifacts` | ✅ |
| Comments/notes | `GET|POST /incidents/{id}/comments` | ✅ |
| Attachments (metadata) | `GET /incidents/{id}/attachments` | ✅ |
| Users | `GET /users` | ✅ |
| Incident field metadata | `GET /types/incident/fields` | ✅ |
| Manual actions for an object | `GET /incidents/{id}/actions` | ✅ |
| Invoke a manual action | `POST /incidents/{id}/action_invocations` `{"action_id": N}` | ✅ |

### 1.1 Behaviours the client already encodes — do not regress

- PATCH is optimistic concurrency, not a merge: `{"version": N, "changes":
  [{"field","old_value":{"object":…},"new_value":{"object":…}}]}`. A `success:
  false` response must raise.
- Custom fields are addressed as `properties.<name>`.
- Closing needs `plan_status`, `resolution_id`, `resolution_summary` together,
  and fails if any close-required custom field is empty.
- Conditions within one `query_paged` filter are ANDed; separate filter objects
  are ORed. `plan_status`: `"A"` active, `"C"` closed.

### 1.2 Gaps to close in Phase 1

| Need | Approach | Conf. |
|---|---|---|
| Attachment **content** download | `GET /incidents/{id}/attachments/{aid}/contents` | ⚠️ verify path; returns binary — **must not** be dumped into MCP output. Return metadata + hash; extract text only for known-safe types, size-capped. |
| Artifact hits / relating incidents | `GET /artifacts/{id}/hits` ❓ | ❓ — valuable for "similar incidents", verify existence |
| Similar-incident search | Build on `query_paged` with artifact-value filters | ✅ (composition, no new API) |
| Incident history / audit | `GET /incidents/{id}/history` | ⚠️ verify; shape varies by version |

---

## 2. Phase 2 — discovery endpoints

| Tool | Endpoint | Conf. | Notes |
|---|---|---|---|
| `soar_list_rules` / `soar_get_rule` | `GET /actions`, `GET /actions/{id}` | ⚠️ | "Rules" in the UI = `actions` in the API. Both manual and automatic. Long-stable. |
| `soar_list_workflows` / `soar_get_workflow` | `GET /workflows`, `GET /workflows/{id}` | ⚠️ | Returns BPMN XML, typically under `content.xml`. Verify field name. |
| `soar_list_scripts` / `soar_get_script` | `GET /scripts`, `GET /scripts/{id}` | ⚠️ | Script bodies are Python. **Read-only in this project.** |
| `soar_list_functions` / `soar_get_function` | `GET /functions`, `GET /functions/{id}` | ⚠️ | Need `view=full`-equivalent to get input definitions. ❓ on the exact parameter. |
| `soar_list_message_destinations` | `GET /message_destinations` | ⚠️ | |
| `soar_list_incident_types` | `GET /incident_types` | ⚠️ | |
| `soar_list_phases` | `GET /phases` | ⚠️ | |
| `soar_list_fields` | `GET /types/{type}/fields` | ✅ | Already used for incident; generalise to `task`, `artifact`, and data table types |
| `soar_list_datatables` | via `GET /types` filtered to data-table types | ⚠️ | Data tables are exposed as *types*; there is no `/datatables` collection as such. ❓ on the exact discriminator field. |
| `soar_list_playbooks` / `soar_get_playbook` | ❓ `GET /playbooks` or `POST /playbooks/query_paged` | ❓ | **Playbooks are a v44+ feature.** The collection endpoint and whether it supports paged query must be confirmed on your appliance. This is the single most important unknown in Phase 2. |
| Groups (for `approver_group`) | `GET /groups` | ❓ | |
| API key's own permissions | ❓ | ❓ | Needed for L5 validation. May require `GET /rest/session` or a permissions endpoint. If unavailable, fall back to capability probing (attempt a harmless read of each collection and record 403s). |

### 2.1 Reliable fallback for all of the above

`POST /configurations/exports` (full configuration export) returns a single JSON
document containing functions, scripts, workflows, rules/actions, message
destinations, incident types, fields, data tables and (on v44+) playbooks. ⚠️

If individual collection endpoints prove version-unstable, **discovery can be
implemented entirely by parsing one full export**, cached in the catalog. This
is slower and heavier but has one big advantage: it is the same representation
the import endpoint consumes, so discovery and compilation share a data model.

**Recommendation:** build the catalog loader with two backends — `collections`
(fast, per-endpoint) and `export` (slow, robust) — selected by
`SOAR_CATALOG_SOURCE`. Ship `export` as the default until `P2-00` confirms the
collection endpoints on real appliances. This de-risks the whole of Phase 2
against my uncertainty above.

---

## 3. Phase 4/5 — export, import, enable

### 3.1 Configuration export

| Purpose | Endpoint | Conf. |
|---|---|---|
| Full config export | `POST /configurations/exports` | ⚠️ |
| Retrieve a previous export | `GET /configurations/exports/{id}` | ⚠️ |
| Export **a single playbook** as `.resz` | ❓ | ❓ — the UI does this; whether a documented REST endpoint exists (vs. a UI-internal call) **must be confirmed**. If it does not, single-playbook export must be done by full-export + local extraction. |

`.resz` is a zip containing an `export.res` JSON document (plus attachments for
some object types). Treat it as an opaque bundle produced by the compiler and
validated by round-trip, not as a format to hand-craft.

### 3.2 Configuration import — two phase

This is the documented, stable mechanism and the one `resilient-sdk res-import`
uses:

1. `POST /configurations/imports` with the export document → returns an
   `ImportDTO` with `status: "PENDING"` and a per-object breakdown of what would
   be created/updated/skipped. **Nothing is committed yet.** ⚠️
2. `PUT /configurations/imports/{id}` with `status: "ACCEPTED"` to commit, or
   `"REJECTED"` to abandon. ⚠️

**This two-phase shape is a gift to this architecture.** Phase 1 of the import
is effectively a server-side dry run: it tells you exactly what SOAR thinks
will change. The design must exploit it:

```
soar_import_playbook(bundle)
  → POST /configurations/imports              (PENDING)
  → parse per-object breakdown
  → present breakdown as the approval payload alongside our own diff
  → HUMAN APPROVAL (out of band)
  → PUT status=ACCEPTED                        (committed)
```

If SOAR's own PENDING breakdown disagrees with our computed diff, **abort and
report the discrepancy**. That cross-check is worth more than either artifact
alone.

Do **not** auto-accept in the same tool call. `soar_import_playbook` should
return at PENDING and require `soar_confirm_import(import_id, approval_id)`.

### 3.3 Enable / disable a playbook

❓ **Requires research.** Likely a `PUT`/`PATCH` on the playbook object toggling
an activation/status field. Until confirmed:

- `soar_enable_playbook` / `soar_disable_playbook` are **specified but not
  implemented** in Phase 4.
- Phase 5 begins with `P5-00`, a research ticket, and does not proceed without
  a confirmed endpoint.
- Interim posture: import leaves the playbook disabled and the tool returns
  explicit instructions for a human to enable it in the UI. **This is an
  acceptable permanent answer.** A human clicking "enable" after reading a diff
  is a good control, not a limitation to engineer away.

### 3.4 `resilient-sdk`

The official SDK (`resilient-sdk`, `resilient`, `resilient-circuits`) provides
`codegen`, `clone`, `export`, `extract`, `validate`, `package`, `docgen`.

**Recommendation: depend on `resilient` (the REST client library) if it
simplifies auth/version handling, but do not shell out to `resilient-sdk` CLI
from the MCP server.** Reasons: subprocess execution from an LLM-driven server
widens the attack surface considerably; the CLI's output is not a stable API;
and it needs filesystem state we would rather control. Use the SDK offline, by
hand, to *learn* the export/import formats and to generate test fixtures —
that is where it earns its keep.

---

## 4. Explicitly unsupported / unsafe (task item 12)

| # | Capability | Why it cannot be done safely or reliably | Position |
|---|---|---|---|
| U1 | **Hand-authoring BPMN workflow XML** | The XML carries Resilient extension elements with object UUIDs, embedded pre/post-process Python, and canvas geometry. No public schema guarantees stability across versions. Generated XML fails at runtime, not at import. | 🚫 Never generate freehand. Compile only via templated composition validated by import-PENDING round-trip. |
| U2 | **Creating new SOAR *functions*** | A function definition without a `resilient-circuits` implementation on the AppHost is a node that hangs forever. Implementations are installed as app packages, not created via REST. | 🚫 Out of scope. Playbooks may only reference functions that already exist. |
| U3 | **Installing / modifying AppHost apps** | Appliance-level operation (`manageapphost`, container registry, app zip upload). Different trust domain, different credentials, no meaningful rollback. | 🚫 Architectural non-goal (Tier 5). |
| U4 | **Creating or editing SOAR scripts (Python)** | `POST/PUT /scripts` may work, but it is arbitrary code execution inside SOAR by a language model. | 🚫 Read-only. `SOAR_ALLOW_SCRIPT_WRITES` reserved and must remain false. |
| U5 | **True playbook dry-run** | No such API exists. | Simulation is our own offline interpreter, explicitly labelled as such (`04 §3.1`). |
| U6 | **Transactional import / rollback** | Config import has no rollback API. `REJECTED` only works pre-commit; post-commit there is no undo. | Mandatory pre-import full-config snapshot + documented manual restore runbook. Accept that restore is a human, partly-manual operation. |
| U7 | **Deleting playbooks/rules/workflows** | Deletion of automation is unbounded-damage and rarely reversible. | 🚫 No delete tools at any tier. |
| U8 | **Playbook canvas layout** | Coordinates are UI state with no documented contract. | Compiler emits a deterministic auto-layout; diff ignores geometry; expect the SOAR UI to look tidier after a human opens and saves it. |
| U9 | **Faithful decompilation of arbitrary playbooks** | Inline scripts and loops have no IR representation. | Partial decompilation with explicit `unrepresentable` list; `REVIEW_UNSAFE` blocks modify-deploy (`03 §4`). |
| U10 | **Bulk operations** | Any tool that can act on N objects can act on all of them. | 🚫 `SOAR_MAX_MUTATIONS_PER_CALL=1`. |
| U11 | **Attachment content interpretation** | Attachments are attacker-supplied files. Parsing them in-process is a code-execution and prompt-injection vector. | Metadata + hash only by default; opt-in size-capped text extraction for a whitelist of types, output clearly marked untrusted. |
| U12 | **Reading the API key's own permission set** | Endpoint uncertain. | ❓ Research; fall back to probe-and-record-403 capability discovery. |

---

## 5. Research tickets these imply

| ID | Question | Blocks |
|---|---|---|
| `P2-00` | Confirm every ⚠️/❓ endpoint above against the lab appliance; record exact paths, params, response shapes and version. Produce `docs/soar-api-verified.md`. | All of Phase 2 |
| `P2-01` | Does a playbook collection endpoint exist? Paged? What does a playbook object contain? | `soar_list_playbooks` |
| `P4-00` | Confirm single-playbook `.resz` export; if absent, design full-export + extract. | Phase 4 |
| `P4-01` | Confirm import two-phase shape and the PENDING breakdown structure. | Phase 4/5 |
| `P5-00` | Confirm enable/disable mechanism. If none, Phase 5 ships as "import disabled + human enables in UI" permanently. | Phase 5 |
| `P2-02` | Determine API-key permission introspection; else implement probe-based discovery. | L5 validation |

Each of these produces a **document with copy-pasted real responses** (sanitised)
committed to `docs/`, and fixtures committed to `tests/fixtures/`. Research
whose output is only in someone's head is not done.

---

## 6. Pre-import snapshot runbook (because U6)

Before any `PUT .../imports/{id}` with `ACCEPTED`:

1. `POST /configurations/exports` → write to
   `${SOAR_SNAPSHOT_DIR}/{utc_timestamp}-pre-{playbook_api_name}.res`
2. Record its SHA-256 in the audit log alongside the import record.
3. If the snapshot fails, **the import fails**. No snapshot, no import.

Restore is manual: a human re-imports the snapshot via the SOAR UI or
`resilient-sdk`, reviewing the PENDING breakdown. Document this in
`docs/runbooks/restore.md` and **test it once in the lab** (`P4-07`) — an
untested restore procedure is a comforting fiction.
