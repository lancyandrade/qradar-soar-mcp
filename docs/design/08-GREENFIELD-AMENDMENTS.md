# 08 — Greenfield amendments to the Phase 0–1 design

**Status:** authoritative **only** for the points explicitly listed below, each
of which was decided by the project owner on 2026-09-17. Where a point here
conflicts with `00-` to `07-`, this document wins *for that point only*. It
does not license any other redesign; anything not listed here is governed by
`00-` to `07-` unchanged.

`00-` to `07-` are the baseline and are not edited, with six recorded
exceptions: before first publication the private lab topology was replaced by
generic placeholders (§17), P2-00 added a status pointer to `05` (§20),
P1-CORR-01 added an implementation-status note to `05` (§21), P2-TLS added
the TLS trust model to `02` as §7.1 (§22), P2-00b added a research-status
note to `05` (§23), and P1-CORR-02 added an implementation-status note to
`05` (§24).

---

## 1. Premise correction: there was never a v0.1.0 implementation

`00-GAP-ANALYSIS.md §1` describes an existing two-module prototype
(`client.py`, `server.py`, 18 tools, `SOAR_ALLOW_WRITES`). That code did not
exist in this repository and, per the owner's decision, never existed as an
artifact to preserve. Consequently:

| Baseline text | Reads as |
|---|---|
| "keep it", "do not rewrite", "move, do not change semantics" (00 §1.2, 01, 06 P1-04) | *implement to the documented semantics* |
| "characterisation tests against the current code" (06 P1-01) | *offline contract tests of the documented known-good REST semantics* (§2.1) |
| "tool list identical to v0.1.0" (06 P1-14, `CLAUDE-CODE-PROMPT.md`) | *tool list identical to the approved contract in §3* |
| 05 §1 "✅ = in use in the current codebase and working against your lab" | *documented known-good; the only REST behaviour Phase 1 may implement; not yet verified by this repository* |
| 00 §3 risk register entries about the current build (R2, R4, R5, R7, R9) | the risks stand; the "current build" is the greenfield one |

Everything else in the baseline — tiers, flags, policy, approvals, caps, audit,
transport, test strategy, phase boundaries, ticket IDs and acceptance
criteria — is unchanged.

## 2. Ticket amendments

### 2.1 P1-01 — contract tests instead of characterisation tests
P1-01 delivers the test harness (`tests/fake_soar.py` state engine behind
`respx`, synthetic fixtures, `conftest.py`) and a **REST-semantics contract
suite** that encodes `05 §1` and `05 §1.1` in executable form: PatchDTO shape
and `success:false` on a stale version, `properties.<name>` custom fields,
`handle_format=names` and `text_content_output_format=always_text` on every
request, `return_level=normal` on `query_paged`, AND-within / OR-across
filters, `plan_status` A/C, close requiring `plan_status` + `resolution_id` +
`resolution_summary` together and failing on an empty close-required custom
field, `ping` reachability via `query_paged`, the incident-scoped manual-action
list, and the exact `{"action_id": N}` invocation body. The P1-01 acceptance
criterion "a deliberately introduced regression in `apply_patch` fails a test"
is satisfied by P1-04, when `apply_patch` exists.

### 2.2 P1-04 — greenfield client
The `client/` package is written to the documented semantics rather than moved.
Its acceptance criterion becomes: every P1-01 contract test passes through the
client; **no REST call outside §4 of this document exists in `client/`**,
enforced by an AST test.

### 2.3 P1-14 — approved tool contract
There is no historical tool list. The Phase-1 surface is exactly §3, pinned by
a snapshot test. `soar_invoke_action` is classified per call by the action
policy (`02 §1.1`), so its tier is a property of the target action.

### 2.4 P1-13 / P1-14 ordering
`06` makes P1-14 depend on P1-13, yet P1-13 enumerates "the registry" that
P1-14 introduces. Resolution: the registry mechanism (`tools/registry.py`,
`@soar_tool`, the enforce→audit→execute→redact pipeline) lands with **P1-13**
together with the matrix, the transport-spy test and the AST test, exercised
against a test-local tool set; **P1-14** adds the real tools, `server.py`, and
the `EXPECTED` entries for the approved surface.

### 2.5 P0-01 — "first commit"
The baseline commit (`64641f9`) already carries `.gitignore`, so no code ever
preceded an ignore file. P0-01 extends it with the patterns the ticket lists
(`*.resz`, `*.res`, `snapshots/`, `approvals/`, `*.jsonl`) and records the
history checks. Results on 2026-09-17: `git log --all --full-history -- .env`
is empty; `git check-ignore -v .env` → `.gitignore:2:.env`; the A6
credential patterns match nothing in history — no credential has ever been
committed. The lab-topology half of A6 is settled by §17.

### 2.6 P0-02 / P0-03
`pyproject.toml` is introduced at P0-02 (its AC requires the licence to agree
between `LICENSE` and `pyproject.toml`); P0-03 adds the package skeleton and
lock file. The P0-03 criterion "`--check` still passes against the lab; no tool
signature changed" has no subject in a greenfield build and is replaced by
"`python -c 'import qradar_soar_mcp'` works and `playbook/`, `catalog/` hold no
behaviour".

## 3. Approved Phase-1 tool contract (P1-14 amendment)

| Tool | Tier | Capability flag | REST (see §4) |
|---|---|---|---|
| `soar_search_incidents` | 0 | — | `POST /incidents/query_paged?return_level=normal` |
| `soar_get_incident` | 0 | — | `GET /incidents/{id}` |
| `soar_list_artifacts` | 0 | — | `GET /incidents/{id}/artifacts` |
| `soar_list_tasks` | 0 | — | `GET /incidents/{id}/tasks` |
| `soar_list_comments` | 0 | — | `GET /incidents/{id}/comments` |
| `soar_list_attachments` | 0 | — | `GET /incidents/{id}/attachments` (metadata only) |
| `soar_list_users` | 0 | — | `GET /users` |
| `soar_describe_incident_fields` | 0 | — | `GET /types/incident/fields` |
| `soar_list_incident_actions` | 0 | — | `GET /incidents/{id}` (the `actions` list it carries; §21) |
| `soar_check_approval` | 0 | — | none (broker files) |
| `soar_get_incident_full` | 0 | — | composition of the reads above |
| `soar_find_similar_incidents` | 0 | — | composition of `query_paged` + artifact reads (§9) |
| `soar_add_comment` | 1 | `SOAR_ALLOW_COMMENTS` | `POST /incidents/{id}/comments` |
| `soar_add_artifact` | 1 | `SOAR_ALLOW_ARTIFACTS` | `POST /incidents/{id}/artifacts` |
| `soar_create_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | `POST /incidents` |
| `soar_update_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | `GET` + `PATCH /incidents/{id}` |
| `soar_assign_incident` | 2 | `SOAR_ALLOW_INCIDENT_WRITES` | `GET` + `PATCH /incidents/{id}` |
| `soar_close_incident` | 2 | `SOAR_ALLOW_INCIDENT_CLOSE` | `GET` + `PATCH /incidents/{id}` |
| `soar_update_task_status` | 2 | `SOAR_ALLOW_TASK_WRITES` | `GET` + `PUT` + `GET /tasks/{id}` (§24) |
| `soar_invoke_action` | per policy (1–5) | `SOAR_ALLOW_ACTIONS` (+ `SOAR_ALLOW_DESTRUCTIVE_ACTIONS` when the rule is destructive) | none: every call is refused as `DENY_UNSUPPORTED`; the invocation contract is unverified (§21) |

**Explicitly not in Phase 1:** `soar_ping`, `soar_security_status`, data-table
reads, `/functions`, org-level `/actions`, any playbook tool, any generic REST
tool, and anything else not in this table. Connectivity checking is the
`qradar-soar-mcp --check` CLI, not a tool.

A tool in this table that cannot be built from §4 without guessing is left
**unregistered**, recorded in `docs/open-questions.md`, and reported as
DEFERRED-P2 (see §9).

## 4. Phase-1 REST surface (P1-04 amendment; rule "no invented APIs")

Only these calls may appear in `client/` (all under `/rest/orgs/{org_id}`
unless absolute; every request carries `handle_format=names` and
`text_content_output_format=always_text`, except the two single-task calls, §24):

| Method | Path | Notes |
|---|---|---|
| GET | `/rest/session` | may 403 for API keys; `ping` degrades |
| POST | `incidents/query_paged` | `return_level=normal`; `{filters: [{conditions: [...]}], sorts, start, length}`; AND within a filter, OR across filters |
| GET | `incidents/{id}` | |
| POST | `incidents` | `discovered_date` required |
| PATCH | `incidents/{id}` | PatchDTO `{version, changes: [{field: {name}, old_value: {object}, new_value: {object}}]}`; `success:false` raises |
| GET | `incidents/{id}/tasks` | |
| GET | `tasks/{id}` | §24: `handle_format: ids` and `text_content_output_format: objects_convert` as headers, no query string |
| PUT | `tasks/{id}` | §24: the same two headers; the body is the whole object that `GET` returned with `status` as the only change; a StatusDTO answer, `success` other than `true` raises. The only `PUT` there is |
| GET / POST | `incidents/{id}/artifacts` | |
| GET / POST | `incidents/{id}/comments` | `{"text": {"format": "text", "content": ...}}` |
| GET | `incidents/{id}/attachments` | metadata only; contents endpoint is ⚠️ and not used |
| GET | `users` | |
| GET | `types/incident/fields` | field definitions incl. `prefix: properties` for custom fields |

Precedence over any prior implementation: a task's status is changed with the
verified `PUT /tasks/{id}`, never `PATCH`, and only as §24 describes; `query_paged` sends
`return_level=normal`; manual actions come from the `actions` list the
incident object carries, and nothing is invoked (§21);
reachability (`--check` and `ping`) uses `query_paged`. `/types`, `/functions`,
table data, org-level `/actions`, `/rest/const`, `/rest/orgs/{org}`, attachment
contents, incident history and every `05 §2–3` endpoint stay out of Phase 1.

## 5. Approval key custody — intentional security correction (P1-10)

`02 §4.2` requires an approval the MCP server can verify but cannot forge. A
symmetric HMAC cannot provide that: whoever verifies holds the key. Phase 1
therefore uses **Ed25519** (`cryptography` package):

- `qradar-soar-approve` (the approver's environment) signs with the private
  key from `SOAR_APPROVAL_PRIVATE_KEY_FILE`; the MCP server never reads that
  variable or file.
- The server verifies with the public key from
  `SOAR_APPROVAL_PUBLIC_KEY_FILE` (replaces `SOAR_APPROVAL_HMAC_KEY_FILE` in
  `env.example` and `SOAR_APPROVAL_HMAC_KEY` in `02 §4.2`).

Everything else in `02 §4` is preserved: the file broker in
`SOAR_APPROVAL_BROKER_PATH` (`{id}.request.json` → `{id}.approved.json`),
the CLI printing the full plan and requiring the reference typed back,
argument-hash binding, TTL, atomic single-use consumption (rename), the
`out_of_band` default, `in_band` only with `SOAR_LAB_MODE=true` for Tier ≥ 3,
and `soar_check_approval` (Tier 0).

## 6. Licence and security contact (P0-02)

Apache-2.0. `SECURITY.md` reporting address: `lancy@gulfsoftware.com`.
`LICENSE`, `pyproject.toml` and the documentation must agree (tested).

## 7. Incident projection (P1-14, lifecycle step 12)

Raw incident DTOs are never returned. `summarise_incident`
(`tools/projection.py`) emits exactly:

`id`, `name`, `description` (trimmed), `plan_status`, `phase_id`,
`severity_code`, `incident_type_ids`, `owner_id`, `discovered_date`,
`create_date`, `start_date`, `due_date`, `inc_last_modified_date`,
`resolution_id`, `resolution_summary` (trimmed), `vers`.

Custom fields (`properties.*`) are returned only when a tool explicitly
requests them (`custom_fields=[...]`), individually trimmed, never wholesale.
The list is pinned by a snapshot test and documented in the README. Adding a
field is a deliberate, reviewed change.

## 8. `safe_message` vs `detail` (P1-03)

`safe_message` (MCP output) = failure class + status + the redacted, truncated
SOAR `message`. `detail` (logs only) = everything else. Raw bodies, URLs,
`Authorization` data, `httpx.Request` objects, API secrets and unsanitised
exception strings never reach MCP output.

## 9. P1-15 — what is implemented and what is deferred

| Element | Status | Basis |
|---|---|---|
| `soar_get_incident_full` | IMPLEMENTED | composition of §4 reads; projected; size-capped under a documented budget |
| `soar_find_similar_incidents` | IMPLEMENTED (client-side composition) | `05 §1.2` calls artifact-value search a `query_paged` composition but gives no filter field syntax; guessing is forbidden. Implementation: `query_paged` for recent candidates (capped by `SOAR_MAX_RESULTS`), then `GET /incidents/{id}/artifacts` per candidate, ranked by overlapping (type, value) pairs. Cost is N+1 reads; a server-side filter is an open question for P2-00 |
| attachment hash + opt-in text extraction | **DEFERRED-P2** | requires `GET …/attachments/{aid}/contents`, marked ⚠️; metadata is exposed, contents are not |

## 10. Test tooling (07 §2)

`respx` is the HTTP interception layer for T2 contract tests; `FakeSoar` is
the state/response engine behind a single catch-all `respx` route.
`pytest-asyncio` (`asyncio_mode = "auto"`). `hypothesis`, `syrupy`, `freezegun`
are used where they add value (config parsing properties, tool-list and
projection snapshots, TTL tests), not everywhere.

## 11. Coverage gates (07 §1 vs 06 P1-12)

`security/` ≥ 95 %, `playbook/` ≥ 90 % once it has behaviour (not in Phase 1;
no tests are manufactured for empty packages), overall ≥ 80 %.

## 12. Reference work

Branch `feat/phase-0-1` and tag `reference/phase-0-1-attempt` (`8fa199a`) are
**local only**, never pushed, never merged or rebased into this branch. Code
from it is ported file-by-file only where it conforms to the baseline.

## 13. Security additions retained from the reference work

Streamed response-size cap; the real stdio subprocess handshake test; the
function-level AST chokepoint test (stricter than `07 §3.1`'s file-level
rule); the sentinel secret-leak matrix (every tool × every failure class);
scrubbing of the API secret and the `Basic` credential from any server-echoed
error text.

## 14. Configuration parsing details (P1-02)

- Booleans: exactly `true`/`1`/`yes`/`on` (case-insensitive, **no whitespace
  trimming**) ⇒ true; `false`/`0`/`no`/`off` ⇒ false; anything else resolves
  to the **safe** side — `false` for every capability flag (`SOAR_ALLOW_*`,
  `SOAR_LAB_MODE`, `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE`), `true` for the safety
  switches (`SOAR_REQUIRE_ACTION_CONFIRMATION`,
  `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION`, `SOAR_AUDIT_REQUIRED`). Empty-but-present
  or unrecognised values log a warning naming the variable; absent values do
  not.
- `SOAR_ORG_ID`: unparseable or non-positive ⇒ connection disabled plus a
  warning (every tool that reaches SOAR then fails with `not_configured`).
- `SOAR_MAX_MUTATIONS_PER_CALL`: values other than `1` are clamped to `1` with
  a warning (`05 U10`: bulk mutation is a Tier-5 non-goal).
- Code defaults for the state paths are relative (`approvals`, `audit.jsonl`,
  `snapshots`, `HALT`, `out/playbooks`); `env.example` shows the recommended
  absolute locations.
- `SOAR_VERIFY_SSL`: `true` or `false`; anything else refuses to start (a
  misread TLS setting must not pick a side). `false` additionally needs
  `SOAR_LAB_MODE=true`, and the path of an existing CA bundle is still accepted
  as a deprecated spelling of `SOAR_CA_BUNDLE` (§22).
- `SOAR_CA_BUNDLE`: empty ⇒ Python's default TLS trust configuration; otherwise
  it must be an existing PEM file, which is then used instead, or the server
  refuses to start (§22).
- Integers: unparseable or out-of-range ⇒ documented default plus a warning.
- `SOAR_MCP_TRANSPORT`: `stdio` (default) or `streamable-http` (`http`
  accepted as an alias); unrecognised ⇒ `stdio` plus a warning.
- `SOAR_APPROVAL_MODE`: unrecognised ⇒ `out_of_band` plus a warning.
- `SOAR_ALLOW_SCRIPT_WRITES=true` refuses to start.

## 15. Version

Phase 1 is the `v0.2.0` milestone (`06`). `__version__ = "0.2.0"`.

## 16. Inconsistencies inside the baseline, resolved here

| Where | Conflict | Resolution |
|---|---|---|
| `07 §1` vs `06 P1-12` | 95 % vs 85 % on `security/` | 95 % |
| `02 §4.2` vs `env.example` | `SOAR_APPROVAL_HMAC_KEY` vs `..._FILE` | superseded by §5 |
| `05 §3.4` | "depend on `resilient` if it simplifies" | not adopted; `httpx` directly, per §4 |
| `06 P0-01` vs baseline `.gitignore` | ticket lists patterns the file lacks | added in P0-01 |

## 17. Baseline public-sanitisation (before first publication)

The original private source pack named the maintainer's lab hosts by their
RFC 1918 addresses in `00 §1.4`, `01 §2`, `07 §7.1`,
`docs/ACCESS-CHECKLIST.md` and `CLAUDE-CODE-PROMPT.md`. Rule 4 of the build
prompt forbids real-environment addresses in any file of this public
repository, so on 2026-09-18, before anything was pushed, the owner had the
unpublished history rewritten: the baseline commit and every commit after it
were recreated with those references replaced by generic placeholders. The
private topology exists in no commit of the published history.

The published baseline differs from the private source pack **only** in these
substitutions; no other byte of `00-` to `07-`, `docs/ACCESS-CHECKLIST.md` or
`CLAUDE-CODE-PROMPT.md` was changed:

| Private reference | Published placeholder |
|---|---|
| SOAR appliance address | `soar.example.internal` |
| AppHost address | `apphost.example.internal` |
| mock AppHost address | `mock-apphost.example.internal` |
| MCP server / test-runner address | `mcp.example.internal` |
| the lab subnet literal in prose | `<lab-subnet>.x` |
| the lab subnet in the A6 grep pattern | `<lab-subnet-regex>` |
| the two addresses quoted as "hardcoded in the old README" | `<lab-soar-ip>`, `<lab-apphost-ip>` |

In `01 §2` the two host labels moved from inside the diagram boxes to the
annotation beside them, because the placeholder names are wider than the
boxes. Intentional generic examples are **not** topology and were kept: the
RFC 1918 deny-list ranges of the policy example (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), the CIDR test address in the `06 P1-06`
acceptance criteria, and org `201`.

`scripts/check_no_secrets.py` scans the baseline documents like every other
tracked file: being authoritative exempts nothing from topology detection.
Its only address allowance in the design pack is that one CIDR test example,
keyed by file and literal value.

## 18. Implementation notes recorded during P1-13 – P1-16

Decisions taken while building, each the conservative reading of the baseline;
none widens the REST surface of §4.

| Where | Note |
|---|---|
| P1-13 `tools/runtime.py` | `Runtime.build()` never raises; a refused configuration makes every tool call `DENY_CONFIG` and the CLI refuses to serve. A `--transport` override is applied to the settings before the P1-11 checks run, so it cannot bypass them. |
| P1-13 `tools/registry.py` | `MUTATION_PENDING` is written before any mutation and an audit failure there refuses the mutation; every other audit write is best-effort and logged. Responses always round-trip through JSON + redaction (tuples become lists). |
| P1-14 `tools/actions.py` | `soar_invoke_action` invokes **incident-scoped** actions only (`object_type == "incident"`), because the known-good body `{"action_id": N}` is incident-scoped; artifact-scoped actions are listed, marked `invocable: false`, and refused (open question Q4). Policy `constraints` are therefore exercised by tests only in this release. |
| P1-14 `tools/actions.py` | The approval plan is built from ids and the operator-named action (`PolicyResult.subject`), never from incident text, so attacker-writable content cannot reach the approver's terminal. |
| P1-14 `tools/incidents.py` | `soar_update_incident` refuses `plan_status`, `resolution_id`, `resolution_summary` so `SOAR_ALLOW_INCIDENT_CLOSE` cannot be bypassed through `SOAR_ALLOW_INCIDENT_WRITES`. |
| P1-14 `tools/projection.py` | Trim limits: description / resolution summary 2 000, note text 2 000, artifact value 1 000, custom field 1 000, names 300 characters, with a visible marker. |
| P1-15 `tools/investigation.py` | `soar_get_incident_full` budget: 60 000 characters of JSON (≈15k tokens); caps 50 tasks / 100 artifacts / 50 notes / 50 attachments, halved until the budget fits. `soar_find_similar_incidents` sends **no filter** (only `sorts` + `length`) and skips the source incident client-side, to avoid relying on an unverified `id` condition (open question Q2/Q3). |
| P1-16 | README claims about SOAR behaviour carry ✅/⚠️/❓ marks and state that ✅ means "documented and modelled offline, not yet verified by this repository". The key-capability startup probe of `01 §6` is documented as not implemented (Q6). |

## 19. Deferred to Session 2 / lab access

Mock AppHost and `tests/lab/` (`07 §7`), T4–T6 test tiers (registered as
markers, skipped without `SOAR_TEST_BASE_URL`), the startup key-capability
probe (`01 §6`; the introspection endpoint is ❓ U12), attachment contents, and
every ⚠️/❓ endpoint of `05 §2–3`.

## 20. P2-00 pointer in `05` (second baseline exception)

Ticket `P2-00` requires `05-SOAR-API-SURFACE.md` to point at the verified
record. On 2026-09-18 one status note was added under the confidence legend of
`05`, naming `docs/soar-api-verified.md` as authoritative for QRadar SOAR
`51.0.9.0.20848`. Nothing else in `05` was changed: its marks and research text
are preserved as the pre-verification history, and the verified record states
where it disagrees. No other baseline document was touched by P2-00.

## 21. P1-CORR-01 — Phase 1 reconciled with the verified v51 API

Decided by the owner on 2026-09-19. `docs/soar-api-verified.md §3` found four
Phase-1 assumptions contradicted on QRadar SOAR `51.0.9.0.20848`. Each is
corrected from what that record verified and nothing else; where the record
does not verify a request shape, the tool is disabled rather than guessed. This
section amends the rows of §3 and §4 marked §21 and supersedes, for these
points only, the task, manual-action and invocation items of §2.1 and the two
`tools/actions.py` notes of §18.

| # | Phase 1 | Now |
|---|---|---|
| D1 | `PATCH /tasks/{id}` | Method/path corrected from the invalid `PATCH` assumption to the verified `PUT` endpoint, but **task mutation remains disabled because the `PUT` request body has not yet been verified.** `soar_update_task_status` stays registered and refuses every call; the client sends nothing to a single task by any method (no `PUT`, no `PATCH`, no `GET /tasks/{id}`), and no body is guessed: not a partial body, a PatchDTO, a full-object `PUT`, a version or any other lock field. Enabling it waits for a live verification of the body (`P2-00b`). |
| D2 | the task's `vers` was required | **Resolved.** Tasks carry no version on this API. Nothing requires one and none is invented; the offline model's tasks have none. |
| D3 | `GET /incidents/{id}/actions` (500, undocumented) | **Resolved.** The `actions` list the incident object carries (`GET /incidents/{id}`). The list was empty on the verified appliance, so its entries' shape is unverified: only a positive integer `id` and a non-empty `name` are used, and anything else fails closed. Actions carried by tasks and artifacts are not listed. |
| D4 | `POST /incidents/{id}/action_invocations` `{"action_id": N}` | **Fail-closed; the invocation contract is unresolved.** `soar_invoke_action` keeps its tier, flag, `approval_id` and `describe()` and refuses every call; the client has no invocation method. With no verified invocation there is no per-call policy classification either, so its effective tier is its declared Tier 3. |

**How the two refusals work.** A tool may be declared `unsupported` with a fixed
refusal text (`tools/registry.py`). `enforce()` gates it like any other tool —
capability flag, configuration, Tier-5 and transport gates first — and then
denies it with `DENY_UNSUPPORTED`, before the approval step. The denial takes
the pipeline's normal denial path, so, as `02 §6` requires of every denial, it
is audited as `DECISION_DENIED`; no `MUTATION_PENDING` is written, no approval
is requested or consumed, the rate counters are untouched and nothing is sent
to SOAR. The tool bodies raise the same fixed refusal as a backstop. Keeping
the two tools registered departs from the last paragraph of §3 (a tool that
cannot be built without guessing is left unregistered): they stay so that the
20-tool contract is stable and the gap stays visible.

Unchanged: incident `PATCH` and its version check; every other row of §4; the
pipeline order. `client/` still has no `PUT` and no `DELETE`.

Still open, and not guessed: the `PUT /tasks/{task_id}` request body, and what,
if anything, protects a task against a concurrent edit; the entry shape of the
carried `actions` lists; the invocation contract; `return_level` (not in this
ticket). See `docs/open-questions.md`. *(The request body has since been verified
by `P2-00b`: §23. `P1-CORR-02` then implemented it and re-enabled
`soar_update_task_status`: §24. `soar_invoke_action` stays disabled.)*

This ticket's only edit to the baseline is one implementation-status note in
`05`, under the P2-00 note.

## 22. P2-TLS — public TLS trust model

Decided by the owner on 2026-09-19. `docs/soar-api-verified.md §6` showed that
the Phase-1 client could not verify an appliance with a private or self-signed
certificate out of the box, and that its only documented ways out were a
bool-or-path `SOAR_VERIFY_SSL` and an ungated `false`. This section defines the
trust model for a public connector; it amends the `SOAR_VERIFY_SSL` item of §14
and adds `02 §7.1` (the fourth baseline exception).

| State | Configuration | Trust source |
|---|---|---|
| Default (`python_default`) | `SOAR_VERIFY_SSL=true` or unset, no `SOAR_CA_BUNDLE` | Python's default TLS trust configuration: whatever `ssl.create_default_context()` exposes on the current platform and Python distribution |
| Private or self-signed CA (`ca_bundle`) | `SOAR_CA_BUNDLE=<pem>` (with verification on) | the explicitly supplied bundle **only**; Python's default trust is not consulted |
| Lab only (`insecure`) | `SOAR_VERIFY_SSL=false` **and** `SOAR_LAB_MODE=true` | none |

The exact default trust-store behaviour varies by platform and Python build. It
is often the operating system's trust store, but this project does not claim
that universally: it uses Python's default as it finds it, reports at start-up
when that default exposes no CA certificates, and never substitutes another
trust source (no `certifi` union or fallback).

Rules, all enforced before any request is sent (`config.py`, `tls.py`):

- The chain **and the host name** are verified in both verifying states. A CA
  bundle changes whom the server trusts, never what it checks; there is no
  setting that keeps the chain check and drops the host-name check.
- Fail closed: an unrecognised `SOAR_VERIFY_SSL`, a `SOAR_CA_BUNDLE` that is
  missing, is a directory or is not PEM, two different bundles, or a bundle
  together with `SOAR_VERIFY_SSL=false` each refuse to start. Nothing reverts to
  another trust source.
- No downgrade: one TLS decision is made when the client is built
  (`tls.build_trust`), and nothing retries a failed handshake, with or without
  verification.
- Out of scope by design: certificate pinning, trust-on-first-use, fetching the
  appliance's certificate, bundling any certificate with the package, modifying
  the operating-system trust store, and any DNS or hosts-file workflow.
- Errors: a verification failure reaches MCP output as one of four categories
  with advice that never includes disabling verification (untrusted issuer →
  `SOAR_CA_BUNDLE`; host-name mismatch → the name in `SOAR_BASE_URL`; validity
  period; other). Messages name variables and never a path, host or port. The
  exception class, OpenSSL's integer verify code and the category are log-only.

**Compatibility with Phase 1.**

| Phase-1 configuration | Now |
|---|---|
| `SOAR_VERIFY_SSL=true` / unset | verified, but against **Python's default TLS trust configuration** instead of the `certifi` bundle `httpx` uses by default. Where that default exposes no CA certificates, the server warns at start-up and `SOAR_CA_BUNDLE` must be set; verification is never dropped. |
| `SOAR_VERIFY_SSL=<path>` | unchanged behaviour (that bundle, verified), plus a deprecation warning pointing at `SOAR_CA_BUNDLE`. |
| `SOAR_VERIFY_SSL=false` | **refused unless `SOAR_LAB_MODE=true`**, with a message naming both variables and `SOAR_CA_BUNDLE`. With lab mode it behaves as before and warns on every start. This is the one deliberate break: it is loud, fails closed, and is what makes the insecure state opt-in. |

`SOAR_LAB_MODE` is reused rather than adding a second acknowledgement flag: on
its own it changes nothing, and `02 §4.1` already uses it the same way for
`in_band` / `disabled` approval. The MCP HTTP transport rules (`01 §2.1`, P1-11)
are untouched.

## 23. P2-00b — the task-status contract, verified (research only)

Recorded on 2026-09-21. `P2-00b` is research: it changed no product code, no tool
contract and no security control. It supplies the evidence §21 (D1) was waiting for; the
record is `docs/soar-api-verified.md §3.1`.

| | |
|---|---|
| Verified on `51.0.9.0.20848` | `PUT /tasks/{task_id}` with an API key and a **full task object** closes and reopens a task. The object comes from the documented `GET /tasks/{task_id}`, read immediately before, deep-copied, with **`status` as the only deliberate change**; `handle_format: ids` and `text_content_output_format: objects_convert` on both requests. The answer is 200 with a `StatusDTO`-compatible body and `success: true`. |
| Not needed | A version field (none was observed or required in this experiment), a client-generated `closed_date` (the server sets it on close and clears it on reopen), any `task_layout` normalisation (the documented `GET` returns an empty list and it is accepted unchanged), and the task tree. |
| The task tree | `GET /incidents/{id}/tasktree` is what the web UI reads, and the first experiment used it. It is **not in the appliance's reference or its Swagger description**: UI-internal and undocumented. It stays out of §4 and out of `client/`; the rule "no invented APIs" covers it. |
| Limits | One custom task, one version, one API-key configuration; no conflict (`409`) was ever seen; closing the last required task of a phase was not tested; an early discrepancy in the task's `perms` map was never explained. |

**What this changes here.** Nothing yet *(at the time of this section; the ticket named
below has since landed, §24)*. §4 still has no single-task call, `client/` still
has no `PUT`, and `soar_update_task_status` still refuses with `DENY_UNSUPPORTED` exactly
as §21 describes. Implementing the verified contract is the separate ticket
**`P1-CORR-02`** (`docs/soar-api-verified.md §8`, `docs/open-questions.md` D7). That
ticket will amend §4 with the two documented calls, `GET /tasks/{id}` and
`PUT /tasks/{id}`, and must keep the single chokepoint and the order of flag,
configuration, tier, transport, approval, rate limit and audit unchanged; it must not
assume an administrator key, and the research credential used by `P2-00b` says nothing
about what a deployment should grant.

This ticket's only edit to the baseline is one research-status note in `05`, under the
P1-CORR-01 note (the fifth exception).

## 24. P1-CORR-02 — the verified task-status contract, implemented

Assigned by the owner on 2026-09-21 (`docs/open-questions.md` D7). This section amends
the `soar_update_task_status` row of §3 and adds two rows to §4. It implements what
`docs/soar-api-verified.md §3.1` verified on QRadar SOAR `51.0.9.0.20848` and nothing
wider; where that record is silent, the tool refuses rather than guesses.

**The sequence** (`client/tasks.py`, `TasksClient.set_status`):

1. `GET /tasks/{task_id}`, with `handle_format: ids` and
   `text_content_output_format: objects_convert` **as headers and no query string** — the
   form the contract was verified in. (Every other call keeps the two Phase-1 query
   parameters.)
2. Deep-copy the object and set `status` (`O` or `C`). Nothing else is touched: no key
   is dropped, added or normalised, `task_layout` goes back as it came, `closed_date` is
   passed through as read, and no version field is sent because none was observed.
3. `PUT /tasks/{task_id}` with that object and the same two headers. Anything but a
   StatusDTO with `success: true` fails the call.
4. `GET /tasks/{task_id}` again; the call fails unless the task shows the requested
   status. A success answer that is not reflected, or a task that cannot be read back, is
   reported as `unverified_write` (a new error class beside the existing ones; it is
   deliberately not `conflict`, because nothing here detects a concurrent edit) with a
   message naming the transition and saying the write was accepted and its result is
   unverified. Nothing is retried and there is no alternate body.

In the audit log such a call is `MUTATION_FAILED` like any other tool error, without
pre/post images; the message carries the requested transition (`O -> C`). The same holds
for a `PUT` that times out or loses its connection: the task's state is unknown, exactly
as for the Phase-1 `POST` tools.

**Refused before any `PUT`**, each as an ordinary tool error after `MUTATION_PENDING`,
like every other Tier-2 validation failure: a status other than `open` / `closed`
(nothing is sent, not even the read); a task that does not exist; a task whose `inc_id`
is not the given `incident_id`, also reported as `not_found` (the pair does not exist),
so an incident id cannot be paired with an unrelated task; a task already in the
requested status (only O → C and C → O were verified); a task that does not report
`active: true` and `frozen: false` (the contract was verified on an active, unfrozen
task). The last two are conservative choices of this ticket, not appliance behaviour,
and are the owner's to relax.

**Security model: unchanged.** The tool is Tier 2 behind `SOAR_ALLOW_TASK_WRITES`, one
mutation per call, no approval step (Tier 2 has none), declared with `@soar_tool` and
executed only by `run_pipeline`: flag, configuration, tier, transport, kill switch,
breaker, mutation cap, `MUTATION_PENDING` before any SOAR traffic, the hourly Tier-2
limit, then exactly one of `MUTATION_COMMITTED` / `MUTATION_FAILED`, then redaction.
Only the `unsupported=` declaration was removed from this one tool; `enforce()`, the
denial order and the `unsupported` mechanism are untouched, and `soar_invoke_action`
still uses it. The audit images are a fixed six-field projection (`id`, `inc_id`,
`status`, `closed_date`, `active`, `frozen`), not the 41-key object; the response is the
existing task projection.

**`PUT` in `client/`.** `SoarClient.put` exists as transport support for this one call.
`request()` refuses `PUT` for any path other than this org's `tasks/{id}` and in any
form but the verified one (the two headers, no query string), the format headers accept
exactly the two verified name/value pairs, and the AST tests allow `PUT` for
`tasks/{id}` only and `.put` in `client/tasks.py` only. No tool exposes a method, a path
or a body to the MCP caller. There is still no `DELETE`.

**Not claimed.** Any SOAR version other than `51.0.9.0.20848`. **Any protection against
a concurrent edit:** no version field was observed on a task and no conflict was ever
seen, so
a change made by someone else between the read and the write can be overwritten; the
read and the write are adjacent, which narrows that window and does not close it. What
closing the last required task of a phase does. Which SOAR permission is the minimum:
the key needs the appliance's task-edit capability, a refusal by SOAR is returned as
the usual sanitised error, and the tool never assumes an administrator key.

**Evidence for this ticket is offline only.** No request was sent to an appliance; the
live evidence is `P2-00b`'s (§23). The offline fake models §3.1 and is deliberately
stricter: it refuses any body that is not the `GET` object with `status` as the only
difference (so a reduced body, an invented version or a client-made `closed_date` cannot
pass), owns `closed_date`, and models no conflict, permission or phase behaviour.

This ticket's only edit to the baseline is one implementation-status note in `05`, under
the P2-00b note (the sixth exception).
