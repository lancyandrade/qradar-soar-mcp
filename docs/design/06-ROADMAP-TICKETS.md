# 06 — Phased Roadmap & Implementation Tickets

**Sizing:** S ≤ half a day · M ≈ 1–2 days · L ≈ 3–5 days · XL — split it further.

**Gate rule:** a phase does not start until every ticket in the preceding phase
is closed, including its tests. Phases 3–6 additionally require the Phase-1
security model to be **enforced by the permission-matrix test** (`P1-13`).

**Milestones:** `v0.2.0` = Phase 1 · `v0.3.0` = Phase 2 · `v0.4.0` = Phase 3 ·
`v0.5.0` = Phase 4 · `v0.6.0` = Phase 5 · `v0.7.0` = Phase 6.

---

## Phase 0 — Repository hygiene (do this today, before any other work)

### P0-01 — Add `.gitignore` and verify no secret has ever been committed
**Depends:** — · **Size:** S · **Priority:** 🔴 blocking everything

`.env`, `*.pem`, `*.key`, `*.p12`, `.venv/`, `__pycache__/`, `*.resz`, `*.res`,
`snapshots/`, `approvals/`, `*.jsonl`, `.pytest_cache/`, `dist/`.

**AC:**
- `.gitignore` committed as the first commit of this work.
- `git log --all --full-history -- .env` returns empty; if not, the SOAR API key
  is rotated in Administrator Settings → API Keys and the rotation is recorded
  in the tracking issue.
- `git check-ignore -v .env` confirms the ignore.

### P0-02 — Add LICENSE, CODE_OF_CONDUCT, SECURITY.md, CONTRIBUTING.md
**Depends:** — · **Size:** S

**AC:** MIT or Apache-2.0 chosen and applied consistently in `LICENSE` and
`pyproject.toml`; `SECURITY.md` states a vulnerability-reporting address and
explicitly warns that this project grants an LLM write access to a security
platform; CONTRIBUTING states the no-secrets and deny-by-default rules.

### P0-03 — Repository skeleton for the target layout
**Depends:** P0-01 · **Size:** S

Create empty packages with `__init__.py` for `client/`, `tools/`, `playbook/`,
`security/`, `catalog/`, plus `tests/`, `docs/`, `examples/`, `config/`.
No behaviour change.

**AC:** `python -c "import qradar_soar_mcp"` still works; `--check` still passes
against the lab; no tool signature changed.

---

## Phase 1 — Stable investigation + controlled actions (`v0.2.0`)

> Goal: the existing 18 tools, unchanged in behaviour, sitting behind a real
> security architecture, under test, in the target package layout.

### P1-01 — Test harness and characterisation tests for existing behaviour
**Depends:** P0-03 · **Size:** M · **Do this before any refactor**

`pytest`, `pytest-asyncio`, `respx` for `httpx` mocking. Write tests that pin
current behaviour: `apply_patch` payload shape, `success:false` raising,
`properties.*` resolution, `handle_format`/`text_content_output_format` on every
request, `_summarise_incident` projection, `ping` degradation when `/session`
403s, `query_paged` filter construction.

**AC:**
- ≥ 25 tests, all passing against the *current* code before any refactor.
- A deliberately introduced regression in `apply_patch` fails a test.
- `pytest` runs offline with no SOAR reachable.

### P1-02 — `config.py`: typed settings with granular capability flags
**Depends:** P0-03 · **Size:** M

`pydantic-settings` model, frozen, holding every flag from
`02-SECURITY-MODEL.md §2`. Validation rules: `SOAR_ALLOW_ACTIONS=true` requires
`SOAR_ACTION_POLICY_FILE` to exist and parse; `in_band` approval + Tier 3
requires `SOAR_LAB_MODE=true`; unparseable boolean ⇒ `false` **plus a warning**,
never `true`. Legacy `SOAR_ALLOW_WRITES` mapping per §2.1. `.env.example`
rewritten, defaulting `SOAR_VERIFY_SSL=true`.

**AC:**
- Absent/empty/garbage values for every flag resolve to `false` (parametrised
  test over all flags × `["", "maybe", "TRUE ", None]`).
- `SOAR_ALLOW_WRITES=true` yields `allow_actions == False` and logs a
  deprecation warning naming the dropped capability.
- Config repr and `model_dump()` never contain the secret (test with a sentinel).
- Startup emits a single INFO line listing exactly which capabilities are on.

### P1-03 — `errors.py` + secret-safe error propagation
**Depends:** P1-02 · **Size:** M

`SoarError` hierarchy with `safe_message` (goes to MCP output) and `detail`
(goes to logs only). All `httpx` exceptions caught and converted; never
propagate an exception carrying a `Request` object. `SecretStr` for the key.

**AC:**
- Test injects a sentinel secret, drives every error path (401, 403, 404, 409,
  500, timeout, TLS failure, malformed JSON), asserts the sentinel appears in
  **no** tool response.
- Error responses still identify the failure usefully (status class + SOAR
  message body, sanitised).

### P1-04 — Split `client.py` into `client/` package
**Depends:** P1-01, P1-03 · **Size:** M

`base.py` keeps `SoarClient` (request, `apply_patch`, `ping`, common params).
Domain modules become thin mixins or accessor classes. **Behaviour-preserving.**

**AC:** every P1-01 test passes unmodified; `--check` output byte-identical;
no new REST call introduced.

### P1-05 — `security/tiers.py` + `security/permissions.py`
**Depends:** P1-02 · **Size:** M

Tier enum, capability→tier map, `enforce(tool, tier, capability, config)`
returning an explicit `Decision(allow|deny|require_approval, reason, code)`.
Denial messages are actionable: name the exact env var to set.

**AC:**
- Every tool has exactly one declared `(tier, capability)`; a test enumerates
  the registry and fails on any tool missing a declaration.
- Default config denies every tier ≥ 1.
- Denial message for `soar_add_comment` names `SOAR_ALLOW_COMMENTS`.

### P1-06 — `security/action_policy.py` + policy schema + example policy
**Depends:** P1-05 · **Size:** L

YAML policy loader per `02 §3`: ordered rules, `match` by name/regex/id, tier,
decision, `destructive`, `constraints` (`artifact_types`, `deny_values` incl.
CIDR containment for IPs, `allow_values`). Unmatched ⇒ Tier 5 / deny. Malformed
policy ⇒ startup failure. Ship `config/action_policy.example.yaml`.

**AC:**
- Unmatched action denies with a message naming the action so the operator can
  classify it.
- CIDR test: policy denying `10.0.0.0/8` blocks `10.4.2.9`.
- Regex rules are anchored/validated; a catastrophic pattern is rejected at load.
- Malformed policy causes exit ≠ 0 with a clear message; **never** falls back to
  permissive (explicit test).

### P1-07 — Rate limits, mutation caps, circuit breaker, kill switch
**Depends:** P1-05 · **Size:** M

Sliding-window counters persisted through the audit log; `MAX_MUTATIONS_PER_CALL`;
3-consecutive-failure breaker on Tier ≥ 2; `SOAR_KILL_SWITCH_FILE` checked
before every Tier ≥ 1 operation.

**AC:**
- 6th Tier-3 call in an hour denies with a clear reason.
- Counters survive a process restart (test writes audit, restarts, asserts).
- Touching the kill-switch file denies the very next mutation; removing it
  restores service without restart.

### P1-08 — `security/audit.py`: hash-chained append-only audit log
**Depends:** P1-03 · **Size:** L

Record shape per `02 §6`. PENDING-before / COMMITTED-after. Pre-image sourced
from the fetch `apply_patch` already performs. Denials logged. Chain verifier
CLI: `qradar-soar-audit verify`.

**AC:**
- Every mutation produces exactly two records; every denial exactly one.
- Editing any historical record makes `verify` fail and names the first broken
  link.
- `SOAR_AUDIT_REQUIRED=true` + unwritable path ⇒ refuse to start.
- Mid-session audit write failure fails the mutation **closed** (test with a
  read-only filesystem).
- No audit content ever appears in MCP tool output.

### P1-09 — `logging.py` with redaction filter
**Depends:** P1-03 · **Size:** S

Structured logging; filter applied to message and args matching the live secret,
`Basic <b64>`, and `Authorization:` headers. stdio transport logs to stderr only
(stdout is the MCP channel — a stray print corrupts the protocol).

**AC:** sentinel-secret test across all log levels; a test asserts nothing is
ever written to stdout in stdio mode.

### P1-10 — `security/approvals.py`: confirmation broker + `qradar-soar-approve` CLI
**Depends:** P1-06, P1-08 · **Size:** L

Out-of-band file broker per `02 §4.2`: request file, HMAC-signed approval,
argument-hash binding, TTL, single-use via atomic rename. CLI prints the full
plan and requires the reference typed back. `soar_check_approval` tool (Tier 0).

**AC:**
- Replay of a consumed approval is rejected.
- Changing any argument after approval invalidates it (hash mismatch).
- Expired approval rejected.
- Forged approval file without valid HMAC rejected.
- In `in_band` mode, tool output **states plainly** that this is not human
  approval (asserted by test on the response text).

### P1-11 — Transport hardening
**Depends:** P1-02 · **Size:** M

Refuse to start streamable-HTTP without `SOAR_HTTP_AUTH_TOKEN`; refuse
`0.0.0.0` bind without `SOAR_HTTP_ACKNOWLEDGE_EXPOSURE=true`; hard-disable
Tier ≥ 3 over HTTP regardless of config; bearer-token check on every request.

**AC:** each refusal has a test; a Tier-3 tool over HTTP denies even with
`SOAR_ALLOW_ACTIONS=true` and a valid approval.

### P1-12 — CI pipeline
**Depends:** P1-01 · **Size:** M

GitHub Actions: `ruff`, `mypy --strict` on `security/` and `playbook/`, `pytest`
with coverage gate, `gitleaks`, `pip-audit`. Pre-commit config mirroring it.

**AC:** PR with a hardcoded key fails CI; PR dropping a permission check fails
`P1-13`; coverage < 85 % on `security/` fails.

### P1-13 — Permission matrix test (the keystone test)
**Depends:** P1-05, P1-06, P1-07, P1-10, P1-11 · **Size:** M

Parametrised across **every registered tool × a matrix of config states ×
transports**, asserting the expected `Decision`. Auto-discovers tools from the
registry so a new tool without a matrix entry **fails the suite**.

**AC:**
- Adding a tool without declaring tier/capability fails CI.
- Default config: every tier ≥ 1 tool denies.
- No tool reaches `client/` without passing `enforce()` — verified by a test
  that monkeypatches the client transport and asserts zero mutating requests
  under default config, across all tools.

### P1-14 — Rewire `server.py` to `tools/` package with the registry
**Depends:** P1-04, P1-13 · **Size:** L

`tools/registry.py` `@soar_tool(tier=…, capability=…)` decorator wiring
enforce → audit → execute → redact. Move the 18 tools into
`tools/{incidents,investigation,actions}.py`. Tool signatures and descriptions
unchanged.

**AC:** all P1-01 tests pass; tool list identical to `v0.1.0`; every mutation
path demonstrably goes through the decorator (grep test: no `tools/` module
imports `client` without the decorator present).

### P1-15 — Investigation quality-of-life
**Depends:** P1-14 · **Size:** M

`soar_get_incident_full` (one call: incident + tasks + artifacts + comments +
attachment metadata, projected and size-capped); `soar_find_similar_incidents`
(artifact-value based, composition of `query_paged`); attachment metadata + hash
with opt-in capped text extraction (`05 §1.2`, U11).

**AC:** full-incident payload for a realistic incident stays under a documented
token budget; attachment content is never returned by default; extracted text is
labelled as untrusted attacker-influenced content in the response.

### P1-16 — Docs: README rewrite, SECURITY.md, threat model, runbooks
**Depends:** P1-14 · **Size:** M

**AC:** README documents every flag and its tier; two-instance deployment
documented as the recommendation; `docs/threat-model.md` and
`docs/runbooks/key-rotation.md` exist; every claim about SOAR API behaviour in
the README is marked with a confidence level or removed.

---

## Phase 2 — Discovery (`v0.3.0`)

### P2-00 — 🔬 Research: verify every ⚠️/❓ endpoint against the lab
**Depends:** Phase 1 complete · **Size:** L · **Blocks all of Phase 2**

Probe each endpoint in `05-SOAR-API-SURFACE.md` §2–3 with a read-only key.
Record path, params, status, sanitised response shape, appliance version.

**AC:** `docs/soar-api-verified.md` committed with real (sanitised) responses;
every ⚠️/❓ resolved to ✅ or 🚫; sanitised fixtures in `tests/fixtures/soar/`;
any endpoint that does not exist is struck from the plan with a note.

### P2-01 — `catalog/` with dual backends
**Depends:** P2-00 · **Size:** L

`Catalog` model per `04 §1`; `collections` and `export` backends;
`SOAR_CATALOG_SOURCE` selects, defaulting to whichever P2-00 proved reliable;
TTL cache; JSON round-trip.

**AC:** catalog loads from a committed fixture with no network; both backends
produce an equivalent `Catalog` for the lab (asserted by a lab-marked test);
`soar_refresh_catalog` (Tier 0) forces reload.

### P2-02 — Discovery tools: functions, scripts, message destinations
**Depends:** P2-01 · **Size:** M

`soar_list_functions`, `soar_get_function`, `soar_list_scripts`,
`soar_get_script`, `soar_list_message_destinations`. All Tier 0.

**AC:** `soar_get_function` returns input names, types and required-ness (the
data L4 validation needs); script bodies are returned read-only and truncated
with a documented cap; no write path exists for scripts anywhere in the codebase
(grep test).

### P2-03 — Discovery tools: types, phases, fields, datatables
**Depends:** P2-01 · **Size:** M

`soar_list_incident_types`, `soar_list_phases`, `soar_list_fields` (generalised
across `incident`/`task`/`artifact`), `soar_list_datatables`.

**AC:** field listing includes type, required-ness, close-required, and picklist
values — the last is what lets Claude set fields correctly instead of guessing.

### P2-04 — Discovery tools: rules and workflows
**Depends:** P2-01 · **Size:** M

`soar_list_rules`, `soar_get_rule`, `soar_list_workflows`, `soar_get_workflow`.
Workflow BPMN XML returned raw is useless to a model and large: return a
**structured summary** (nodes, types, functions referenced, edges) plus the raw
XML only on explicit `include_raw=true`, size-capped.

**AC:** summary of a real lab workflow lists the functions it calls; raw XML is
off by default; oversized workflows truncate with an explicit marker.

### P2-05 — Discovery tools: playbooks
**Depends:** P2-00 (specifically P2-01 research question), P2-01 · **Size:** M

`soar_list_playbooks`, `soar_get_playbook`. If no collection endpoint exists,
implement over the export backend.

**AC:** works on the lab appliance; returns activation type/status, trigger
conditions and referenced functions; documents which SOAR versions it supports.

### P2-06 — Auto-classification assist for `action_policy.yaml`
**Depends:** P2-02, P2-04 · **Size:** M

A CLI (`qradar-soar-policy scaffold`) that enumerates every action/function in
the catalog and emits a policy file with **everything denied at Tier 5** plus a
suggested tier and the reason, for a human to review and edit.

**AC:** scaffold output is valid against the policy schema and denies
everything; running the server with an unedited scaffold reaches SOAR for reads
and denies every action; the CLI never writes over an existing policy file.

### P2-07 — Historical-response analysis tool
**Depends:** P2-04, P1-15 · **Size:** M

`soar_analyse_incident_response(incident_ids)` — for a set of historical
incidents, summarise which rules/playbooks fired, which tasks were used, typical
resolution. This is the evidence base for "how were similar incidents handled
previously".

**AC:** returns a comparative summary for ≥ 5 incidents within the token budget;
degrades gracefully when history endpoints are unavailable.

---

## Phase 3 — IR, validation, simulation (`v0.4.0`)

### P3-01 — `playbook/schema.py`: IR v1 models + JSON Schema
**Depends:** Phase 2 complete · **Size:** L

Pydantic v2 models per `03 §2`, `extra="forbid"`, closed step-type and operator
sets, `ir_version` mandatory.

**AC:** `docs/playbook-ir.schema.json` emitted and CI-checked for drift; the
brief's example YAML parses (after normalisation) and the un-normalised version
fails with the specific errors listed in `03 §5`; a `script`/`python` step type
is a parse error.

### P3-02 — Validator L1–L2 (offline)
**Depends:** P3-01 · **Size:** M

**AC:** cycle, unreachable step, dangling `when`, bad regex, `subplaybook`
recursion, out-of-range `wait` each produce their documented stable error code;
zero network calls (asserted).

### P3-03 — Validator L3–L5 (catalog-backed)
**Depends:** P3-02, P2-01 · **Size:** L

**AC:** runs entirely against a committed catalog fixture; unknown function,
wrong message destination, missing required input, wrong input type, absent
field, uninstalled app, insufficient API-key permission each produce their code
and a `hint` naming the discovery tool to call.

### P3-04 — Validator L6: risk computation
**Depends:** P3-03, P1-06 · **Size:** M

**AC:** computed tier equals max over steps incl. transitive subplaybooks;
understated `risk.max_tier` fails with `IR-E-RISK-UNDERSTATED`; ungated
destructive step fails with `IR-E-UNGATED-DESTRUCTIVE`; any unknown function
forces Tier 5 and marks the document non-compilable.

### P3-05 — `soar_validate_playbook` tool (Tier 0)
**Depends:** P3-04 · **Size:** S

**AC:** report shape per `04 §2.2`; usable with no capability flags set; short-
circuits at the first failing layer and says which layer it reached.

### P3-06 — `playbook/simulator.py`: deterministic offline interpreter
**Depends:** P3-04 · **Size:** L

Graph execution, branch exploration on under-determined mocks, no side effects,
scenario-supplied `now`.

**AC:** identical output across 100 runs (byte-comparison); no HTTP client is
constructible from the simulator (dependency-injection test); every step status
is one of the documented enum values.

### P3-07 — Scenario sources: synthetic / historical / historical_batch
**Depends:** P3-06, P1-15 · **Size:** M

**AC:** `historical` fetches read-only and makes no mutating call (asserted by
transport spy); `historical_batch` respects `SOAR_SIM_MAX_INCIDENTS`; batch
output reports fire-rate and destructive-effect count across the set.

### P3-08 — `soar_simulate_playbook` tool (Tier 0) with mandatory disclaimer
**Depends:** P3-07 · **Size:** S

**AC:** trace shape per `04 §3.4`; `would_touch` present whenever any Tier-3
step is reachable; the disclaimer string is present in every response
(asserted); `policy_check` shows the `deny_values` result for each destructive
step.

### P3-09 — `soar_create_playbook_draft` + `playbook/generator.py`
**Depends:** P3-05 · **Size:** M

Template scaffolding from an incident + intent. Tier 0 — produces YAML text
only, writes nothing.

**AC:** draft always parses under `P3-01`; draft always includes
`approval.required_for` populated for any destructive step it emits; tool output
states no SOAR object was created.

### P3-10 — Golden-file corpus of IR documents
**Depends:** P3-05, P3-08 · **Size:** M

10–15 IR documents in `examples/playbooks/` covering: valid simple, valid
branching, valid with approvals, and one instance of each error class.

**AC:** each has a committed expected validation report and simulation trace;
CI fails on drift; `examples/` is referenced from the README.

---

## Phase 4 — Compilation, export, import (`v0.5.0`)

### P4-00 — 🔬 Research: export/import formats and the PENDING breakdown
**Depends:** Phase 3 complete · **Size:** L · **Blocks Phase 4**

Build a playbook by hand in the lab UI, export it, dissect the bundle. Import it
and capture the PENDING `ImportDTO` breakdown verbatim.

**AC:** `docs/soar-export-format.md` with a real annotated bundle (sanitised);
fixtures committed; the exact two-phase import contract documented; single-
playbook export confirmed or ruled out.

### P4-01 — `playbook/compiler.py`: IR → SOAR bundle
**Depends:** P4-00, P3-04 · **Size:** XL — **split by step type**

Templated composition only; never freehand XML (U1). Deterministic auto-layout.
Refuse rather than approximate any construct it cannot represent.

**AC:** compiling each golden IR produces a byte-stable bundle; a construct
outside the template set raises `IR-E-UNCOMPILABLE` with the step id; Tier-5 /
unknown-function documents cannot be compiled at all.

### P4-02 — `playbook/decompiler.py`: SOAR export → IR (partial)
**Depends:** P4-00, P3-01 · **Size:** L

**AC:** round-trip on golden bundles is semantically stable
(compile→decompile→compile is byte-identical); inline scripts and loops appear
in `unrepresentable` with their category; nothing is silently dropped (a test
asserts every source node is either represented or listed).

### P4-03 — `playbook/diff.py` + `soar_diff_playbook` (Tier 0)
**Depends:** P4-02 · **Size:** M

**AC:** normalisation makes a reordered-but-identical playbook diff clean;
`risk_delta` and `trigger_delta` are surfaced separately and prominently;
non-empty script/loop `unrepresentable` marks the diff `REVIEW_UNSAFE`.

### P4-04 — `soar_export_playbook` (Tier 4, gated)
**Depends:** P4-01 · **Size:** M

Writes a bundle to `SOAR_PLAYBOOK_EXPORT_DIR`. Contacts SOAR **only** for
catalog reads.

**AC:** denied under default config with a message naming
`SOAR_ALLOW_PLAYBOOK_EXPORT`; a transport spy asserts zero calls to
`/configurations/imports`; validation is re-run and must pass before writing;
output path is confined to the configured directory (path-traversal test).

### P4-05 — Pre-import configuration snapshot
**Depends:** P4-00 · **Size:** M

**AC:** snapshot written and SHA-256 audited before any import; snapshot failure
aborts the import; `docs/runbooks/restore.md` written.

### P4-06 — `soar_import_playbook` (Tier 4) — stops at PENDING
**Depends:** P4-04, P4-05, P1-10 · **Size:** L

`POST /configurations/imports`, parse the breakdown, cross-check against our
diff, raise an approval request containing diff + simulation + SOAR's own
breakdown. **Never** commits in the same call.

**AC:** returns at PENDING with an approval reference; a test asserts no
`PUT …/imports/{id}` is ever issued by this tool; discrepancy between SOAR's
breakdown and our diff aborts and reports both; approval request lacking a diff
or simulation reference is refused by the broker.

### P4-07 — `soar_confirm_import` (Tier 4) + lab restore drill
**Depends:** P4-06 · **Size:** M

Verifies approval, commits with `status: ACCEPTED`, audits. Then: actually
perform a restore from snapshot in the lab and document what broke.

**AC:** invalid/expired/replayed approval rejected; committed playbook is
verifiably **disabled** in SOAR (asserted by re-reading it); the restore drill
is documented with its real, honest limitations.

---

## Phase 5 — Controlled enablement (`v0.6.0`)

### P5-00 — 🔬 Research: enable/disable mechanism
**Depends:** Phase 4 complete · **Size:** M · **Blocks Phase 5**

**AC:** either a confirmed documented endpoint recorded in
`docs/soar-api-verified.md`, **or** a written decision that Phase 5 ships as
"import disabled; a human enables in the UI" — which is an acceptable outcome
and should be documented as a deliberate control, not a gap.

### P5-01 — `soar_enable_playbook` / `soar_disable_playbook` (Tier 4)
**Depends:** P5-00 · **Size:** M

Separate capability (`SOAR_ALLOW_PLAYBOOK_ENABLE`) and separate approval from
deploy. Disable requires the capability but a lower approval bar than enable —
turning automation **off** is the safe direction.

**AC:** enabling requires an approval whose payload names the playbook, its
computed tier, and its `would_touch` set from the last simulation; enable is
denied if no successful simulation exists for the deployed version.

### P5-02 — Post-deployment monitoring
**Depends:** P5-01 · **Size:** M

`soar_playbook_executions(api_name, since)` — Tier 0 read of recent runs.

**AC:** returns fire count, success/failure, and which destructive functions ran;
degrades cleanly if execution history is unavailable.

### P5-03 — Staged rollout guidance + auto-disable guard
**Depends:** P5-02 · **Size:** M

**AC:** enabling a Tier-3 playbook emits mandatory guidance to first enable it
with `activation: manual` and observe; if `soar_playbook_executions` shows a
failure rate above `SOAR_PLAYBOOK_FAILURE_THRESHOLD`, the server recommends
disable and **allows disable without a fresh approval**.

### P5-04 — End-to-end lab acceptance
**Depends:** P5-03 · **Size:** L

Drive the brief's full scenario in the lab, from investigation to an enabled
playbook, with a human at each approval gate.

**AC:** a written transcript in `docs/e2e-walkthrough.md` showing every gate;
audit log verifies; every destructive step required an out-of-band approval;
the whole thing is reversible via the documented runbook.

---

## Phase 6 — Cross-platform QRadar SIEM + SOAR (`v0.7.0`)

### P6-01 — Offense linkage surfacing
**Depends:** Phase 5 · **Size:** M

Surface the QRadar offense-id linkage field on incidents (name is
deployment-specific — discover via `soar_describe_incident_fields`, do not
hardcode).

**AC:** `soar_get_incident` includes the linkage when present; absence is
handled without error; the field name is configurable.

### P6-02 — Correlation guidance, not a SIEM client
**Depends:** P6-01 · **Size:** S

**AC:** documentation and tool descriptions guide Claude to use the separate
QRadar SIEM MCP server for offense detail; **no QRadar SIEM API client is added
to this codebase** (asserted by a dependency test).

### P6-03 — Cross-platform playbook patterns
**Depends:** P6-02, P5-04 · **Size:** M

**AC:** ≥ 2 worked examples in `examples/` where a SIEM finding informs an IR
document; each carries its validation report and simulation trace.

---

## Dependency graph (critical path)

```
P0-01 ─► P0-03 ─► P1-01 ─┬─► P1-04 ─┐
                          │           ├─► P1-14 ─► P1-15 ─► P1-16 ─► [v0.2.0]
P0-03 ─► P1-02 ─► P1-03 ─┴─► P1-05 ─► P1-06 ─► P1-10 ─┤
                             P1-05 ─► P1-07 ──────────┤
                             P1-03 ─► P1-08 ──────────┤
                             P1-02 ─► P1-11 ──────────┤
                                      P1-13 ──────────┘   (gate)

[v0.2.0] ─► P2-00 ─► P2-01 ─► P2-02…P2-07 ─► [v0.3.0]
[v0.3.0] ─► P3-01 ─► P3-02 ─► P3-03 ─► P3-04 ─┬─► P3-05 ─► P3-09
                                                └─► P3-06 ─► P3-07 ─► P3-08
                                                          P3-10 ─► [v0.4.0]
[v0.4.0] ─► P4-00 ─┬─► P4-01 ─► P4-04 ─┐
                    ├─► P4-02 ─► P4-03  ├─► P4-06 ─► P4-07 ─► [v0.5.0]
                    └─► P4-05 ──────────┘
[v0.5.0] ─► P5-00 ─► P5-01 ─► P5-02 ─► P5-03 ─► P5-04 ─► [v0.6.0]
[v0.6.0] ─► P6-01 ─► P6-02 ─► P6-03 ─► [v0.7.0]
```

**Longest-pole risks:** `P2-00`, `P4-00` and `P5-00` are research tickets whose
outcome can invalidate downstream design. Schedule them at the *start* of their
phase and be willing to redesign. `P4-01` is the only XL — split it by step type
before starting.
