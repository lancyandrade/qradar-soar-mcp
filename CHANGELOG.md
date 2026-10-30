# Changelog

All notable changes to `qradar-soar-mcp` are recorded here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before `1.0.0` a minor
version can add tools and change behaviour.

Milestones (`docs/design/06-ROADMAP-TICKETS.md`): `v0.2.0` = Phase 1, `v0.3.0` = Phase 2.
No version of this project has been published yet. There was never a `0.1.0`
implementation ([08 §1](docs/design/08-GREENFIELD-AMENDMENTS.md#1-premise-correction-there-was-never-a-v010-implementation)).

## [Unreleased]

Nothing yet. Changes merged after the `v0.2.0` tag is created go here.

## [0.2.0] - Pending (alpha)

**Status: alpha, pending publication.** This section describes `main` as it stands; no
`v0.2.0` tag or GitHub release exists yet, and no release date is claimed. The release
gate is **not passed** (see [Release prerequisites](#release-prerequisites-not-yet-met)).
Release notes: [docs/releases/v0.2.0-alpha.md](docs/releases/v0.2.0-alpha.md).

`0.2.0` is the Phase-1 milestone. It also contains 16 early Phase-2 discovery tools, so
it ships **36 MCP tools: 20 Phase-1 and 16 Phase-2**. Phase 2 is incomplete, and
`v0.3.0` is not ready.

### Added

#### Phase 1: 20 tools

The approved Phase-1 contract ([08 §3](docs/design/08-GREENFIELD-AMENDMENTS.md#3-approved-phase-1-tool-contract-p1-14-amendment)).

- **Investigation, Tier 0 (always on):** `soar_search_incidents`, `soar_get_incident`,
  `soar_get_incident_full` (incident, tasks, artifacts, notes and attachment metadata
  under a 60,000-character budget), `soar_find_similar_incidents` (client-side
  composition over recent incidents), `soar_list_artifacts`, `soar_list_tasks`,
  `soar_list_comments`, `soar_list_attachments` (metadata only), `soar_list_users`,
  `soar_describe_incident_fields`, `soar_list_incident_actions`, `soar_check_approval`.
- **Annotate, Tier 1 (off by default):** `soar_add_comment`, `soar_add_artifact`.
- **Modify, Tier 2 (off by default):** `soar_create_incident`, `soar_update_incident`
  (optimistic concurrency; closing fields refused), `soar_assign_incident`,
  `soar_close_incident`, `soar_update_task_status` (status only).
- **Respond, Tier 3:** `soar_invoke_action`, registered but **refuses every call** as
  `DENY_UNSUPPORTED` (see [Known Limitations](#known-limitations)).
- Every incident is projected to a fixed field list; free text is trimmed with a
  visible marker, and attachment names and content types are trimmed too.

#### Early Phase 2: 16 discovery tools

All Tier 0 and read-only. They answer from a cached catalog of the SOAR configuration
that holds a fixed projection of each object, never the object itself.

- **Catalog (P2-01):** `soar_refresh_catalog`. The default source is the read-only
  collection endpoints (`SOAR_CATALOG_SOURCE=collections`); the cache lifetime is
  `SOAR_CATALOG_TTL_SECONDS`.
- **Functions, scripts and message destinations (P2-02):** `soar_list_functions`,
  `soar_get_function`, `soar_list_scripts`, `soar_get_script`,
  `soar_list_message_destinations`. A script body is read on demand, redacted, cut at
  20,000 characters, labelled untrusted and never run.
- **Incident types, phases, fields and data tables (P2-03):** `soar_list_incident_types`,
  `soar_list_phases`, `soar_list_fields`, `soar_list_datatables`. `required` is SOAR's raw
  token; no flag is derived from it. Data tables are definitions only, never rows.
- **Rules and workflows (P2-04):** `soar_list_rules`, `soar_get_rule`,
  `soar_list_workflows`, `soar_get_workflow`. Workflows are structural summaries of
  their BPMN XML; the raw XML is returned only with `include_raw=true`, filtered, cut
  at 50,000 characters and labelled untrusted.
- **Playbooks (P2-05):** `soar_list_playbooks`, `soar_get_playbook`. Structure,
  activation-condition fields and the functions a playbook calls; never the playbook XML
  or the values its conditions compare with.

#### Command-line tools

- `qradar-soar-mcp`: the server (stdio by default, streamable HTTP optional), plus
  `--check` (configuration report and one read-only search call) and `--version`.
- `qradar-soar-approve`: Ed25519 key generation, request listing and out-of-band
  approval.
- `qradar-soar-audit verify`: walks the audit hash chain.

#### Documentation

- README with tier, tool and configuration reference; [SECURITY.md](SECURITY.md);
  [threat model](docs/threat-model.md); [key-rotation runbook](docs/runbooks/key-rotation.md);
  [open questions](docs/open-questions.md); the live API record
  [docs/soar-api-verified.md](docs/soar-api-verified.md); the
  [release-readiness audit](docs/release-readiness.md).

### Security

Controls enforced by code and tests in this release:

- **Deny by default.** Every capability flag is off. An absent, empty or unparseable
  flag is `false`; an unparseable safety switch is `true`. `.env.example` enables
  nothing.
- **One enforcement pipeline.** Every tool runs through it: capability flag, policy
  classification, tier, transport, unsupported-tool refusal, kill switch, circuit
  breaker, one-object cap, approval, audit, hourly cap, the SOAR call, audit,
  redaction. An AST test and a transport spy fail the build if a tool reaches the SOAR
  client any other way. The permission matrix covers every tool, 14 configuration
  states and both transports.
- **Blast-radius limits.** One object per call; 25 Tier-2 and 5 Tier-3 mutations per
  hour, rebuilt from the audit log on restart; a circuit breaker after three
  consecutive Tier ≥ 2 failures; a kill-switch file that denies every Tier ≥ 1 call
  without a restart.
- **Hash-chained audit log** of every denial, approval event and mutation attempt. A
  mutation is refused if its pending record cannot be written. Records are redacted
  string by string before hashing.
- **Approvals.** Out-of-band Ed25519 approvals bound to the tool and exact arguments,
  with expiry and replay protection. The server holds only the public key.
- **Lab-only switches** (P1-SEC-01, [08 §31](docs/design/08-GREENFIELD-AMENDMENTS.md#31-p1-sec-01--confirmation-switches-are-lab-only-the-example-enables-nothing)).
  `SOAR_VERIFY_SSL=false`, `SOAR_REQUIRE_ACTION_CONFIRMATION=false`,
  `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION=false`, and `in_band` or `disabled` approval with
  actions or any Tier-4 flag enabled each refuse to start without `SOAR_LAB_MODE=true`.
- **Transport.** HTTP needs a bearer token, binding all interfaces needs an explicit
  acknowledgement, and Tier ≥ 3 is always denied over HTTP. stdout carries only the
  MCP protocol.
- **TLS.** Verification is on by default against Python's default TLS trust
  configuration, with an optional CA bundle; the host name is always checked.
- **Secret hygiene.** The SOAR key and the bearer token are redacted from output, logs,
  errors and audit records; CI runs gitleaks over the full history and a tree scanner.
- **No script writes, no `DELETE`, no generic REST call.** The REST surface is an
  allow-list pinned by an AST test; `SOAR_ALLOW_SCRIPT_WRITES=true` refuses to start.
- **Packaging (REL-06).** The sdist is now built from an explicit allow-list
  (`only-include`: the package, `pyproject.toml`, `README.md`, `LICENSE`).
  `tests/test_packaging.py` builds both archives with canary files in place and fails if
  anything outside that list gets in. Before the change, an sdist built from a
  developer working copy could pick up locally excluded files.

### Changed

Corrections made during development, before any release:

- **Phase 1 reconciled with the verified v51 API** (P1-CORR-01, P1-CORR-02). Task status
  uses the verified `GET` → `PUT /tasks/{id}` → `GET` contract with `status` as the only
  change. Manual actions are read from the incident's own `actions` list. Action
  invocation fails closed.
- **TLS trust** (P2-TLS). `SOAR_CA_BUNDLE` replaces passing a CA path in
  `SOAR_VERIFY_SSL`; the old form still works and is deprecated.
- **Confirmation switches are lab-only and `.env.example` sets every capability flag to
  `false`** (P1-SEC-01, owner decision D13).
- `SOAR_ALLOW_WRITES` is deprecated. It maps to the five Tier 1–2 flags with a warning,
  never to `SOAR_ALLOW_ACTIONS`, and will be removed in the next minor version.

### Fixed

- **Audit records are redacted structurally** ([08 §27](docs/design/08-GREENFIELD-AMENDMENTS.md#27-audit-records-are-redacted-structurally-correction-after-p2-02)).
  Previously the serialised record was redacted as one string. Attacker-influenced text
  could break the record or consume neighbouring values, and a secret containing a
  quote or backslash could reach the log unredacted.
- **Hourly caps** (P1-14). A write whose final audit record was lost now still counts
  after a restart. Rebuilding the caps from a malformed audit log no longer crashes or
  frees budget.
- **Investigation output** (P1-15). `soar_get_incident_full` fails with
  `response_too_large` rather than exceed its budget. Attachment names and content
  types are trimmed. Shared artifact values in `soar_find_similar_incidents` are
  trimmed.
- **Development dependency advisory.** `msgpack` was upgraded in `uv.lock` past
  CVE-2026-114613. It is pulled in only through the dev-only `pip-audit` tooling; runtime
  dependencies did not change.

### API compatibility

- Live verification covers **one appliance version: IBM QRadar SOAR
  `51.0.9.0.20848`**. Nothing is claimed for any other version.
- The read surface and the task-status `PUT` were verified live in owner-approved
  research runs. The other writes (notes, artifacts, incident create, update, assign and
  close) follow the appliance's API reference and the offline contract model, and were
  **not exercised live**.
- The REST calls the client may make are exactly those listed in
  [08 §4](docs/design/08-GREENFIELD-AMENDMENTS.md#4-phase-1-rest-surface-p1-04-amendment-rule-no-invented-apis),
  §25, §26 and §30, enforced by `tests/test_client_surface_ast.py`. There is no `DELETE`
  and no script write.
- Per-claim confidence marks are in the README section
  [SOAR API behaviours this client relies on](README.md#soar-api-behaviours-this-client-relies-on).

### Known Limitations

- **Phase 2 is incomplete.** P2-06 (policy scaffold CLI) and P2-07 (historical-response
  analysis) are not started. P2-00, P2-01 and P2-03 are partial.
- **Manual-action invocation is unavailable.** `soar_invoke_action` always returns
  `DENY_UNSUPPORTED` and sends nothing to SOAR; the invocation contract is unverified.
  Tier 3 is therefore unusable.
- **The approval broker is implemented but unreachable.** It is built and tested
  offline, but no supported action tool reaches it, and Tiers 1–2 never ask for
  approval.
- **No Tier-4 tools.** No tool creates, changes, exports, imports, deploys or enables a
  playbook. The Tier-4 flags are accepted and unused.
- **Attachment hash and text extraction are deferred.** Attachment contents are never
  fetched.
- **Tier-1/2 mutations are offline-contract-tested, not live-validated**, except the
  task-status change. That change has no protection against a concurrent edit.
- **T4/T5/T6 lab validation has not run.** Opt-in, guarded T4 read-only tests are
  scaffolded under `tests/lab/` (LAB-01) and skip unless explicitly enabled; no T5 or T6
  test and no mock AppHost exist, and no lab audit verification has been run. Live
  evidence comes from one-off research runs.
- The `export` catalog backend is selectable but always unavailable.
  `soar_describe_incident_fields` still derives `close_required` from an unverified
  reading (D10 open).
- No start-up probe of the API key's permissions is possible with a read-only key.
- Successful reads are not audited. Tier-1 writes have no hourly cap.
- **No production-readiness claim** is made for this release.

### Release prerequisites (not yet met)

`v0.2.0` is **NO-GO** until the lab gate is evidenced
([docs/release-readiness.md §13.3](docs/release-readiness.md#133-verdict)). Owner decisions
of 2026-10-29 (REL-05, [08 §32](docs/design/08-GREENFIELD-AMENDMENTS.md#32-rel-05--owner-release-decisions-for-v020-2026-10-29)):

- **T4/T5/T6 have not been waived.** The `07 §7.5` lab gate must pass first: T4 green
  against the lab, T5 green in a disposable organisation, T6 green against a mock
  AppHost, and `qradar-soar-audit verify` clean over the run. No waiver has been
  recorded, and none will be for this alpha.
- The P1-15 attachment-processing deferral and the D4 limitation (invocation refuses,
  approval broker unreachable) are **accepted as alpha scope**. Neither feature is
  implemented.
- **T3 golden tests are mandatory and missing** (owner decision D21, 2026-10-30; no waiver). No test
  carries the `golden` marker yet; the proposed work is LAB-03
  ([docs/proposals/LAB-03-t3-golden-test-gate.md](docs/proposals/LAB-03-t3-golden-test-gate.md)).
- A T6 run that only shows every action being refused is evidence of correct rejection, not of
  successful execution or approval enforcement (D20); full T6 needs every `07 §7.4` step.
- GitHub CI green on the commit to be tagged.
- **REL-04** (tag-triggered CI release build) is open. Until it lands, no wheel, sdist
  or other build artefact is attached to a release or published, and nothing is
  uploaded to PyPI.
- Recommended before tagging: protect `main` with required CI checks (REL-03; the
  configuration is prepared for review in
  [docs/runbooks/branch-protection.md](docs/runbooks/branch-protection.md), not applied).
