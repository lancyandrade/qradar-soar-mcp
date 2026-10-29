# Release readiness — REL-01

**Audited commit:** `main` @ `717530e` (merge of PR #18, P1-SEC-01), 2026-10-29.
**Scope:** documentation and verification only. This audit changed no application
code, configuration default, permission rule, REST call, tool or dependency, and sent
**no request to any SOAR appliance**.

Evidence levels used throughout:

| Level | Meaning |
|---|---|
| **Tested** | enforced by a test in `tests/` that ran green locally in this audit (offline, `respx` + `FakeSoar`) |
| **Designed** | stated in `docs/design/` or `08-GREENFIELD-AMENDMENTS.md`, not (yet) enforced by code |
| **Live-verified** | observed on the one lab appliance, IBM QRadar SOAR `51.0.9.0.20848`, during owner-approved research runs recorded in `docs/soar-api-verified.md`; no other version was observed |

---

## 1. Executive summary

- **Phase 0 is complete. Phase 1 is complete in code with recorded deferrals**:
  manual-action invocation is registered but refuses every call (`DENY_UNSUPPORTED`,
  08 §21 D4), so the out-of-band approval broker is built and tested but reachable by
  no tool; attachment hash and text extraction (P1-15) are deferred; the lab test
  tiers T4–T6 and the mock AppHost do not exist (08 §19).
- **Phase 2 is five of eight tickets in.** P2-00 (research), P2-01 – P2-05 have
  landed, three of them with an acceptance criterion met only as far as the evidence
  allows (P2-00, P2-01, P2-03). **P2-06 (policy scaffold CLI) and P2-07 (historical
  response analysis) are not started.**
- The package version is `0.2.0`, but the tree holds **36 tools: the 20-tool Phase-1
  contract plus 16 Phase-2 discovery tools**. The version number understates what
  ships; a changelog must say so.
- Local gates: Ruff, format, mypy `--strict`, the full offline test suite, both
  coverage floors, the repository secret scanner, `pip-audit --strict` and the package
  build all pass (§5). The wheel is clean; the **sdist is not safe to build from a
  developer working copy** (it picked up locally excluded files, H-5). GitHub CI on `717530e` is reported in §5.1 exactly as GitHub
  reported it at the time of writing.
- Release mechanics are missing: **no changelog, no tag (other than a local-only
  reference tag), no GitHub release, no release workflow**, and `main` has **no branch
  protection or ruleset**, so a red CI does not block a merge.
- The baseline release gate (`07 §7.5`) requires T4, T5 and T6 green against a lab.
  None of those tests exists. Releasing needs either that work or an explicit,
  recorded owner waiver for an alpha pre-release.

**Verdict:** `v0.2.0` — **CONDITIONAL GO** as a source-only alpha pre-release
(§10). `v0.3.0` — **NO-GO**: Phase 2 is not complete.

---

## 2. Current implementation and milestone status

| Area | State on `717530e` | Evidence |
|---|---|---|
| Version | `0.2.0` in `pyproject.toml` and `src/qradar_soar_mcp/__init__.py`; pinned by `tests/test_repo_hygiene.py::test_version_is_the_phase_one_milestone` | 08 §15 |
| Milestone map | `v0.2.0` = Phase 1, `v0.3.0` = Phase 2 (`06`) | `06` header |
| Registered tools | 36 (`tests/__snapshots__/test_tools.ambr`): 20 Phase-1 (08 §3), `soar_refresh_catalog` (P2-01), 5 × P2-02, 4 × P2-03, 4 × P2-04, 2 × P2-05 | snapshot + `test_readme_tool_table_is_the_registry` |
| Mutating tools | 7 (Tier 1: 2, Tier 2: 5) plus `soar_invoke_action` (Tier 3, always refuses) | `tests/test_permission_matrix.py`, `tests/test_confirmation_lab_mode.py` |
| Tier-4 tools | none (flags accepted, unused) | 08 §31, threat model §6 |
| CLI entry points | `qradar-soar-mcp`, `qradar-soar-approve`, `qradar-soar-audit` | `pyproject.toml [project.scripts]`; `qradar-soar-policy` (P2-06) does not exist |
| Packages with behaviour | `client/`, `security/`, `tools/`, `catalog/`; `playbook/` is an empty skeleton (Phase 3) | `test_future_phase_packages_hold_no_behaviour` |
| Live-verified appliance | one: `51.0.9.0.20848` | `docs/soar-api-verified.md` |
| Lab-marked tests | **none**; markers `lab`, `lab_write`, `lab_destructive` are registered only | `pyproject.toml`, grep of `tests/` |
| Changelog / tags / releases | none / only `reference/phase-0-1-attempt` (local, never pushed, 08 §12) / none | `git ls-remote --tags origin` empty; `gh release list` empty |

---

## 3. Phase-0/1/2 acceptance-criteria matrix

Status key: **COMPLETE** — every AC met (as amended by `08`), tested; **PARTIAL** — an
AC is deferred or met only as far as evidence allows, and the deferral is recorded;
**BLOCKED** — cannot proceed without an external input; **NOT STARTED**.

### 3.1 Phase 0

| Ticket | Status | Evidence |
|---|---|---|
| P0-01 `.gitignore`, no secret in history | COMPLETE | 08 §2.5; `test_env_is_ignored`, `test_ticket_patterns_are_ignored`, `test_env_never_committed_in_any_ref`; CI gitleaks full-history job |
| P0-02 LICENSE, CoC, SECURITY, CONTRIBUTING | COMPLETE | Apache-2.0 (08 §6); `test_governance_files_present_and_consistent` |
| P0-03 skeleton | COMPLETE (AC amended, 08 §2.6) | `test_skeleton_packages_import`, `test_future_phase_packages_hold_no_behaviour` |

### 3.2 Phase 1 (`v0.2.0`)

| Ticket | Status | Evidence | Deferral / note |
|---|---|---|---|
| P1-01 harness + contract tests | COMPLETE (amended, 08 §2.1) | `tests/fake_soar.py`, `tests/conftest.py`, `test_contract_rest_semantics.py` (47 tests); suite offline | characterisation → contract tests |
| P1-02 typed settings | COMPLETE | `test_config.py` (38), `test_confirmation_lab_mode.py` (24); startup INFO line `config.py` "capabilities enabled: …" | extended by P2-TLS (08 §22), P1-SEC-01 (08 §31) |
| P1-03 errors + secret-safe propagation | COMPLETE | `test_errors.py`, `test_secret_leak.py::test_no_secret_anywhere` (every tool × failure class) | |
| P1-04 `client/` package | COMPLETE (amended, 08 §2.2) | `test_client_surface_ast.py` pins every method/path to 08 §4, §25.3, §26.3, §30.3 | |
| P1-05 tiers + permissions | COMPLETE | `test_permissions.py`, `test_registry_enforcement.py::test_the_registry_declares_what_the_documents_say` | |
| P1-06 action policy | COMPLETE (offline) | `test_action_policy.py` (CIDR, anchored regex, catastrophic regex, malformed ⇒ no fallback, schema drift) | `07 §7.1` asks for the mock AppHost "during P1-06": **not built** (08 §19). Policy `constraints` are exercised by tests only, because no action can be invoked (08 §18) |
| P1-07 limits, caps, breaker, kill switch | COMPLETE | `test_limits.py` (6th Tier-3 call denies, counters survive restart, breaker, kill switch without restart) | |
| P1-08 hash-chained audit | COMPLETE | `test_audit.py`, `test_audit_redaction.py`, `test_registry_enforcement.py` (unwritable/missing audit refuses mutation), `test_registry.py` (no audit field in tool output) | structural redaction fix 08 §27; residuals in 08 §27.5 |
| P1-09 logging + redaction | COMPLETE | `test_logging.py`, `test_stdio_server.py::test_real_stdio_server_speaks_only_protocol_on_stdout` | |
| P1-10 approval broker + CLI | COMPLETE (offline), **unreachable** | `test_approvals.py`, `test_registry_enforcement.py` (replay, argument change, expiry, forgery, other key); Ed25519 per 08 §5; in-band disclaimer asserted | no tool requests an approval in this release (D4) |
| P1-11 transport hardening | COMPLETE | `test_transport.py` (no token ⇒ refuse, `0.0.0.0` needs ack, bearer on every request, Tier 3 over HTTP denies with flag + approval) | |
| P1-12 CI pipeline | COMPLETE | `.github/workflows/ci.yml`; `test_ci_hygiene.py` (every gate present, pre-commit mirrors CI, planted key caught) | security floor is 95 % (08 §16), stricter than 85 %. **No branch protection**, so CI does not technically block a merge (§8, H-3) |
| P1-13 permission matrix | COMPLETE | `test_permission_matrix.py::test_decision`: 36 tools × 14 config states × 2 transports, auto-discovered; `test_chokepoint.py` (transport spy + AST) | |
| P1-14 registry + tools | COMPLETE (amended, 08 §2.3/§2.4) | `test_tools.py` snapshot, `test_registry_enforcement.py::test_every_server_tool_runs_through_run_pipeline` | |
| P1-15 investigation QoL | **PARTIAL** | `soar_get_incident_full` (60 000-char budget), `soar_find_similar_incidents` (client-side N+1): `test_investigation_compositions.py` | attachment hash + opt-in text extraction **DEFERRED-P2** (08 §9). The contents route is live-verified for one `text/plain` attachment's headers only (Q7). The `06` AC "extracted text is labelled untrusted" therefore has no subject |
| P1-16 docs | COMPLETE | README, `SECURITY.md`, `docs/threat-model.md`, `docs/runbooks/key-rotation.md`; `test_docs_consistency.py` (17 tests: every flag + tier, tool table = registry, every API claim marked, links/anchors) | |

Corrective tickets on Phase 1, all COMPLETE: **P1-CORR-01** (08 §21), **P1-CORR-02**
(08 §24, `test_task_status_update.py`), **P2-TLS** (08 §22, `test_tls.py`,
`test_tls_handshake.py`), audit structural redaction (08 §27), **P1-SEC-01** (08 §31,
D13).

### 3.3 Phase 2 (`v0.3.0`)

| Ticket | Status | Evidence | Gap |
|---|---|---|---|
| P2-00 verify ⚠️/❓ endpoints | **PARTIAL** (research done; AC not fully met) | `docs/soar-api-verified.md`, 64+ sanitised fixtures in `tests/fixtures/soar/verified/` | AC "every ⚠️/❓ resolved to ✅ or 🚫" is not met: Q2, Q4, Q5, Q8, Q14, export contents and the meaning of `required` stay ❓/📄 (`open-questions.md`). Each needs a write, an export-capable key or a disposable org |
| P2-00b finish the record | COMPLETE (for what the lab could show) | `soar-api-verified.md §3.1`; D6 | closed incident, note reply, executed playbook, export contents unavailable |
| P2-01 catalog, dual backends | **PARTIAL** | `catalog/`, `test_catalog_*.py`, `soar_refresh_catalog` | `export` backend selectable but always `catalog_unavailable` (403); the "both backends equivalent" lab-marked AC is **deferred** with the export contract (08 §25.1) |
| P2-02 functions, scripts, destinations | COMPLETE | `test_discovery_tools.py`, `test_no_script_writes.py` (AST, mutation-tested) | owner choices open (D9) |
| P2-03 types, phases, fields, datatables | **PARTIAL** | `test_discovery_types_fields.py` | close-required not met as a verified flag (08 §28.3, **D10 open**); `soar_describe_incident_fields` still derives `close_required` from the unverified baseline reading |
| P2-04 rules, workflows | COMPLETE (one workflow observed) | `test_workflow_summary.py`, `test_discovery_rules_workflows.py`; live structure on 2026-10-23 | uuid resolution by exact equality only (D11) |
| P2-05 playbooks | COMPLETE (one playbook observed) | `test_discovery_playbooks.py`; `verified_on: 51.0.9.0.20848` | owner choices open (D12) |
| P2-06 policy scaffold CLI | **NOT STARTED** | no `qradar-soar-policy` entry point or module | — |
| P2-07 historical-response analysis | **NOT STARTED** | no `soar_analyse_incident_response` | history is live-readable; execution rows were zero on the lab (B, "Past function results") |

---

## 4. Security-control verification matrix

| Control | Tested | Designed | Live-verified | Evidence |
|---|---|---|---|---|
| Deny-by-default: every tier ≥ 1 denies with no config | ✅ | ✅ | n/a | matrix `default` state; `test_default_config_sends_no_mutation_through_the_server`; `test_no_mutation_under_default_config` |
| Capability flags fail closed (absent/empty/garbage ⇒ `false`; safety switches ⇒ `true`) | ✅ | ✅ (08 §14) | n/a | `test_config.py` (parametrised) |
| `.env.example` enables nothing | ✅ | ✅ (08 §31.2) | n/a | `test_confirmation_lab_mode.py`, `test_config.py` |
| `SOAR_ALLOW_ACTIONS` needs a parseable policy; malformed policy ⇒ refuse | ✅ | ✅ | n/a | `test_action_policy.py`, `test_config.py` |
| Unmatched action ⇒ Tier 5 deny | ✅ | ✅ | ❌ no action invocable | `test_action_policy.py` |
| Confirmation switches off ⇒ lab mode required | ✅ | ✅ (08 §31.1) | n/a | `test_confirmation_lab_mode.py` |
| **D13**: `in_band`/`disabled` + any Tier-4 flag ⇒ lab mode required | ✅ | ✅ (08 §31.3) | n/a | `test_confirmation_lab_mode.py`; `open-questions.md` D13 resolved |
| `in_band` approval + Tier 3 ⇒ lab mode; disclaimer text | ✅ | ✅ | n/a | `test_approvals.py`, `test_registry.py` |
| Out-of-band Ed25519 approvals: replay, argument binding, TTL, forgery | ✅ | ✅ (08 §5) | ❌ unreachable (no tool asks) | `test_approvals.py`, `test_registry_enforcement.py` |
| Permission matrix (tool × state × transport) | ✅ 1 008 cases | ✅ | n/a | `test_permission_matrix.py` |
| Single chokepoint (no tool reaches `client/` outside `run_pipeline`) | ✅ AST + spy | ✅ | n/a | `test_chokepoint.py` |
| Tier 3 over HTTP always denies | ✅ | ✅ | n/a | `test_transport.py`, matrix |
| HTTP transport: token required, `0.0.0.0` needs ack, bearer every request | ✅ | ✅ | n/a | `test_transport.py` |
| Rate limits, mutation cap = 1, breaker, kill switch | ✅ | ✅ | n/a | `test_limits.py` |
| Audit: PENDING before SOAR, chain, verify names first broken link, fail closed | ✅ | ✅ | n/a | `test_audit.py`, `test_registry_enforcement.py` |
| Audit structural redaction, key-collision refusal | ✅ | ✅ (08 §27) | n/a | `test_audit_redaction.py`; residuals 08 §27.5 |
| Secret never in output/logs/audit/exceptions | ✅ | ✅ | n/a | `test_secret_leak.py`, `test_logging.py` |
| stdout carries only MCP protocol | ✅ (real subprocess) | ✅ | n/a | `test_stdio_server.py` |
| TLS: verification on, CA bundle, `false` lab-only, host name always checked, no downgrade | ✅ (incl. real handshake harness) | ✅ (08 §22) | ✅ CA-bundle mode on the lab (`soar-api-verified.md §6`) | `test_tls.py`, `test_tls_handshake.py` |
| REST allow-list in `client/` | ✅ AST | ✅ (08 §4, §25.3, §26.3, §30.3) | ✅ reads; ⚠️ Tier-1/2 writes except task `PUT` | `test_client_surface_ast.py` |
| No `DELETE`; `PUT` only to `tasks/{id}` in verified form | ✅ | ✅ (08 §24) | ✅ task `PUT` contract (P2-00b) | `test_client_surface_ast.py`, `test_client_base.py` |
| No script write path | ✅ AST, mutation-tested | ✅ (08 §26.4) | n/a | `test_no_script_writes.py` |
| Tool registry = documented contract | ✅ snapshot + docs test | ✅ | n/a | `test_tools.py`, `test_docs_consistency.py` |
| Tier-1/2 write bodies (comment, artifact, create, update, close) | ✅ offline model | 📄 appliance reference | ❌ **not exercised live** | README "Confidence in API claims"; threat model §7 |
| Key permission probe at start-up | — | ✅ (`01 §6`) | 🚫 impossible read-only (Q6) | threat model §6 |

---

## 5. CI, test, coverage and packaging evidence

Environment: Windows 11, `uv 0.11.14`, Python 3.12 (`.python-version`), lock file
`uv.lock` (90 packages resolved). Every command was run from the repository root on
`717530e`, with no `SOAR_*` variable set in the shell; the suite also scrubs `SOAR_*`
itself (`tests/conftest.py`), and `config.py` reads no `.env` file.

| # | Command | Result |
|---|---|---|
| 1 | `uv sync --extra dev --locked` | pass (exit 0; 89 packages checked) |
| 2 | `uv run ruff check .` | pass — `All checks passed!` |
| 3 | `uv run ruff format --check .` | pass — `133 files already formatted` |
| 4 | `uv run mypy` | pass — `Success: no issues found in 55 source files` (strict; `qradar_soar_mcp`, `review_loop`) |
| 5 | `SOAR_BASE_URL= uv run pytest -q --cov=qradar_soar_mcp --cov-report=term-missing --cov-fail-under=80` | pass — **4 090 passed**, 0 failed, 0 skipped, 4 snapshots passed, 432 s; total coverage **98.44 %** (floor 80 %) |
| 6 | `uv run coverage report --include="src/qradar_soar_mcp/security/*" --fail-under=95` | pass — `security/` **99 %** (825 statements, 10 missed; floor 95 %) |
| 7 | `uv run python scripts/check_no_secrets.py` | pass — `check_no_secrets: clean (321 files, design baseline included)`; the 321 include this report |
| 8 | `uv export --locked --extra dev --no-emit-project --format requirements-txt` + `uv run pip-audit --strict --desc --disable-pip --require-hashes -r …` | pass — `No known vulnerabilities found` over 89 locked, hash-pinned third-party requirements |
| 9 | `uv build` | pass — `qradar_soar_mcp-0.2.0.tar.gz` and `qradar_soar_mcp-0.2.0-py3-none-any.whl` built; see packaging below |
| 10 | `uv lock --check` | pass — lock file up to date |
| 11 | gitleaks (full history) | **not run locally** (binary not installed); see CI below |

**Packaging inspection** (archive listings only; the local artefacts were deleted afterwards):

- **Wheel: clean.** 51 entries: the 46 files of `qradar_soar_mcp/` (`.py` and `py.typed` only) plus
  `METADATA`, `WHEEL`, `RECORD`, `entry_points.txt` and `licenses/LICENSE`. Console scripts:
  `qradar-soar-mcp = qradar_soar_mcp.cli:main`, `qradar-soar-approve = qradar_soar_mcp.cli_approve:main`,
  `qradar-soar-audit = qradar_soar_mcp.cli_audit:main`. No tests, probes, fixtures or `automation/`.
- **sdist: not release-safe when built from a developer working copy.** Hatch's sdist honours
  `.gitignore` but not `.git/info/exclude`. On this machine `.claude/` and `.playwright-mcp/` are
  excluded only locally, so the sdist (633 entries) also held **`.claude/settings.local.json`**, a
  complete stale git worktree under `.claude/worktrees/` (319 files) and 6 browser-session logs and
  screenshots. Their contents were not opened. The `[tool.hatch.build.targets.sdist] exclude` list
  (`/.github`, `/automation`, raw probe/fixture dirs) is respected for the top-level tree only; the
  worktree copy re-introduces both. A sdist built from a clean checkout (as CI would) contains none
  of these, but nothing enforces that. See H-5.
- The intended sdist content also includes `tests/`, `docs/`, `scripts/probe/`,
  `CLAUDE-CODE-PROMPT.md`, `.env.example` and `uv.lock` (L-1).

### 5.1 GitHub CI

Workflow `ci`, run `40885222688`, push to `main`, head `717530ec03600f5efb7606638d31e86d635f14d8`:
GitHub reported **`completed` / `success`** (updated 2026-10-29T13:57:50Z), every job
`success`:

| Job | Conclusion |
|---|---|
| secret scan (gitleaks, full history) | success |
| test (ubuntu-latest, 3.12) | success |
| test (ubuntu-latest, 3.13) | success |
| test (windows-latest, 3.12) | success |
| test (windows-latest, 3.13) | success |
| dependency audit (pip-audit) | success |

The `review-loop` / `review-gate` workflows were `skipped` on `main`, as designed (they
act on pull requests that opt in; `docs/runbooks/review-loop.md`). This is a statement
about that commit only; the CI result of this PR is whatever GitHub reports for it.

### 5.2 Not performed

- No T4/T5/T6 lab test (none exists, and live requests were out of scope).
- No local gitleaks run.
- No install of the built wheel into a clean virtual environment and no start of the
  installed server against a fake endpoint beyond what the test suite already does.
- No review of GitHub secret-scanning alerts (needs repository admin UI; push
  protection and secret scanning are reported **enabled** by the API).

---

## 6. SOAR API verification boundaries

- **One appliance, one version:** IBM QRadar SOAR `51.0.9.0.20848`. Nothing is claimed
  for any other version; README, tool descriptions (`verified_on`) and
  `soar-api-verified.md` say so.
- **Live-verified (read surface):** incident query/get, tasks, artifacts, comments,
  attachment metadata, users, field definitions, `/rest/const`, `/rest/session`,
  functions (+ single, + input fields), rules (`/actions`), scripts (+ body),
  workflows (one row, structure only), message destinations, phases, groups,
  incident types, `/types` (data tables), playbooks (`query_paged` + single).
- **Live-verified (write):** only `PUT /tasks/{id}` close/reopen on one disposable
  custom task (P2-00b).
- **Documented, modelled offline, not exercised live:** `POST` comment, `POST`
  artifact, `POST /incidents`, incident `PATCH` (update, assign, close) and its
  stale-version `success:false`.
- **Unverified and not used:** manual-action invocation (Q4, Q5), artifact-value
  search syntax (Q2), configuration export contents (403), attachment contents
  beyond headers, AND/OR filter semantics live (Q14), field `required` semantics
  (D10), playbook enable/disable (`P5-00`).
- **Reproducibility:** probe tooling is in `scripts/probe/` (not in the wheel; it is
  in the sdist, see §5).

---

## 7. Known limitations and deferred functionality

| Item | Deferred to / owner | Recorded in |
|---|---|---|
| `soar_invoke_action` refuses every call; Tier 3 unusable; approval flow unreachable | invocation contract research (Q4) | 08 §21 D4 |
| Attachment hash + text extraction | DEFERRED-P2 | 08 §9 |
| T4–T6 lab tiers, `tests/lab/`, mock AppHost | "Session 2 / lab access" | 08 §19, `07 §7` |
| Start-up key-permission probe | not possible (Q6) | 08 §19, threat model §6 |
| `export` catalog backend; dual-backend equivalence AC | export-capable key in a disposable org | 08 §25.1, D8(e) |
| Close-required semantics; `soar_describe_incident_fields` flag | D10 | 08 §28.3 |
| Concurrent-edit protection on task `PUT` | none exists on 51.0.9 | 08 §24, threat model §7 |
| Audit residuals (clip before redaction, `str()` key merge, numeric secrets, fsync gap, best-effort record collision) | owner | 08 §27.3, §27.5 |
| Owner choices D8, D9, D10, D11(g–l), D12(a–f) | owner | `open-questions.md` C |
| Successful reads not audited; Tier-1 writes uncapped hourly | design choice | README "Known limitations" |
| P2-06, P2-07 | Phase 2 | §3.3 |

---

## 8. Release blockers, ranked

### Critical

None that block a source-only **alpha pre-release** of `v0.2.0`, provided the
conditions in §10 are met. No security control was found unenforced, and no default
was found unsafe.

### High

| # | Blocker | Applies to | Why |
|---|---|---|---|
| H-1 | `07 §7.5` release gate unmet: no T4/T5/T6 tests, no mock AppHost, no `audit verify` over a lab run | v0.2.0 (as a full release), v0.3.0 | The baseline says "no release without" them; 08 §19 defers the work but does not waive the gate. Needs the owner's **recorded waiver** for an alpha, or the lab suite |
| H-2 | No `CHANGELOG.md` and no release notes | v0.2.0 | The `0.2.0` package also contains 16 Phase-2 tools; without a changelog the version misdescribes the content and the deferrals of §7 are not attached to the release |
| H-3 | `main` has no branch protection and no ruleset | all | CI is advisory: a PR that drops a permission check fails `P1-13` but can still be merged. This weakens the `07 §1` principle in practice |
| H-4 | Phase 2 incomplete: P2-06, P2-07 not started; P2-00, P2-01, P2-03 partial | v0.3.0 | `06` gate rule |
| H-5 | The sdist takes whatever is on disk and not in `.gitignore`: built from this working copy it held `.claude/settings.local.json`, a stale worktree and browser logs (§5) | any published sdist | A hand-built release could ship local tool configuration. Fix (separate ticket REL-06): an `only-include` allow-list for the sdist plus a test over the built archive, and build release artefacts only in CI from a clean checkout (REL-04) |

### Medium

| # | Item | Why |
|---|---|---|
| M-1 | Tier-1/2 write contracts (comment, artifact, create, update, assign, close) never exercised live | Operators enabling Tier 1–2 rely on offline modelling and the appliance reference only; documented in README and threat model §7 |
| M-2 | `SECURITY.md` "Supported versions: only the latest release on `main`" while no release exists | Ambiguous until a tag exists |
| M-3 | No release/publishing workflow (build + checksum + provenance on tag) | Release artefacts would be built by hand |
| M-4 | `soar_describe_incident_fields` still reports an unverified `close_required` (D10b) | Inconsistent with `soar_list_fields`; documented |
| M-5 | Dependabot security updates disabled | `pip-audit` runs only on push/PR; new advisories against the lock surface only on the next CI run |

### Low

| # | Item |
|---|---|
| L-1 | sdist includes `scripts/probe/`, `tests/`, `docs/`, `CLAUDE-CODE-PROMPT.md`; harmless (sanitised, scanner-clean) but larger than needed |
| L-2 | Running the suite or the server from the repository root leaves an empty `audit.jsonl` there (git-ignored) |
| L-3 | `playbook/` is an empty skeleton shipped in the wheel (by design until Phase 3) |
| L-4 | Classifier `Development Status :: 3 - Alpha` is correct; README does not state "alpha" in its status table |

---

## 9. Recommended release version and rationale

**Recommend `v0.2.0`**, tagged on the audited `main` commit (or its successor carrying
only the changelog), published as a **GitHub pre-release, source-only** (no PyPI
upload).

- `v0.2.0` is the Phase-1 milestone (`06`); Phase 1 is complete in code with recorded
  deferrals. Version, tests (`test_version_is_the_phase_one_milestone`), README,
  `SECURITY.md` and the threat model all already say `0.2.0`.
- The extra Phase-2 discovery tools are additive Tier-0 reads; pre-1.0 SemVer allows
  them in a minor. The changelog must list them as "early Phase-2 discovery".
- **`v0.3.0` is not ready**: P2-06 and P2-07 are not started and three Phase-2
  tickets are partial. Calling this tree `0.3.0` would claim the Phase-2 milestone.
- Not recommended: `0.3.0a1` / `0.2.1`. They imply either a milestone or a patch that
  does not exist; a changelog is the cheaper and more accurate fix.

---

## 10. Verdict

| Release | Verdict | Conditions |
|---|---|---|
| **`v0.2.0`** | **CONDITIONAL GO** (alpha pre-release, source-only) | (1) GitHub CI green on the tagged commit; (2) `CHANGELOG.md` with the 36-tool content and every deferral in §7 (REL-02); (3) owner records a waiver of `07 §7.5` T4–T6 for this alpha, or the lab suite is built first; (4) owner accepts the P1-15 and D4 deferrals as release scope; (5) any attached sdist is built from a clean checkout, or REL-06 lands first (H-5); (6) recommended before tagging: protect `main` with the CI checks required (H-3) |
| **`v0.3.0`** | **NO-GO** | P2-06, P2-07; the partial ACs of P2-00, P2-01, P2-03 accepted or closed by the owner |

No `v0.2.0` tag, release or version change is made by this PR.

---

## 11. Next engineering tickets, in dependency order

| # | Ticket | Depends | Scope |
|---|---|---|---|
| 1 | **REL-02** — `CHANGELOG.md` + release notes for `v0.2.0` | this audit | docs only; lists Phase-1 contract, 16 Phase-2 tools, every §7 deferral, verified appliance version |
| 2 | **REL-03** — protect `main` (required CI checks, no force-push, PR required) | — | repository settings, owner action |
| 3 | **REL-04** — tag-triggered release workflow: `uv build`, SHA-256 sums, artefact upload, optional attestation; no PyPI | REL-02 | CI only |
| 4 | **REL-05** — owner decision record: waive `07 §7.5` lab gates for the alpha, or schedule LAB-01 first | — | 08 entry |
| 4a | **REL-06** — sdist `only-include` allow-list + archive-content test (no `.claude/`, worktrees, logs, `automation/`, `.github/`) | — | `pyproject.toml` packaging config + one test |
| 5 | **TAG v0.2.0** | 1, 4, 4a or a clean-checkout build (3 recommended) | owner |
| 6 | **P2-06** — `qradar-soar-policy scaffold` (deny-all Tier-5 scaffold, schema-valid, never overwrites) | catalog (P2-02, P2-04 done) | offline-buildable from the committed catalog fixture |
| 7 | **P2-07** — `soar_analyse_incident_response` | P2-04, P1-15 | history reads are live-verified; execution rows were empty on the lab, so degradation is mandatory |
| 8 | **D10 decision / P2-03b** — settle `required` semantics; align `soar_describe_incident_fields` | owner approval for a static read or a close experiment | |
| 9 | **LAB-01** — `tests/lab/` T4 read-only suite against a lab (`SOAR_TEST_BASE_URL`) | lab access | `07 §7` |
| 10 | **LAB-02** — mock AppHost + T5 (org 301) for Tier-1/2 writes, closing M-1 | LAB-01, disposable org | |
| 11 | **P2-00c** — export contract with an export-capable key in a disposable org; then P2-01 dual-backend AC | owner, disposable org | |
| 12 | **Phase-2 close-out review** → **`v0.3.0`** | 6, 7, 8 (+ 9 if the gate is not waived again) | |
| 13 | **P1-INV-01** — manual-action invocation contract (Q4/Q5) research, then T6 against the mock AppHost | LAB-02 | unlocks Tier 3 and the approval flow |
