# LAB-03 — T3 Golden-Test Release Gate (proposed ticket)

**Status:** proposed, not implemented. **Scope pending D22 (open):** nothing in §3 –
§9 is adopted until the owner decides D22 and approves the output list. **Owner decision D21 (2026-10-30):** T3 golden
tests remain a mandatory release gate; no waiver is granted. `v0.2.0` is NO-GO until
the T3 gate item is evidenced (and the T4/T5/T6 items, D14).

**Naming:** the owner named this ticket `LAB-03`. The Sprint 1 lab plan had used
`LAB-03` for the T6 mock-AppHost work; that work is renamed **`LAB-04`**
([`lab-validation-plan.md`](../lab-validation-plan.md) §4).

## 1. What the baseline actually requires

Quoted from [`07-TEST-STRATEGY.md`](../design/07-TEST-STRATEGY.md):

| Where | Text |
|---|---|
| §2 tier table | `T3 Golden` · marker `@pytest.mark.golden` · network **none** · runs **every commit** |
| §2 | "`pytest` with no configuration must run green offline on a fresh clone" |
| §6.2 Validator | "**One golden document per error code.** `docs/error-codes.md` is generated from the corpus, and a test fails if a code exists in the source with no corresponding golden document." |
| §6.3 Simulator | "**Determinism:** run each golden scenario 100× and byte-compare." |
| §6.4 Compiler / decompiler | "`compile → decompile → compile` is byte-identical for every golden IR." |
| §7.5 Release gate | "No release without: All T1–T3 green in CI." |

Related tickets in [`06-ROADMAP-TICKETS.md`](../design/06-ROADMAP-TICKETS.md):
`P3-10` (golden-file corpus of 10–15 IR documents in `examples/playbooks/`, each with a
committed expected validation report and simulation trace; "CI fails on drift"),
`P4-01` and `P4-02` (golden bundles, byte-stable).

The marker is registered in `pyproject.toml` (`golden: T3 golden-file tests`).

### 1.1 Ambiguity (recorded, not resolved here)

Every concrete T3 requirement in `07` and `06` is about **Phase-3/4 artefacts**: IR
documents, validation reports, simulation traces and compiled bundles. None of these
exists in `v0.2.0`: `src/qradar_soar_mcp/playbook/` is an empty package
(`tests/test_repo_hygiene.py::test_future_phase_packages_hold_no_behaviour`). The
baseline does **not** say what a golden test is for a Phase-1/2 release.

So two readings are possible, and choosing one is the owner's call: open question
**D22** ([`open-questions.md`](../open-questions.md)), **not decided**:

- **(A) Phase-scoped.** T3 applies to the IR corpus; until Phase 3 there is nothing to
  golden-test. Under D21 this reading leaves the gate unmeetable for `v0.2.0`, and so
  it would need an amendment that D21 explicitly does not grant.
- **(B) Release-scoped (proposed).** T3 is "golden-file tests of every deterministic,
  user-visible output this release produces", with the IR corpus of `P3-10` added in
  Phase 3. This ticket **details** (B) so the owner can judge it; it does **not**
  adopt it. The exact output list in §3 is a **proposal**: the baseline does not name
  it, and it must be approved before implementation. If the owner chooses (A), or
  amends (B), §3 – §9 change accordingly.

Nothing below is presented as a baseline requirement except what §1 quotes.

## 2. What exists today

| Asset | What it is | Counts towards T3? |
|---|---|---|
| `tests/__snapshots__/test_tools.ambr` (syrupy) | 4 snapshots: the tool manifest (names, descriptions, schemas, annotations), the incident projection field list, a projected `soar_get_incident`, a task-status update result | **Partly**: they are golden comparisons, but carry no `golden` marker and are not documented as T3 |
| `tests/fixtures/soar/` (`incident_42.json`, `incident_fields.json`, `task_objects.json`, `collections.json`) | synthetic, sanitised inputs for the contract model | inputs only |
| `tests/fixtures/soar/verified/` (138 files) | sanitised response shapes recorded from the one lab appliance | inputs only; shape tests, not golden outputs |
| `tests/fixtures/catalog/lab-v51.json` + `tests/test_catalog_fixture.py` | the committed offline catalog; the test rebuilds it and compares | **Partly**: a regenerate-and-compare golden check, unmarked |
| `tests/workflow_data.py`, `tests/playbook_data.py`, `test_workflow_summary.py`, `test_discovery_playbooks.py` | synthetic BPMN documents and assertions on their summaries | assertion-based, not golden files |
| `tests/test_permission_matrix.py` | 36 tools × 14 states × 2 transports, expected decisions in code | an expected-output table in code; not a golden file |
| `tests/test_docs_consistency.py` | README tables compared with the registry | consistency, not golden |
| `@pytest.mark.golden` | registered | **no test uses it** |
| Snapshot review procedure | — | **none documented** (no `--snapshot-update` rule in `CONTRIBUTING.md`) |

## 3. Missing golden tests (proposal under reading B)

Each is an expected output committed under `tests/golden/`, compared byte for byte (after
canonical JSON serialisation: sorted keys, `\n` line endings, UTF-8, no trailing
whitespace), and marked `@pytest.mark.golden`:

| # | Output | Input | Why it matters |
|---|---|---|---|
| G1 | MCP tool manifest | the registry | any change to a tool's name, description, schema or annotations is a reviewed event (move the existing snapshot) |
| G2 | Projected responses of every Tier-0 tool | `FakeSoar` + `tests/fixtures/soar/` | what the model sees; catches a projection that starts leaking a field |
| G3 | Every denial message, per tool × config state × transport | the permission-matrix states | operators act on these messages ("name the exact env var", `06 P1-05`) |
| G4 | `qradar-soar-mcp --check` JSON report for fixed configurations | synthetic env, `FakeSoar` | the operator's startup evidence; must contain no secret |
| G5 | Startup capability summary line and each refusal message of `Settings.load` | synthetic env | security-relevant configuration errors |
| G6 | Audit records for one denial, one mutation (PENDING + COMMITTED), one hourly-cap denial | fixed clock and request ids | the record shape `02 §6` defines and §32.1 amends |
| G7 | Catalog built from `lab-v51.json` and the discovery tool outputs over it | committed catalog fixture | move the existing regenerate-and-compare check under the marker |
| G8 | Workflow and playbook structural summaries | `workflow_data.py`, `playbook_data.py` | summaries feed future validation (P3-03) |
| G9 | Error responses (`SoarError.to_dict()`) per failure class | `FakeSoar` failure modes | sanitised `safe_message` content (P1-03) |
| G10 *(Phase 3)* | IR corpus, validation reports, simulation traces (`P3-10`) | `examples/playbooks/` | the baseline's own T3; added when Phase 3 starts |

## 4. Fixtures and expected outputs

- **Deterministic:** frozen clock (`freezegun`, already a dev dependency, or the
  `clock`/`now` callables `Runtime.build` accepts), fixed request ids (patch
  `qradar_soar_mcp.tools.registry.new_request_id`, which the pipeline imports by name,
  with a counter in tests; no `uuid4` value in golden
  output), fixed ordering (sorted keys; lists in source
  order), no absolute paths (replace `tmp_path` with a placeholder before comparing),
  no platform line endings.
- **Sanitised:** synthetic values only, using the placeholders `scripts/check_no_secrets.py`
  allows (`soar.example.com`, documentation IP ranges). The sentinel secret of
  `tests/conftest.py` is injected into every input; a golden test fails if it appears in
  any expected file. `check_no_secrets.py` scans `tests/golden/` like everything else.
- **Located** in `tests/golden/<group>/<case>.json` with a short `README.md` per group
  naming the generator test.

## 5. Offline only

- No network: the golden tests use `FakeSoar` behind `respx` with `assert_all_mocked`,
  or no client at all. A golden test that needs a live appliance is a T4 test, not T3.
- They read no `SOAR_*` variable (the root `conftest.py` scrub applies) and no `.env`.
- They run in the default `pytest` invocation on a fresh clone.

## 6. Failure behaviour when an output changes

- Any difference fails the test with a unified diff of expected vs actual, truncated to
  a readable size, and the path of the expected file.
- A golden test never rewrites its expected file during a normal run.
- A missing expected file fails (never "created on first run").
- An expected file with no test that produces it fails (orphan check), so stale golden
  files cannot accumulate.
- A golden file containing the sentinel secret, a private address or an internal host
  fails, regardless of the comparison.

## 7. Review and approval of expected outputs

- Regeneration is explicit: `uv run pytest -m golden --golden-update` (a project option
  that writes expected files) or `--snapshot-update` for syrupy snapshots. CI never
  passes either flag; a test asserts that the CI workflow does not contain them.
- A PR that changes any file under `tests/golden/` or `tests/__snapshots__/` must say why
  in its description, and a human reads every changed expected file before merge.
- **Under REL-03 phase 1 this review is a manual maintainer responsibility, not an
  enforced control.** Phase 1 requires a pull request but 0 approvals and no code-owner
  review (`docs/runbooks/rulesets/main-phase1.json`), so a PR with no review threads can
  merge with regenerated expectations nobody read, and a regenerated expectation can
  make an output regression pass CI. A test that only asserts the expected files are
  present cannot detect that.
- **Enforcement, once a second maintainer exists:** a `CODEOWNERS` entry for
  `tests/golden/` and `tests/__snapshots__/`, and a ruleset change to
  `require_code_owner_review: true` with `required_approving_review_count: 1`. Both are
  owner decisions on repository settings and are **not** part of this ticket; until
  then, the release-gate evidence of §9 must state that golden-file changes since the
  last release were reviewed by hand, and by whom.
- Changes to G1 (tool manifest), G3 (denials) and G6 (audit shape) are
  security-relevant and are listed in the changelog.
- Procedure documented in `CONTRIBUTING.md`.

## 8. CI integration and coverage

- No CI change is needed to run them: `ci.yml`'s `pytest` runs every marker, so the
  golden tests run on all four test jobs (Ubuntu/Windows × 3.12/3.13), and the six
  required checks of REL-03 cover them.
- Add a guard test: at least one test carries `golden` per group G1–G9, and none of them
  is skipped in CI (a `-m golden` run in the default job must report zero skipped).
- Coverage: the existing floors stay (overall ≥ 80 %, `security/` ≥ 95 %); golden tests
  must not be the only coverage of a security branch (they pin outputs, unit tests pin
  logic). `playbook/` ≥ 90 % applies once Phase 3 adds behaviour (08 §11).

## 9. Release-gate evidence and acceptance criteria

**Acceptance criteria:**

1. The owner has chosen reading A or B (D22), and this ticket's §3 list is approved or
   amended in writing.
2. Every approved output group has at least one `@pytest.mark.golden` test with a
   committed expected file under `tests/golden/` (or a syrupy snapshot moved under the
   marker).
3. Golden tests are deterministic: each golden test run 100× in one process produces
   byte-identical output (`07 §6.3`'s determinism rule, applied here).
4. Offline: the golden suite passes with the network disabled (a socket guard) and no
   `SOAR_*` variable.
5. Failure behaviour of §6 is tested: a changed output, a missing expected file, an
   orphan expected file and a planted sentinel each fail.
6. Regeneration needs an explicit flag that CI never passes (asserted).
7. The review procedure of §7 is in `CONTRIBUTING.md`, and says plainly that under
   REL-03 phase 1 it is a manual maintainer responsibility, not enforced by the ruleset.
8. `check_no_secrets.py` and `check_artifact_hygiene.py` stay clean; packages unchanged
   (no golden files in the sdist or wheel).

**Gate evidence** (recorded in `docs/release-readiness.md` for the release commit): the
GitHub CI run id on the commit to be tagged, with `uv run pytest -m golden -q` output
from that run showing *N passed, 0 skipped, 0 failed* and N ≥ the number of approved
groups, plus a signed-off line naming who reviewed every golden-file change since the
last release (while review is not enforced by a ruleset, §7). Only then may the release
documents say the T3 gate item is met.

## 10. Out of scope

Implementation (a later PR), the Phase-3 IR corpus itself (`P3-10`), any change to the
tool surface, and the T4/T5/T6 lab work.
