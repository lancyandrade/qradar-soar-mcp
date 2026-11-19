# Phase-2 close-out: provisional owner decisions and implementation plan

**Status: PROVISIONAL. Nothing in this document is approved, resolved or accepted.**
It records the owner's *proposed* selections for D26 (a), D26 (b), D10 / D26 (c) and
D22, and plans the work they imply, for owner review. No acceptance criterion, test-
strategy text or release gate is amended here. D10, D22 and D26 stay **Open** in
[`open-questions.md`](../open-questions.md) until the owner records a decision.

Baseline: `main` @ `6c9d269` (PR #28, the Phase-2 close-out review, merged).
[`release-readiness.md`](../release-readiness.md) §14 records `v0.3.0` **NO-GO** and
Phase 3 **NOT YET**. This plan changes neither verdict: the T3, T4, T5 and T6 release
gates stay mandatory, and Phase 3 stays NOT YET.

Constraints carried unchanged: no waiver of T3, T4, T5 or T6; no lab write, export
`POST`, action invocation or close experiment without separate explicit approval; no
mutation outside a disposable org; TLS verification stays on; no credential or sensitive
response body in logs, fixtures, commits or PR text; fail-closed, permission and
approval controls unchanged; no version bump, tag or release; no Phase-3 code.

## 1. Provisional decision record

| # | Proposed selection | What it means | What it does **not** do | AC / gate text changed? |
|---|---|---|---|---|
| **D26 (a)** P2-00 | Close the open ⚠️/❓ items **by work**, not by accepting them as permanent limitations | Every item of §2 gets a read-only probe, a separately authorised experiment, or stays explicitly open | Does not run any write, invocation, export or close; does not resolve any item without lab evidence | **No.** See §1.1 for a bounding question the owner may need to answer later |
| **D26 (b)** P2-01 | Keep both backends and **complete** the dual-backend AC | `collections` and `export` stay; `SOAR_CATALOG_SOURCE` unchanged; a lab-marked equivalence test is prepared (§4) | Does not treat HTTP 403 as export validation; does not send `POST /configurations/exports` | **No** |
| **D10 / D26 (c)** P2-03 | **Read-only first**; no close experiment authorised | Align `soar_describe_incident_fields` with `soar_list_fields` now (no derived flag, raw token kept) and look for documented meaning by a static read | Does not infer what `close` means; does not mark the close-required clause met | **No.** The clause stays **NOT MET** until verified |
| **D22** LAB-03 | Reading **(B), bounded**: golden tests of a named set of deterministic, release-relevant outputs now; Playbook-IR goldens (G10) in Phase 3 | §6 proposes the set; a pilot of three groups is in this branch | Does not claim the pilot or future IR goldens meet the current T3 gate | **Yes, proposed only:** §6.4 drafts the interpretation note for `07 §2` / `§7.5`. Nothing is applied |

### 1.1 Language that would need an owner amendment (none applied)

- **D22.** `07 §2` defines T3 by its marker and every concrete golden requirement is
  Playbook-IR (LAB-03 §1). Reading (B) is an interpretation and needs a recorded
  amendment (an `08` section) before LAB-03 can count as the T3 gate item. Draft: §6.4.
- **D26 (a), E2.** "Any workflow beyond the one read" (P2-00) is unbounded: no finite
  set of probes resolves it. §2.1 **proposes** a bounded node-type scope; adopting it is
  an owner scoping decision on how the P2-00 AC is read for E2, and is not applied.
- **D10, release notes.** The `0.2.0` CHANGELOG section and
  [`releases/v0.2.0-alpha.md`](../releases/v0.2.0-alpha.md) describe the audited tree,
  where `soar_describe_incident_fields` still derives `close_required`. The fix in this
  branch is listed under `[Unreleased]` (as D23 (d) did for P2-06/P2-07). If `v0.2.0` is
  tagged from a commit that contains the fix, the 0.2.0 text is wrong. Which way is the
  owner's call.

### 1.2 Approving a research direction is not authorising a lab operation

Two different approvals, never merged:

- **Research direction** (what this document asks the owner to approve): which items
  are pursued, in what order, and by which kind of evidence. Approving it authorises
  **offline work only**: plans, probe code, selftests, offline tests, documentation.
- **Lab operation** (a separate, written approval per run): names the probe flag or
  experiment, the org, the designated object ids, the exact requests and their count,
  and the date. Required for every request to an appliance, read-only ones included,
  and for every owner-side UI setup the tooling relies on. It is valid for that run
  only; it does not carry over to a rerun, another org or another item.

No item of this plan, and no approval of it, is an authorisation of the second kind.

## 2. Evidence and blocker matrix

Kinds: **S** static read of IBM's on-box documentation (no org data) · **R** read-only
request against existing data · **R\*** read-only request after the owner sets up
synthetic data in the UI (the setup is a lab change made by a human, not by the
tooling) · **W** write in a disposable org · **X** configuration export.

"Offline" means work that needs no lab at all. Only the offline parts are done in this
branch.

| ID | Open item (source) | Current evidence | Kind | Permission / authorisation needed | Expected evidence | Blocker | Offline part |
|---|---|---|---|---|---|---|---|
| E1 | Note-reply nesting (Q10) | ✅ a note row has `children` (empty) and `parent_id` (null); no reply ever existed | R\* | incident read (existing key); owner adds one synthetic reply in the UI to a designated synthetic incident | sanitised shape of a parent row with one child, and of the child: where the reply sits, `parent_id` type | no reply exists | probe spec (§3) |
| E2 | Workflow variants beyond the one read (record §3.3) | ✅ one workflow: start, service task, exclusive gateway, end events | R\* | workflow read (granted 2026-10-23); owner builds further disposable workflows | structure-only summaries per node type | **unbounded** as written; §2.1 proposes a bounded scope (owner decision) | probe exists (`probe_p2_04.py`) |
| E3 | Execution row shape (record B) | ✅ route answers 200 with zero rows; no playbook ever ran | R\* + W | the owner runs the disposable playbook once on a synthetic incident (creates execution records: a lab write, by a human); then one approved criteria-only `POST /playbooks/execution/query_paged` | sanitised row shape | no execution exists; running one is a write | probe spec |
| E4 | Past function results (record B) | ❓ not in history or newsfeed; `…/activities` never called | R\* | E3 first; separate approval for `…/activities` (a `POST` query) | whether any read exposes function output, and its shape | depends on E3 | probe spec |
| E5 | Export contents (record B; D3) | 🚫 one attempt → 403 for the read-only key | X | export-capable key (ACCESS-CHECKLIST D2) **and** separate authorisation for `POST /configurations/exports` and its retrieval, in a disposable org or an org the owner names | structure-only description of the export document; no raw export kept | no key; no authorisation | equivalence scaffold (§4) |
| E6 | Action invocation (Q4) | 📄 invoke DTOs used only by the inbox endpoint; nothing invoked | W | Tier-3 in org 301 with the mock AppHost (P1-INV-01, LAB-04) | the verified invocation contract | org 301, mock AppHost, authorisation | none (code refuses, `DENY_UNSUPPORTED`) |
| E6r | `actions` list entry shape (Q4, read part) | 📄 `ActionInfoDTO`; every list empty | R\* | owner configures one manual rule on a synthetic incident type | live shape of a non-empty `actions` entry | no manual rule visible | probe spec |
| E7 | Invocation result rows (Q5) | ✅ `{entities: []}`, shape unknown | W | depends on E6 | row shape | E6 | none |
| E8 | `409` / concurrent edit (Q1) | no `409` ever seen | W | two writers on one disposable task/incident in org 301 | status and body shape of a conflict, or proof none exists | write approval | none |
| E9 | Closing the last required task of a phase (Q1) | ❓ | W | close experiment in org 301 | phase / incident side effects | write approval | none |
| E10 | Artifact-value search (Q2) | 📄 `…/related_incidents/query_paged`, `/incidents/{id}/related_ex` documented, not exercised | R | approval for one `POST …/query_paged` (a read, sent by `POST`, as D6) and one `GET` | status and sanitised shapes | approval of the two requests | probe spec |
| E11 | `POST /incidents` mandatory fields (Q8) | 📄 documented | S + W | static read of the incident DTO's required properties; then a create in org 301 | which fields the server requires | write approval for the live half | probe spec (S part) |
| E12 | AND-within / OR-across filters (Q14) | 📄 stated by the reference; not distinguishable live | R\* | a key that can see at least one closed and one open synthetic incident | two queries whose results differ only by the logic | no closed incident visible to the key | probe spec |
| E13 | Meaning of the `close` token (D10, record §3.2) | ✅ tokens observed; 📄 Swagger defines no string `required`; HTML field-definition page **not read**; names of data types with a boolean `required` **not kept** | S, then W if still open | approval for the two static reads (IBM documentation, no org data) | whether IBM documents the token; whether the field-definition type declares `required` as boolean | approval; if undocumented, the close experiment X1 | **D10 consistency fix done** (§5) |

### 2.1 Proposed bounded scope for E2 (workflow node types; not adopted)

Already observed on 51.0.9.0.20848 (one workflow, `soar-api-verified.md` §3.3): start
event, service task carrying a function call, exclusive gateway with a `default` flow,
end event, `sequenceFlow` edges. The summariser lists any other type with
`type_observed: false` and does not summarise its contents.

Proposed: E2 is **resolved for exactly the types below** once each has been observed,
read-only, in at least one disposable workflow the owner builds in the UI (synthetic
values only, no function that touches anything outside SOAR), and summarised
structure-only by `probe_p2_04.py`:

| # | Workflow-editor element | What must be observed |
|---|---|---|
| N1 | Script step | its BPMN element name and whether the script is inline or a reference |
| N2 | Timer / wait | element name and how the duration is represented (no value kept) |
| N3 | Parallel split and join | element names; how a join is distinguished from a split |
| N4 | Sub-workflow call | element name and how the called workflow is referenced |
| N5 | A second function call in the same workflow | that two calls are two elements with distinct uuids |

Rules: the BPMN names are recorded as observed, never assumed from the editor label;
a type not in this table, or in it but not observed, stays `type_observed: false` and
**unverified**, and nothing may describe it as supported; the summariser's behaviour
for an observed type changes only in a later, reviewed PR. Each owner build and each
read is a lab operation under §1.2.

What none of these needs: a production org, the real AppHost, TLS verification off, or
any change to the server's permission model.

## 3. Read-only investigation plan (E1, E2, E3/E4 read side, E6r, E10, E11 S, E12, E13)

**Not run.** Each probe needs a separate approval naming its exact requests before it
is run, as D6 and D11 did.

Probes are built on the existing framework in [`scripts/probe/`](../../scripts/probe/):
`guarded.py` (launch guard), `safe_http.ReadOnlyClient` (refuses every verb but `GET`
and the named, approved `POST` queries), `sanitise.dump_verified` (structure only,
token enums, bucketed counts), the per-ticket ledger, and `selftest.py`.

Proposed: one module, `probe_p2_00d.py`, with one flag per item and a **closed list of
requests** per flag:

| Flag | Requests (closed list) | Kept | Never kept |
|---|---|---|---|
| `--doc-field-required` (E13) | `GET` the HTML reference page of the field-definition type; `GET /docs/rest-api/ui/swagger.json` | names of data types whose `required` is boolean; whether the field-definition type declares `required` and how; whether its page mentions closing (a boolean, plus a human paraphrase in the PR, not the text) | the page text |
| `--doc-incident-required` (E11 S) | the same Swagger document | the incident DTO's declared `required` property names | descriptions |
| `--reply` (E1) | `GET /incidents/{id}/comments` on the **designated** synthetic incident only | key set and types of parent and child rows; nesting path | note text, user names, ids |
| `--related` (E10) | one `POST …/artifacts/{id}/related_incidents/query_paged` (criteria-only), one `GET /incidents/{id}/related_ex` | status, wrapper and row shapes | artifact values, incident names |
| `--filters` (E12) | two `POST /incidents/query_paged` differing only in `logic_type` | status, `recordsTotal` buckets, whether they differ | rows |
| `--actions` (E6r) | `GET /incidents/{id}` on the designated incident | `actions[]` entry key set and types | action names |
| `--executions` (E3/E4) | one criteria-only `POST /playbooks/execution/query_paged`; `…/activities` only if separately approved | row key sets and types | messages, function output values |

Fixture-capture procedure (each run):

1. Owner approves the run: flag, target org, designated object ids, date.
2. `uv run python scripts/probe/selftest.py` passes before anything is sent.
3. The probe writes structure-only files under `tests/fixtures/soar/verified/` with
   `_request` (method, path template, query keys), `_status`, `_enums`, `_facts`, and
   the ledger records every request sent.
4. `uv run python scripts/check_no_secrets.py` and
   `uv run python scripts/check_artifact_hygiene.py` are clean; a human reads every new
   fixture before it is committed.
5. `soar-api-verified.md` and `open-questions.md` change an item's mark only on that
   evidence, and say what the evidence does not cover.

## 4. Catalog-backend equivalence test plan (D26 (b))

**Done in this branch (offline):**

- [`tests/catalog_equivalence.py`](../../tests/catalog_equivalence.py) fixes what
  *equivalent* means: the catalog's JSON without `source` and `fetched_at`, compared
  strictly (a type change, a `null` vs `false`, a missing entry are all differences).
  Differences are reported as JSON paths, never values.
- [`tests/test_catalog_equivalence.py`](../../tests/test_catalog_equivalence.py) tests
  that rule on synthetic copies of the committed fixture, and that `ExportBackend` still
  refuses and sends nothing.
- [`tests/lab/test_catalog_equivalence.py`](../../tests/lab/test_catalog_equivalence.py),
  `lab`-marked, skipped unless `SOAR_TEST_ENABLE` includes `lab` **and**
  `SOAR_TEST_CATALOG_EQUIVALENCE=authorised-export`. It loads `collections`, then
  `export`, then `collections` again through one client; drift between the two
  `collections` loads fails the run as invalid evidence. **Today it fails when opted
  in**, because `ExportBackend` refuses: that is the honest result.

**Still needed, in order (none started):**

1. ACCESS-CHECKLIST D2: an export-capable key, issued by the owner, scoped to the
   lab org named for the run.
2. Separate owner authorisation for `POST /configurations/exports` and the reads that
   retrieve the document (P2-00c), stating org, count of requests and retention: the
   raw export is held in memory only and never written to disk or committed.
3. P2-00c research: a probe that records the export document's structure only.
4. An `ExportBackend` implementation over that verified contract, with offline tests
   from a synthetic export fixture built from the recorded structure.
5. An export-specific, separately authorised transport for the equivalence test (§4.1),
   reviewed with item 4. `ReadOnlyTransport` itself is **not** widened.
6. The lab run, with the configuration frozen by the owner for its duration; evidence =
   the passing test, its audit log and `qradar-soar-audit verify` output.

Any difference the two backends legitimately cannot avoid (for example a section one
source cannot observe) becomes a named, tested exception only after an owner decision;
the rule is never widened silently.

### 4.1 Export authorisation safeguards (design; the export itself is not implemented)

**Review findings on the current tree:**

| Component | Export creation (`POST …/configurations/exports`) | Export retrieval / history (`GET …/configurations/exports[/{id}\|/history]`) |
|---|---|---|
| Product server (`src/`) | never sent: `ExportBackend` holds no client and refuses every load (`not_sent=True`) | never sent: no code path names the route |
| T4 guard `tests/lab/guard.py` `ReadOnlyTransport` | refused (not one of the two allowed `POST` paths) | **was allowed** as an ordinary `GET` under `/rest/orgs/<org>/`. **Fixed in this branch**: every method under `configurations/` and `playbooks/exports\|imports` is refused, case-insensitively, with regression cases in `tests/test_lab_guards.py` (they fail on the old guard) |
| Probe client `scripts/probe/safe_http.py` `ReadOnlyClient` | **structurally allowed** (body limited to the three section switches); gated only by `probe.py --with-export` | allowed (any `GET` under `/rest/`) |

The probe-client finding is **not changed in this PR** (the probes are research tools
with their own selftests); it is a required change before any export research run
(item 2 below).

**Required design before any export request is sent** (P2-00c; each item is reviewed
code with tests, none exists yet):

1. **A separate, export-specific authorisation object**, not a flag on a read-only
   client and not an entry in a `POST` allow-list. It is constructed only from an
   explicit per-run grant naming: the org id, the appliance host and port, the exact
   request (`POST /rest/orgs/<org>/configurations/exports` with an exact body), a
   maximum count (one), and a date. Missing, malformed, expired or mismatched ⇒ refuse
   before sending (fail closed).
2. **Creation and retrieval are two grants.** The creation grant permits exactly one
   `POST`; it does not permit retrieval. A retrieval grant names the export id the
   creation returned and permits exactly one `GET …/configurations/exports/<id>` (and,
   only if separately named, one `GET …/exports/history`). Neither grant authorises any
   other path, org or method, and a grant is consumed by use.
3. **Org scope.** The grant's org must equal the run's org; the read-only T4 org (201)
   is refused unless the owner names it explicitly for that run; the server's own
   `SOAR_*` configuration is never consulted.
4. **No broad `POST` allow-list.** `ReadOnlyTransport` keeps its two `query_paged`
   `POST`s and its new export refusal; export requests go through a distinct transport
   wrapping the grant. `safe_http.ReadOnlyClient` loses its standing export allowance:
   the export `POST` moves behind the grant, so `probe.py` without a grant cannot send
   it even with `--with-export`.
5. **No persistence of raw export content.** The response body is parsed in memory into
   structure-only facts (key sets, types, counts as buckets) or, for the backend, into
   a `Catalog`; the raw bytes are never written to disk, logged, put in an exception
   message, a fixture, an audit record or a test report. Errors carry status and a fixed
   category only.
6. **Fail closed throughout**: a refusal never falls back to `collections` or to another
   org; a 403 or any non-success is a failure of the run, never a skip or a pass.

**Regression tests required with that change:**

- the read-only guard refuses creation, retrieval and history, every method, any case
  (in this branch);
- without a grant, no client or transport in the repository can send the export `POST`
  (product, T4 guard, probe client), checked at the wire with a recording transport;
- a creation grant cannot retrieve; a retrieval grant cannot create, cannot retrieve a
  different id and cannot be reused; a grant for org A refuses org B, another host or
  port, another body, a second request;
- an expired or malformed grant refuses before any byte is sent;
- a planted sentinel in a synthetic export response never appears in logs, exceptions,
  audit records, fixtures or the test's assertion messages;
- `ExportBackend` with no grant still raises `catalog_unavailable` with `not_sent=True`
  (in this branch, `tests/test_catalog_equivalence.py`).

## 5. D10 consistency fix (implemented in this branch, for review)

**Evidence basis.** `soar-api-verified.md` §3.2: the tokens `always` and `close` are
observed; the on-box Swagger description defines no string `required`; behaviour was
never exercised. The reading `required == "close"` ⇒ *must be filled before close*
comes from the design baseline only.

**Assumptions found** (all occurrences of the reading in product code):

| Where | Before | After |
|---|---|---|
| `client/org.py` `FieldDef.close_required` | property `required == "close"` | removed |
| `client/org.py` `FieldDef.to_dict` | `"close_required": bool` | removed; `"required"` raw token unchanged |
| `tools/incidents.py` `soar_describe_incident_fields` | docstring "whether required at close" | raw token, plus the same `required_semantics` block as `soar_list_fields` |
| `client/incidents.py` module and `close()` docstrings | "SOAR itself rejects the close if a close-required custom field is empty" | the rejection is surfaced; *which* fields SOAR requires is unverified |

Not product code, left as is: `tests/fake_soar.py` still simulates the baseline reading
(its close rejection is a synthetic fixture for the error path, not evidence), and
`docs/design/05` keeps the baseline text, which `soar-api-verified.md` already qualifies.

**Tests.** In `test_discovery_types_fields.py`:
`test_both_field_tools_state_the_same_token_and_derive_nothing` (every incident field:
same token from both tools, no derived flag in either, identical `required_semantics`;
fails on the old code, checked) and
`test_both_field_tools_pass_any_token_through_unchanged` (an unseen token, `close` and
an absent token each reach both tools unchanged). The existing `soar_list_fields` tests
of the same file (no derived flag for any token, `required_semantics` content) are
retained. `test_tools.py` and `test_client_domain.py` assert the raw token and the
absence of the flag on the Phase-1 tool. README tool table, README limitation, CHANGELOG `[Unreleased]` / `Changed`
updated. The narrowing of `_unreleased_tools()` in `test_docs_consistency.py` to the
`### Added` subsection lets a `Changed` entry name an existing tool.

**Response-contract change for consumers (Tier 0, `soar_describe_incident_fields`).**

| | Before | After |
|---|---|---|
| per field | `api_name`, `label`, `input_type`, `custom`, `required`, **`close_required`** (bool), `read_only`, `values`? | the same **without `close_required`**; `required` unchanged (SOAR's raw token, or `null` when SOAR sent none) |
| top level | `count`, `fields` | `count`, `fields`, **`required_semantics`** (the block `soar_list_fields` returns: `status: "unresolved"`, observed tokens per object type and SOAR version, and a statement that no meaning is derived) |
| tool input, tier, capability, annotations | — | unchanged |

Migration: a consumer that read `close_required` must read `required` instead and treat
its meaning as **unresolved**. In particular, `required != "close"` does not mean a
field is optional at close, and `"close"` does not mean SOAR will refuse the close; an
unknown token is unknown, never optional. The removal is deliberate: a consumer that
breaks on the missing key fails visibly instead of acting on an unverified claim. The
change is listed under CHANGELOG `[Unreleased]` / `Changed`, not in the `0.2.0` section
(§1.1, and the release-readiness warning in §14.6).

**AC.** The P2-03 close-required clause stays **NOT MET**. If E13 finds IBM
documentation of the token, a follow-up adds a documented flag to **both** tools
together; if not, closing the clause needs X1.

## 6. T3 golden-test scope and plan (D22)

### 6.1 Proposed bounded set (current implementation only)

| Group | Output | Deterministic how | Status |
|---|---|---|---|
| G1 | MCP tool manifest incl. descriptions | registry, no runtime state | **pilot here** |
| G2 | Projected outputs of the Tier-0 tools | `FakeSoar` fixtures; request ids patched | planned |
| G3 | Denial messages, tool × configuration state × transport | the permission-matrix states | planned |
| G4 | `qradar-soar-mcp --check` JSON for fixed configurations | synthetic env, `FakeSoar`; paths replaced by a placeholder | planned |
| G5 | `Settings.load` refusal messages and the start-up capability line | synthetic env | planned |
| G6 | Audit records: one denial, one PENDING + COMMITTED mutation, one cap denial | frozen clock, fixed request ids; hash chain recomputed from fixed input | planned |
| G7 | Catalog summary and discovery outputs over `lab-v51.json` | committed fixture | **pilot here** (summary only) |
| G8 | Workflow and playbook structural summaries | `workflow_data.py`, `playbook_data.py` | planned |
| G9 | `SoarError.to_dict()` per class | fixed synthetic message | **pilot here** |
| G10 | *(Phase 3)* IR corpus, validation reports, simulation traces, compile round trip (`P3-10`) | — | **Phase 3 only; does not count toward the current gate** |

### 6.2 Unsuitable for golden files

- Anything from a live appliance (that is T4, not T3).
- Outputs with wall-clock time, `uuid4` ids, temporary paths, or process ids not
  replaced by fixed values.
- Audit-log hashes over un-frozen input (pin the record shape and recompute instead).
- README and release-document tables (already consistency tests, not outputs).
- Anything whose bytes depend on the platform (path separators, line endings): the
  harness writes and compares `\n` only.
- Raw script bodies, workflow or playbook XML, and any export content: they are
  configuration, and the tools return filtered representations already covered by G2.

Note: G1 includes JSON Schemas generated by `pydantic`/`mcp`; an upgrade in `uv.lock`
can change them. That is intended (the contract changed) and is reviewed as such.

### 6.3 Infrastructure (pilot in this branch)

- [`tests/golden_support.py`](../../tests/golden_support.py): canonical JSON, byte
  comparison with a bounded diff, refusal of the sentinel secret and private addresses
  in outputs and in expected files, missing-file failure, orphan detection.
- `--golden-update` (in `tests/conftest.py`) is the only way to write an expected file;
  `test_ci_never_regenerates_expected_outputs` asserts no workflow passes it or
  `--snapshot-update`.
- [`tests/test_golden.py`](../../tests/test_golden.py): G1, G7, G9, a 100× byte-stability
  check (LAB-03 §9.3), and tests of every failure rule (LAB-03 §6).
- Expected files in [`tests/golden/`](../../tests/golden/), with a README. Not packaged:
  the wheel and the sdist allow-list (REL-06) include neither `tests/` nor `docs/`.
- Review procedure in `CONTRIBUTING.md`, stating it is manual under REL-03 phase 1.
- CI: none needed; `ci.yml` runs every marker on all four test jobs.

**The pilot does not meet the T3 gate item.** LAB-03 §9 still needs: D22 recorded, the
§6.1 list approved, every approved group implemented, and the gate evidence on the
release commit.

### 6.4 Draft amendment text for owner review (not applied)

> *`08` §N — T3 scope before Phase 3 (D22).* For a release that ships no Playbook-IR
> artefact, the `07 §7.5` item "T3 green in CI" means: every group of the approved list
> (LAB-03 §3 as amended) has at least one `@pytest.mark.golden` test with a committed
> expected file, the golden suite passes on the release commit with zero skipped, and
> golden-file changes since the last release were reviewed by a named person. From
> Phase 3 the `P3-10` corpus is added to that list; it never replaces it.

## 7. Write, close and export experiments: separate proposals, none authorised

| # | Experiment | Prerequisites | Expected mutations | Isolation | Rollback / residue |
|---|---|---|---|---|---|
| X1 | Close a disposable incident with a `close`-token field empty, then filled (E13) | E13 static read done and inconclusive; org 301; a write key; one synthetic incident created for it; VM snapshot or accepted residue | one incident created, one failed close attempt (if SOAR enforces), one close | org 301 only; nothing in 201 | a closed incident cannot be un-created; reopen is a further write; the incident stays as residue unless the org is reset |
| X2 | Close the last required task of a phase (E9) | org 301; a write key; a synthetic incident with a phase holding one required task | task closed; possibly phase or incident state changed | org 301 | reopen the task (a write); phase side effects may not be reversible |
| X3 | Concurrent edit of one task / incident (E8) | org 301; two clients | two `PUT`/`PATCH` on one object | org 301 | object left in the last writer's state; reset by a further write |
| X4 | Configuration export (E5, P2-00c) | export-capable key; owner names the org; retention rule (memory only) | an export is created server-side (and may appear in export history) | disposable org preferred | export history may keep a record; cannot be assumed removable |
| X5 | Manual-action invocation (E6/E7, P1-INV-01) | org 301; mock AppHost (LAB-04); policy and approval in place | one action invocation; one mock-AppHost call | org 301 + mock AppHost only; never the real AppHost | invocation records remain |
| X6 | `POST /incidents` with minimal fields (E11) | E11 static read; org 301 | one incident created | org 301 | residue unless the org is reset |

Each needs its own written approval naming the org, objects, request count and date.

## 8. Remaining release blockers (unchanged by this branch)

| | Blocker | State after this branch |
|---|---|---|
| B1 | P2-00 open items | open; §2 maps each to its evidence path |
| B2 | P2-01 equivalence | open; scaffold ready and the read-only guard now refuses export creation and retrieval; needs E5 / X4, the §4.1 authorisation design and P2-00c |
| B3 | P2-03 close-required; tool disagreement | **disagreement removed** (§5); close-required clause still unmet |
| B4 | `07 §7.5` gate: T3 (D22, LAB-03), T4 (LAB-01 run), T5 (LAB-02, org 301), T6 (LAB-04, mock AppHost), audit verify, human read of `security/` | T3: harness pilot only, gate unmet; T4: scaffold, never run; T5, T6: not implemented |
| B5 | `v0.2.0` not released | unchanged; version stays `0.2.0` |

## 9. Proposed PR sequence

1. **This branch** (`docs/phase2-owner-decisions-plan`): this record and plan, the D10
   consistency fix, the golden-test harness pilot (G1, G7, G9), the equivalence scaffold
   and the read-only guard's export refusal.
2. **Read-only probe module** (`probe_p2_00d.py` + selftests, §3), offline only.
3. **First approved read-only run** (E13 static reads, E10), then E1 / E6r / E12 once the
   owner has set up the synthetic data; a PR recording the evidence.
4. **T3 expansion** to the approved list (after D22 is recorded), with the `08`
   amendment.
5. **P2-00c** (needs X4): export structure, then `ExportBackend`, then the equivalence
   lab run.
6. **Write experiments** X1 – X3, X5, X6, each separately authorised, in org 301.

Phase 3 does not start until P2-00, P2-01 and P2-03 are each closed by work or by a
recorded owner decision (the `06` gate rule).
