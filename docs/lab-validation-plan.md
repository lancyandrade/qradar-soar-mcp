# Lab-validation plan — LAB-01

**Status (2026-10-29):** plan and offline scaffolding only. **No lab test has run, and
the `07 §7.5` lab gate has not passed.** The owner decided not to waive it (08 §32, D14),
so `v0.2.0` stays NO-GO until the evidence of §6 exists. No SOAR request was sent to
write this plan or the scaffolding.

## 1. What the gate requires

From [`07-TEST-STRATEGY.md`](design/07-TEST-STRATEGY.md) §2 and §7.5, word for word where
it matters:

| Gate item (`07 §7.5`) | Tier | Where it runs (`07 §2`, §7.1–7.2) | Exact requirement |
|---|---|---|---|
| All T1–T3 green in CI | T1 unit, T2 `contract`, T3 `golden` | CI, offline | T1 and T2 met today (GitHub CI on every push and PR). **T3: no test carries the `golden` marker** (there are snapshot tests only; the golden corpus is `P3-10`, Phase 3), so T3 is **unmet**: D21 (2026-10-30) keeps T3 mandatory with no waiver; work in [`LAB-03`](proposals/LAB-03-t3-golden-test-gate.md), scope open in D22 |
| T4 green against the lab | `lab` | real SOAR, **read-only key**, org `201` ("existing lab data — read-only tests only", never reset) | nightly / pre-release |
| T5 green in org 301 | `lab_write` | real SOAR, **disposable org** `301` (`MCP-TEST`), seeded and torn down per run (§7.3); snapshot the VM before every run (§7.1) | pre-release, manual trigger |
| T6 green against the mock AppHost | `lab_destructive` | real SOAR + **mock AppHost** (`resilient-circuits` app whose `fn_edr_isolate_endpoint`, `fn_firewall_block_ip`, `fn_disable_account` only log); the real AppHost is **never** targeted (§7.1) | pre-release, manual, **never in CI** |
| `qradar-soar-audit verify` clean over the whole test run | all | the audit log written by the run | — |
| `gitleaks` clean over full history | — | CI | met today |
| A human has read the diff of `security/` since the last release | — | owner | not done for `v0.2.0` |

`07 §2` also requires that T4–T6 are skipped by default and that `pytest` with no
configuration runs green offline on a fresh clone. The scaffolding keeps that.

## 2. Three kinds of test

| Kind | Network | What may run it | In this repository |
|---|---|---|---|
| **Offline** (T1–T3, and the guard tests of §5) | none; `respx` + `FakeSoar`; anything else is an error | anyone, CI | `tests/` except `tests/lab/` |
| **Read-only live** (T4) | one lab SOAR host, read-only key, org 201; writes are blocked on the wire | an operator who opts in | `tests/lab/test_t4_read_only.py` (scaffolded, never run) |
| **Isolated mutation** (T5, T6) | a disposable org (T5) and additionally a mock AppHost (T6) | an operator who opts in, after a VM snapshot | **not written**: LAB-02, LAB-04 |

## 3. T4 — lab read-only (scaffolded)

`tests/lab/test_t4_read_only.py`, marker `lab`. Under the **default** configuration
(every capability off), with TLS verification on and the audit log required:

1. the lab runtime has no capability enabled;
2. every Tier-0 tool that needs no argument answers `ok` (18 tools, parametrised from the
   registry, so a new read tool is picked up);
3. the incident-scoped reads (`soar_get_incident`, `_full`, artifacts, tasks, notes,
   attachment metadata, manual actions, similar incidents) answer `ok` for the first
   incident the search returns (org 201 must hold at least one);
4. `soar_list_fields` answers for `incident`, `task` and `artifact`;
5. every Tier ≥ 1 tool is denied and **no request at all** leaves while denying (the live
   counterpart of `tests/test_chokepoint.py`);
6. no response contains the API secret;
7. at each test's teardown: the wire guard blocked nothing, and the audit log verifies.
   All T4 tests of one pytest run share **one** audit log (a session-scoped state
   directory), so the chain verified at the end covers the whole run, as `07 §7.5`
   asks; it is copied once, at the end of the run, to `SOAR_TEST_EVIDENCE_DIR`.

The read-only key must be allowed to read everything the read tools touch: incidents
and their tasks, artifacts, notes and attachment metadata, users, field definitions,
and the configuration the catalog loads (functions, scripts, rules, workflows,
playbooks, message destinations, phases, incident types, data tables). Earlier
research saw `403` for workflows and playbooks with a narrower key (open questions
D11, D12); a `403` in T4 fails the test rather than being skipped.

The wire guard (`tests/lab/guard.py`, `ReadOnlyTransport`) sits under the SOAR client.
It sends only HTTPS to exactly the configured host and port: `GET`/`HEAD` on
`/rest/session`, `/rest/const` or under `/rest/orgs/<configured org>/`, and `POST` to the
two verified search endpoints (`incidents/query_paged`, `playbooks/query_paged`) of
that org. Plain HTTP, another port or org, the org list, `.`/`..` segments and
percent-encoded dots, slashes or backslashes are refused. Anything else raises before it
reaches the network, so T4 cannot write or wander even if a code path regressed. A read-only API key is still required: the guard is a
second line, not the first.

## 4. T5 and T6 — what is left (not implemented)

**LAB-02 — T5 in org 301** (needs the owner: a disposable org, a write key scoped to it,
a VM snapshot, permission to seed):

- `tests/lab/seed.py` per `07 §7.3`: malware (PowerShell artifacts), phishing (URL +
  email), a closed incident with full task history, one with 50+ artifacts, one with a
  large attachment, and one whose note holds the prompt-injection text of §7.3.
- Each Tier-1/2 tool once with its flag on (closing `M-1` of release-readiness §8: the
  write bodies were never exercised live), each audited `PENDING` → `COMMITTED`, and the
  post-image re-read; hourly cap and kill switch exercised once.
- The prompt-injection incident: driving the pipeline with the injected text still ends
  at the approval gate / refusal and is audited as attempted.
- Teardown of the seeded set; audit verify over the run.

**LAB-04 — T6 against a mock AppHost** (named `LAB-03` in Sprint 1; renamed, 08 §33) (needs the owner: a mock AppHost host,
the three logging functions installed in org 301 only, a way to read its call log):

`07 §7.4` lists nine assertions. With the D16 limitation (`soar_invoke_action` always
returns `DENY_UNSUPPORTED`):

| §7.4 step | Can run today? |
|---|---|
| 1 default config ⇒ deny | yes |
| 2 `SOAR_ALLOW_ACTIONS=true`, no policy ⇒ startup failure | yes (offline already; live adds nothing) |
| 3 unclassified action ⇒ Tier-5 deny | only as `DENY_UNSUPPORTED` |
| 4 `require_approval` ⇒ request written, zero calls at the mock | **no**: refused before approval |
| 5 out-of-band approval ⇒ exactly one call at the mock | **no** |
| 6 replay ⇒ denied, mock count unchanged | **no** |
| 7 `deny_values` ⇒ deny with a valid approval | **no** |
| 8 kill switch ⇒ deny with a valid approval | only without an approval |
| 9 audit chain verifies, every denial present | yes |

Whether a T6 run that proves the refusal (zero calls at the mock AppHost) is enough for
`v0.2.0`, or invocation (`P1-INV-01`) must land first, was open question **D20**.
**Decided 2026-10-30 (08 §33):** a denial-only T6 run counts as evidence that
unsupported invocation is correctly rejected, and only that. It does not show successful
execution or approval enforcement, so full T6 is not complete until every §7.4 step
passes or the criteria are amended. Release documents call such a run "T6 (denial
path only)".

## 5. Guards on every live test

Implemented in `tests/lab/guard.py` and `tests/lab/conftest.py`, tested offline by
`tests/test_lab_guards.py` (runs in CI):

- Every test under `tests/lab/` carries exactly one of `lab`, `lab_write`,
  `lab_destructive`, or collection fails. An autouse fixture resolves its target
  before the body runs.
- **Opt-in:** a tier runs only if `SOAR_TEST_ENABLE` names it (`lab`, `lab_write`,
  `lab_destructive`, comma-separated). Not named ⇒ skipped. An unknown name refuses, so
  a typo cannot skip silently.
- **No fallback:** an enabled tier whose target is missing or unsafe **fails**; it never
  skips, never uses defaults and never reads the server's own `SOAR_*` variables. The
  lab runtime is built only from `SOAR_TEST_*`, and it refuses if `SOAR_TEST_BASE_URL`
  names the host of the shell's `SOAR_BASE_URL` (on an operator machine, production).
- **Target acknowledgement:** `SOAR_TEST_TARGET_ACK` must repeat the host;
  `SOAR_TEST_FORBIDDEN_HOSTS` lists hosts that can never be a target. HTTPS only, no
  credentials, path, query or fragment in the URL.
- **T5/T6:** `SOAR_TEST_WRITE_ORG_ID` must differ from `SOAR_TEST_ORG_ID`,
  `SOAR_TEST_DISPOSABLE_ORG_ACK` must repeat it, and the write key must differ from the
  read key.
- **T6:** `SOAR_TEST_MOCK_APPHOST_URL` is required (never derived), must not be the SOAR
  host or any host in the required `SOAR_TEST_REAL_APPHOST_HOSTS`, and
  `SOAR_TEST_MOCK_APPHOST_ACK` must repeat it.
- With no `SOAR_TEST_*` variable (CI) every lab test is skipped and nothing is sent;
  a test runs the lab directory in a subprocess to prove it.

| Variable | T4 | T5 | T6 |
|---|---|---|---|
| `SOAR_TEST_ENABLE` | `lab` | `lab_write` | `lab_destructive` |
| `SOAR_TEST_BASE_URL`, `SOAR_TEST_TARGET_ACK` | ✓ | ✓ | ✓ |
| `SOAR_TEST_ORG_ID`, `SOAR_TEST_API_KEY_ID` | ✓ | ✓ (to compare) | ✓ (to compare) |
| `SOAR_TEST_API_KEY_SECRET` | ✓ | — | — |
| `SOAR_TEST_WRITE_ORG_ID`, `SOAR_TEST_DISPOSABLE_ORG_ACK`, `SOAR_TEST_WRITE_API_KEY_ID`, `SOAR_TEST_WRITE_API_KEY_SECRET` | — | ✓ | ✓ |
| `SOAR_TEST_MOCK_APPHOST_URL`, `SOAR_TEST_MOCK_APPHOST_ACK`, `SOAR_TEST_REAL_APPHOST_HOSTS` | — | — | ✓ |
| `SOAR_TEST_CA_BUNDLE`, `SOAR_TEST_FORBIDDEN_HOSTS` | optional | optional | optional |
| `SOAR_TEST_EVIDENCE_DIR` (e.g. `lab-evidence/`, git-ignored) | for gate evidence | for gate evidence | for gate evidence |

Never put these in `.env` or in the repository. Export them in a dedicated shell with
no `SOAR_*` variable of the server set.

## 6. Evidence the gate needs

For each of T4, T5 and T6: the exact command, commit, appliance version, the pytest
summary line (with **zero** skipped tests for the tier under test), and the
`qradar-soar-audit verify` line over the run's audit log. pytest rotates its temporary
directories, so set `SOAR_TEST_EVIDENCE_DIR`: the run's single audit log is copied there
at the end of the run with its SHA-256 (never overwritten) and kept under the retention rules of
[`runbooks/artifact-hygiene.md`](runbooks/artifact-hygiene.md). Recorded in
`docs/release-readiness.md`, sanitised (no host names, ids beyond org numbers, or
incident content). Only then may the release documents say the lab gate passed.

T4 command, once the owner approves a run:

```bash
SOAR_TEST_ENABLE=lab uv run pytest -m lab tests/lab -rs
```
