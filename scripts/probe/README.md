# scripts/probe — P2-00 research tooling

Read-only probing of a QRadar SOAR appliance, used once per appliance version to
turn the ⚠️/❓ marks of `docs/design/05-SOAR-API-SURFACE.md` into evidence in
`docs/soar-api-verified.md`. **This is not part of the installed package**: it
is not imported by `qradar_soar_mcp`, adds no MCP tool and no client method,
and nothing here changes Phase-1 behaviour.

| File | Purpose |
|---|---|
| `probe_env.py` | Reads the connection values from the environment or a git-ignored `.env`. Reports names and presence only. |
| `tls_check.py` | TLS inspection that runs before any API request. Reports booleans and fixed categories, never a subject, SAN value, host name or address. |
| `safe_http.py` | The only HTTP path. `GET` under `/rest/` and `/docs/`, plus exactly four semantically read-only `POST`s with key-by-key body validation. Everything else is refused before anything is sent. |
| `sanitise.py` | Shape extraction, the enum allow-list, and the verifier that rejects environment-specific text. Also a CLI: `--check FILE…`. |
| `probe.py` | The plan, mapped to the eight P2-00 priority questions, and the runner. |
| `probe_00b.py` | `P2-00b`: the follow-up research (see below). Same read-only client, verified TLS only. |
| `shape_request.py` | `P2-00b`, offline: reduces a request the web UI sent (the JSON payload only, on stdin) to key names and JSON types. Refuses a HAR, a copied cURL/fetch, any session header and any path that contains an id. Sends nothing. |
| `guarded.py` | Outer guard for live runs: runs a probe script in a child process, captures stdout and stderr, verifies them like a fixture, and shows them only if clean. |
| `selftest.py` | Offline proof of the properties below against a hostile in-process fake. |

## Running it

```bash
# 1. connection values: environment variables, or a git-ignored .env at the repo root
#    SOAR_BASE_URL  SOAR_ORG_ID  SOAR_API_KEY_ID  SOAR_API_KEY_SECRET
#    optional: SOAR_VERIFY_SSL=<ca bundle path>  P2_PROBE_CA_BUNDLE=<path>
uv run python scripts/probe/probe_env.py          # names + presence, never values
uv run python scripts/probe/selftest.py           # offline; must print OK
uv run python scripts/probe/guarded.py tls_check.py          # TLS first
uv run python scripts/probe/guarded.py probe.py --smoke      # ONE authenticated read, no files
uv run python scripts/probe/guarded.py probe.py              # the plan
uv run python scripts/probe/guarded.py probe.py --with-export  # + the configuration export, once
uv run python scripts/probe/sanitise.py --check "tests/fixtures/soar/verified/*.json"
uv run python scripts/check_no_secrets.py
```

Use a **read-only** API key. The probe never needs more.

## What it guarantees

1. **Read-only by construction.** `safe_http.py` refuses, before any I/O, every
   `PUT`, `PATCH` and `DELETE`, and every `POST` except four that are read-only
   in effect: `incidents/query_paged`, `playbooks/query_paged`,
   `configurations/exports` and (P2-00b, owner-approved)
   `playbooks/execution/query_paged` with the one exact body
   `{"filters": [], "start": 0, "length": 1}`, at most once per client. The other
   execution paths (`…/activities`, `…/cancel`, `…/status`) are refused. A query
   body may hold only `filters`, `sorts`,
   `start` and `length` (conditions: `field_name`, `method`, `value`; sorts:
   `field_name`, `type`; `length` ≤ 50); an export body only the three boolean
   section switches. Any other key, and any *other* path that merely contains
   `query_paged`, is refused: a name is not evidence of read-only semantics.
   The probe itself only ever asks for one row with no criteria. The key is
   never tested for write capability by attempting a write. Refusals are
   recorded in the ledger.
2. **No appliance value is written or printed.** Response bodies live in memory.
   What reaches the disk is a *shape*: key names and JSON types. Dictionaries
   keyed by administrator-chosen names (custom fields under `properties`, type
   and data-table maps, field maps) collapse to a single `<name>` entry, so
   those names never appear either. Facts recorded next to a shape are
   booleans, size/count buckets and schema key names derived from the collapsed
   shape, never from the raw document.
3. **A short, vetted enum allow-list.** Values are kept only under a handful of
   IBM schema enum keys (`input_type`, `object_type`, …), only when they are a
   single token, never directly under a name-keyed map, and a key that shows
   more than a dozen distinct values is dropped as "not an enum".
4. **Reject, don't trust.** Every file is serialised, run through
   `verify_clean` against the live connection values *and* generic patterns (IP
   addresses, e-mail addresses, internal host names, URLs, UUIDs, long tokens),
   and written only if nothing is found. The refusal names a category, never the
   text.
5. **Ids stay in memory.** Object ids found along the way build the next request
   and are never printed or stored; paths are recorded as templates such as
   `/rest/orgs/{org_id}/incidents/{incident_id}/attachments`.
6. **Attachment content is never read.** The content endpoint is requested for
   its status and headers only; the stream is closed without reading the body.
7. **Failures are categories.** Transport and TLS errors are reduced to a fixed
   label; exception messages (which contain URLs and host names) are never shown.

## TLS

Order tried, first that verifies wins: normal trust (certifi, which is what the
package uses today, then the operating-system store) → a supplied CA bundle →
a SAN DNS name that resolves to the same endpoint → **`lab-pinned`**.

The probe never falls back to it on its own: if nothing else verifies it stops
and reports. `lab-pinned` is LAB ONLY and must be asked for (`--tls-mode lab-pinned` or
`P2_PROBE_TLS_MODE=lab-pinned`). Verification against public/private trust is
off; the leaf certificate seen by the TLS check is pinned in memory for the rest
of the run (trust on first use), so the first connection is unauthenticated. It
prints a warning on every run, exists only in this probe, and never changes a
package default.

## P2-00b (`probe_00b.py`)

```bash
uv run python scripts/probe/guarded.py probe_00b.py --only preflight   # is the key read-only?
uv run python scripts/probe/guarded.py probe_00b.py                    # every read step
uv run python scripts/probe/guarded.py probe_00b.py --doc-index --grep Task
uv run python scripts/probe/guarded.py probe_00b.py --doc-page json_TaskDTO.html
```

- **Verified TLS or no run.** The context comes from `SOAR_CA_BUNDLE` /
  `P2_PROBE_CA_BUNDLE` (or Python's default TLS trust configuration when neither
  is set); the chain and the host name are checked. It does not use
  `tls_check.py`, whose certificate description needs one unverified handshake,
  and it refuses `lab-pinned`, `SOAR_VERIFY_SSL=false` and two different bundles.
- **One added request, opt-in.** The default steps send only what P2-00 already
  allowed. `--only execution_query` sends the single owner-approved
  `POST playbooks/execution/query_paged` (exact body, once); it refuses to run again
  while its fixture exists. A preflight runs first, and a key whose own permission
  set is readable and mutating stops the run.
- **One bounded scan**: at most 10 incidents, newest first, serving the
  attachment, carried-`actions` and comment questions together; each search
  stops at its first hit and an unanswered one is reported, never widened. No
  page is longer than 10.
- **The on-box API reference as evidence for request bodies.** `docs` records,
  per documented request, the body types, response codes and parameter names,
  and per data type the property names, JSON types and the "read-only" /
  "create-only" flags. No prose is stored. `--doc-index` / `--doc-page` show
  pages as text for a human, line by line through the same verifier;
  `--doc-find REGEX` names the documented endpoints that mention something;
  `--doc-artifacts` / `--doc-swagger` read the machine-readable description
  published beside the reference (`ui/swagger.json`) as schema facts only.
- An object's own `perms` map is reported as three statements (read; edit / assign /
  create / delete; annotate), never by permission name, value or count, and nothing
  is exercised to see what a category permits. `P2_PROBE_INCIDENT_ID` and `P2_PROBE_TASK_ID` (an
  owner-designated disposable task) stay in memory like every other id.
- **Owner-designated objects.** `--designated` sends GETs to the designated incident and
  task only (plus that incident's own notes, attachments and artifacts); a 403/404 or a
  task outside the incident stops it. `--designated-task` is ONE GET of the task in the
  output formats the web UI uses, and it is sent only when a valid close/reopen
  observation pair is on record.

- **The task tree, as the web UI reads it.** `--tasktree` is ONE
  `GET incidents/{incident_id}/tasktree` with the two output-format controls sent as
  HEADERS (`handle_format`, `text_content_output_format`: closed names and values; the
  client can set no other header). The tree is narrowed in memory to exactly one
  designated task in the designated incident, or to nothing; no other task is kept.
  `task_layout` is recorded as a class, and the fresh task is compared with the observed
  UI requests and the recorded direct GET. The endpoint is not in the appliance's
  reference or its swagger description.
- **The pre-mutation report.** `--preflight-close` is two GETs (task tree, incident) and
  never a PUT: the real candidate builder's verdict on the fresh task, the permission
  evidence (the documented `read`/`write`/`close` flags of the task's own `perms` map), the
  incident phase kept in memory, and a GO / NO-GO with fixed reasons.

### The browser observation of a task save (`shape_request.py`, `task_candidate.py`)

```powershell
# copy ONLY the request payload in the browser's Network panel, then (PowerShell):
Get-Clipboard | uv run python scripts/probe/guarded.py shape_request.py --label close `
    --method PUT --path-template "/rest/orgs/{org_id}/tasks/{task_id}" `
    --header handle_format=ids --header text_content_output_format=objects_convert
# ... the same for the request that reopens the task, with --label reopen, then:
uv run python scripts/probe/guarded.py shape_request.py --compare close reopen
```

`shape_request.py` keeps key names, JSON types and a few safe state facts: the status
letter, whether `closed_date` is null, the `active` and `required` booleans, and two
booleans saying whether the body is the designated task in the designated incident (the
ids are compared in memory). `--label close` must carry status `C` and `--label reopen`
status `O`; anything else is refused and nothing is written. `--compare` is offline: it
says whether the two recordings are a valid pair and how they differ, in types and
booleans.

`task_candidate.py` is the body-construction algorithm of the task PUT experiment: a
fresh read, deep-copied, with `status` as the ONLY change. `closed_date` is a prerequisite
and passes through (null before a close, non-null before a reopen; never cleared, never
invented). `task_layout` is never normalised: with the task-tree source it must be in the
representation the UI was observed to send (null); with the documented source it must be
the empty list the documented GET returns, and goes back untouched. Anything unsettled is
a stop. The module is pure: it imports no HTTP client and cannot send anything.

`task_experiment.py` is the controlled experiment the owner authorised for a disposable
lab appliance and one designated disposable task. It is research tooling, it is the only
file here that can send a `PUT`, and it is not part of the installed package:

```bash
uv run python scripts/probe/guarded.py task_experiment.py --source documented            # dry run: two GETs
uv run python scripts/probe/guarded.py task_experiment.py --source documented --execute  # close, verify, reopen, verify
```

`--source documented` reads the task with the documented `GET /tasks/{task_id}`;
`--source tasktree` (the default, kept for provenance) reads it from the undocumented,
UI-internal task tree, narrowed in memory to exactly one designated task. Its client has
fixed operations on the designated objects only (GET the task, GET the incident's task
tree, GET the incident, PUT the task) and no general request method; a ceiling of 7 GET,
2 PUT and 9 requests in which an attempt counts even if it fails; nothing is retried and
there is no alternate body. A PUT takes a `Candidate` from `task_candidate.py`, not a
body: it must differ from the fresh read in `status` only, the first must close and the
second may only reopen. The credential must report `read`, `write` and `close` true on
the task; every PUT is followed by verification reads whatever it answered; a changed
incident phase after the close is a hard stop with no reopen. `safe_http.py`, which every
other tool uses, still refuses every `PUT`.

Its fixtures are `p2_00b_<step>.json` and `_ledger_00b.json`, next to the P2-00
evidence, which it never rewrites.

## Output

`tests/fixtures/soar/verified/`: one `<step>.json` per request
(`_fixture: "verified-shape"`), `_ledger.json` (every request as method, path
template, status, content type, size bucket; the on-box documented endpoints;
anything refused by policy) and `_tls.json`. These are evidence, not inputs to
`tests/fake_soar.py`, whose fixtures stay labelled `synthetic`.

Nothing is written to `scripts/probe/raw/` (git-ignored) unless you add that
yourself; the tooling has no raw-capture mode on purpose.
