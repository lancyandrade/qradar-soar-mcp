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
| `safe_http.py` | The only HTTP path. `GET` under `/rest/` and `/docs/`, plus exactly three semantically read-only `POST`s with key-by-key body validation. Everything else is refused before anything is sent. |
| `sanitise.py` | Shape extraction, the enum allow-list, and the verifier that rejects environment-specific text. Also a CLI: `--check FILE…`. |
| `probe.py` | The plan, mapped to the eight P2-00 priority questions, and the runner. |
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
   `PUT`, `PATCH` and `DELETE`, and every `POST` except three that are read-only
   in effect: `incidents/query_paged`, `playbooks/query_paged` and
   `configurations/exports`. A query body may hold only `filters`, `sorts`,
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

## Output

`tests/fixtures/soar/verified/`: one `<step>.json` per request
(`_fixture: "verified-shape"`), `_ledger.json` (every request as method, path
template, status, content type, size bucket; the on-box documented endpoints;
anything refused by policy) and `_tls.json`. These are evidence, not inputs to
`tests/fake_soar.py`, whose fixtures stay labelled `synthetic`.

Nothing is written to `scripts/probe/raw/` (git-ignored) unless you add that
yourself; the tooling has no raw-capture mode on purpose.
