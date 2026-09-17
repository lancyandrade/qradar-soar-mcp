# Claude Code — Build Prompt

Two prompts. **Session 1** runs tonight, offline, no SOAR needed. **Session 2**
runs after you have appliance access.

Copy the block verbatim into Claude Code from the repo root. Don't paste both at
once — the first must be complete and merged before the second is meaningful.

Before pasting: put the design docs in the repo at `docs/design/` (files `00-` to
`07-`, plus `README-draft.md` and `env.example`). The prompt refers to them by
path.

---

# SESSION 1 — Phase 0 + Phase 1 (no SOAR access required)

````text
You are the implementing engineer on `qradar-soar-mcp`, an open-source MCP
server that connects Claude to IBM QRadar SOAR (formerly Resilient). This will
be a PUBLIC GitHub repository. Treat it accordingly.

## Read first, before writing any code

Read these in order and do not start implementing until you have:

  docs/design/00-GAP-ANALYSIS.md        current state vs target
  docs/design/01-ARCHITECTURE.md        target design and principles
  docs/design/02-SECURITY-MODEL.md      tiers, flags, approvals, audit
  docs/design/06-ROADMAP-TICKETS.md     the tickets you are implementing
  docs/design/07-TEST-STRATEGY.md       how each ticket is verified
  docs/design/README-draft.md           the README to adopt
  docs/design/env.example               the .env.example to adopt

Skim but do not implement: 03-PLAYBOOK-IR.md, 04-VALIDATION-SIMULATION.md,
05-SOAR-API-SURFACE.md. Those are Phase 2-5.

Then read the existing source (src/qradar_soar_mcp/client.py and server.py) in
full before touching it.

## Scope of this session — hard boundary

Implement, in order: P0-01, P0-02, P0-03, then P1-01 through P1-16.

Do NOT implement anything from Phase 2 onward. Specifically, do not create:
playbook/, catalog/, tools/discovery.py, tools/playbooks.py, or any tool whose
name is not already in the v0.1.0 tool list plus the three added by P1-15.
Creating empty package directories with __init__.py (P0-03) is fine; putting
logic in them is not.

If you finish early, improve tests. Do not start Phase 2.

## Ground rules — violating any of these is a failed task

1. DENY BY DEFAULT. Every capability flag defaults to false. Absent, empty, or
   unparseable config values resolve to false and log a warning. There must be
   no code path where a parse failure, a missing file, or an exception results
   in a permission being granted. Write a test for each.

2. DO NOT CHANGE THE SEMANTICS OF THE EXISTING SOAR CLIENT. The current
   client.py encodes hard-won REST behaviour: PATCH optimistic concurrency with
   version + old_value/new_value, raising on `success: false`,
   `properties.<field>` resolution for custom fields, `handle_format=names` and
   `text_content_output_format=always_text` on every request, POST
   /incidents/query_paged for listing, ping() degrading when /rest/session is
   forbidden. P1-04 MOVES this code into a client/ package. It does not
   rewrite it. Write the characterisation tests (P1-01) FIRST, confirm they
   pass against the unmodified code, and only then refactor.

3. NO INVENTED APIs. Do not add any REST call that is not already present in
   client.py. If you believe an endpoint is needed, add it to a TODO list in
   docs/open-questions.md with the reason, and move on. This project does not
   guess at IBM's API surface.

4. NO SECRETS ANYWHERE. `.gitignore` is the first commit. No key, token, cert,
   hostname, IP, or org id from a real environment goes into any file — use
   `soar.example.internal` and org `201` as generic examples. Scrub the
   existing README of `<lab-subnet>.x`.

5. ONE CHOKEPOINT. After P1-14, every mutating operation must pass through the
   `@soar_tool` decorator, which runs: permission enforce -> action policy ->
   rate/cap check -> approval -> audit PENDING -> execute -> audit COMMITTED.
   No module under tools/ may reach client/ mutating methods outside that path.
   P1-13 must include a test that proves this by AST inspection, not grep.

6. STDIO SAFETY. In stdio transport, stdout is the MCP protocol channel. Nothing
   may print to stdout. All logging goes to stderr. Add a test that asserts
   stdout stays empty across a full tool invocation.

7. THESE TOOLS MUST NOT EXIST, at any tier, in any configuration: delete of any
   SOAR object; create/update of SOAR scripts; arbitrary Python or shell
   execution; bulk operations over more than one object; anything that touches
   the AppHost directly. `SOAR_ALLOW_SCRIPT_WRITES` is parsed and must be
   asserted false. Do not shell out to `resilient-sdk`.

8. NO FABRICATED TEST DATA THAT LOOKS REAL. Fixtures are synthetic and labelled
   as such. Never commit a response captured from a real appliance without
   sanitising it, and there is no appliance in this session anyway.

## Definition of done, per ticket

A ticket is done when:
  - every acceptance criterion in 06-ROADMAP-TICKETS.md is met by a test that
    fails if the behaviour is removed
  - `ruff check` and `ruff format --check` pass
  - `mypy --strict` passes on security/ (and on playbook/ when it exists)
  - `pytest` passes offline on a fresh clone with no environment variables set
  - it is a single commit, message `P1-07: rate limits, mutation caps, kill switch`

Work ticket by ticket. Commit each one separately. Do not batch.

## The keystone test — P1-13

This is the most important thing you will write. It parametrises across every
registered tool x ~14 named config states x both transports and asserts the
expected permission Decision. Tools are enumerated FROM THE REGISTRY, not a
hand-written list, so a new tool with no entry in the expected-outcome table
fails collection.

Two assertions in it matter more than the rest:
  - under the legacy `SOAR_ALLOW_WRITES=true` state, `soar_invoke_action` must
    DENY. That flag maps to Tier 1-2 only. Nobody who set it intended to
    authorise endpoint isolation.
  - over http transport, every tier >= 3 tool denies in every config state,
    including with a valid approval.

## Secret-leak test — P1-03

Inject the sentinel `SENTINEL-SECRET-DO-NOT-LEAK-7f3a` as the API key secret.
Drive every tool to success and to failure, and drive every error path: 401,
403, 404, 409, 422, 500, timeout, TLS failure, connection refused, malformed
JSON, oversized response. Assert the sentinel appears in no tool response, no
log record at any level, no exception str/repr, no audit record, no traceback.

Note the specific trap: httpx.HTTPStatusError.__str__ includes the request URL,
and the Request object carries the Authorization header. Never propagate an
httpx exception. Everything goes through errors.py and is sanitised.

## Verification before you report done

Run and paste the output of:

    ruff check . && ruff format --check .
    mypy --strict src/qradar_soar_mcp/security
    pytest -v --cov=qradar_soar_mcp --cov-report=term-missing
    git check-ignore -v .env
    git log --oneline
    python -c "import qradar_soar_mcp; print(qradar_soar_mcp.__version__)"

Coverage must be >= 95% on security/, >= 80% overall.

Then run these and report the result honestly:
  - grep the whole tree for any RFC1918 address or real hostname
  - confirm `pytest` passes with a completely empty environment
  - confirm the tool list is identical to v0.1.0 plus exactly the three tools
    added by P1-15

## Stop and ask me when

- an acceptance criterion in the design docs is ambiguous or looks wrong. Say
  so rather than picking an interpretation silently.
- a refactor would change observable behaviour of an existing tool.
- you conclude a ticket needs a REST endpoint that isn't already in client.py.
- you find something in the existing code that looks like a security bug not
  listed in the 00-GAP-ANALYSIS.md risk register.

Do not ask permission to proceed between tickets. Work through the list.

## Report at the end

  - ticket-by-ticket status
  - the verification output above
  - anything in docs/open-questions.md you added
  - a one-paragraph honest assessment of what is weakest in what you built
````

---

# SESSION 2 — Phase 2 research (requires SOAR access)

Run this only after Session 1 is merged and you've supplied a **read-only** API
key. This is ticket `P2-00`, and it is deliberately research-only — no feature
code.

````text
This session implements ONLY ticket P2-00 from docs/design/06-ROADMAP-TICKETS.md:
verifying the QRadar SOAR API surface against a real appliance.

Read docs/design/05-SOAR-API-SURFACE.md in full first. Every endpoint there is
marked with a confidence level. Your job is to convert every ⚠️ and ❓ into
either ✅ with a verified path and response shape, or 🚫 with evidence it does
not exist on this version.

## Constraints

1. READ-ONLY. The credential you have is a read-only API key. Issue no POST,
   PATCH, PUT or DELETE — with one exception: POST /configurations/exports,
   which is read-only in effect and which I have separately confirmed is
   acceptable on this appliance. If any other write is needed to answer a
   question, stop and ask.

2. DO NOT BUILD FEATURES. No new MCP tools, no catalog/, no client methods
   beyond a throwaway probe script in scripts/probe/ that is NOT part of the
   package. The deliverable is documentation and fixtures.

3. SANITISE EVERYTHING. This is a public repo. Every captured response must
   have hostnames, IPs, org ids, usernames, email addresses, API keys and any
   real incident content replaced with generic placeholders before it is
   committed. Write the sanitiser as a script so it is repeatable and
   reviewable — do not hand-edit.

4. RECORD WHAT FAILED. A 404 or 403 is a result, not a dead end. Document the
   exact request and the exact status.

## For each endpoint, record

  - exact path and query parameters
  - HTTP status
  - response shape (keys and types, not values)
  - appliance version it was tested against
  - whether it paginates, and how
  - anything surprising

## Priority order — the answers that most change the design

  1. Do playbooks exist as a REST collection on this version? What does a
     playbook object contain? Is there a query_paged variant?
  2. Does POST /configurations/exports work, and does its output contain
     playbooks, functions, scripts, workflows, rules, message destinations,
     incident types, fields and data tables? If yes, the entire Phase 2
     catalog can be built from it and the per-collection endpoints become an
     optimisation rather than a dependency.
  3. Can a SINGLE playbook be exported, or only the full configuration?
  4. How are data tables discovered? Via /types with a discriminator, or
     something else?
  5. Does GET /functions return input definitions (names, types, required)?
     Phase 3 validation is impossible without this. If it needs a parameter
     like view=full, find it.
  6. Can the API key's own permission set be read? If not, design a
     probe-based fallback: attempt a harmless read of each collection and
     record which return 403.
  7. Attachment content endpoint path, and what content type it returns.
  8. Incident history endpoint, and whether it exposes past function results
     (needed for realistic simulation mocking).

## Deliverables

  - docs/soar-api-verified.md — the authoritative record, replacing the
    confidence markers in 05-SOAR-API-SURFACE.md. Update that file to point
    at it.
  - tests/fixtures/soar/*.json — sanitised responses
  - scripts/probe/ — the probe script and the sanitiser, documented, excluded
    from the installed package
  - docs/open-questions.md — anything still unresolved

## Report

For each of the 8 priority questions: the answer, the evidence, and what it
changes in the Phase 3-5 design. Where an endpoint does not exist, say so
plainly and recommend the fallback. Do not soften a negative result — a
confirmed "this is not possible" is more valuable to me than a maybe.
````

---

## Notes on using these

**Why Session 1 needs no SOAR.** Everything in Phase 0–1 is security
architecture, refactoring under characterisation tests, and offline test
infrastructure. It runs entirely against mocked HTTP. You can hand this to
Claude Code tonight and have a merged, tested, publishable v0.2.0 before the
appliance access lands.

**Why the phases are separate prompts.** A single prompt covering Phases 1–5
produces plausible-looking code for endpoints that may not exist. The gating is
the point: Session 2's output can invalidate parts of the Phase 3–5 design, and
that's a feature.

**Expect Session 1 to take several hours of Claude Code time** and to need one
or two rounds of follow-up, most likely on `P1-10` (approvals — the HMAC and
atomic-consumption logic is fiddly) and `P1-13` (the registry-driven
parametrisation). Those are the two worth reviewing by hand yourself.

**One thing to review personally:** the generated `config/action_policy.example.yaml`.
Claude Code will produce a reasonable shape, but the `deny_values` entries are
judgements about a real network and must be yours.
