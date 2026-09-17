# Access & Information Checklist

What I need from you, split by when I need it. Phase 0–1 (security architecture,
refactor, tests) needs **none** of this — Claude Code can do all of it offline
tonight. Everything below is what unblocks Phase 2 onward.

---

## A. Needed before any code is written (you, 5 minutes)

| # | Item | Why |
|---|---|---|
| A1 | **Repo name** — I'd suggest `qradar-soar-mcp` (matches the package, matches what people will search for) | Ticket P0-01 |
| A2 | **Licence choice — Apache-2.0 or MIT** | Apache-2.0 if you want the patent grant and the NOTICE convention, which is the norm for security tooling others may adopt commercially. MIT if you want maximum simplicity. Pick one; it goes in `LICENSE` and `pyproject.toml`. |
| A3 | **Security contact address** for `SECURITY.md` | Public repos that touch security platforms need a non-issue reporting path. A dedicated alias, not your personal mail. |
| A4 | **Confirm: is this repo under `lancyandrade` personally, or an org?** | Affects CI secret scope and whether you want branch protection from day one. I'd recommend an org even for a solo project — it makes transferring or adding maintainers later painless. |
| A5 | **Existing repo state** — if `qradar-soar-mcp` already exists as a private repo with the v0.1.0 code, give me `git log --oneline -20` and `git ls-files` output | I reviewed the code from our earlier session, not the live tree. If they've diverged I need to know before the refactor. |

### A6 — One thing to check before making anything public

```bash
git log --all --full-history -- .env
git log -p --all | grep -iE "api_key_secret|<lab-subnet-regex>|BEGIN .*PRIVATE KEY"
```

If `.env` appears anywhere in history, **rotate the SOAR API key before the repo
goes public**, not after. History rewriting doesn't help once it's pushed.

Also: the v0.1.0 README hardcoded `<lab-soar-ip>`, `<lab-apphost-ip>` and org `201`.
Those are RFC1918 so the disclosure is minor, but a public repo shouldn't carry
your lab topology. All docs should use `soar.example.internal` / org `201` as a
generic example. I've already done that in the README draft.

---

## B. Needed tomorrow, for Phase 1 verification (SOAR access)

| # | Item | Notes |
|---|---|---|
| B1 | **SOAR base URL** reachable from wherever the work happens | |
| B2 | **Organisation ID** | |
| B3 | **SOAR version** — exact, from Administrator Settings → About | Drives everything in `05-SOAR-API-SURFACE.md`. Playbooks are a v44+ feature; below that, Phase 3–5 targets workflows instead and the design changes materially. |
| B4 | **API key #1 — read-only.** Permission set: read incidents, tasks, artifacts, notes, attachments, users, field/type metadata, and **read** functions/scripts/workflows/rules/playbooks/message destinations | This is the key for Phase 1–2. 90% of the work uses only this. |
| B5 | **Appliance CA certificate** (PEM) | So we can develop with `SOAR_VERIFY_SSL=<path>` instead of `false`. `verify=false` in a security tool's own docs is a bad look for a public repo. |
| B6 | **Network path** — can the dev host reach the appliance directly, or is a jump host / VPN involved? | |

## C. Needed for Phase 2 research (P2-00), same key as B4

Nothing extra — P2-00 is read-only endpoint probing. But I need to know:

| # | Item |
|---|---|
| C1 | Is it acceptable to run `POST /configurations/exports` against this appliance? It's read-only but generates a full config export — some orgs treat that as sensitive. |
| C2 | Roughly how many playbooks / rules / workflows / functions exist? Tells me whether the catalog can be loaded wholesale or needs pagination. |
| C3 | Which app packages are installed on the AppHost (names + versions)? This is the function inventory Phase 3 validates against. |

---

## D. Needed for Phase 4–5 (mutating work) — not tomorrow, but plan for it

| # | Item | Notes |
|---|---|---|
| D1 | **API key #2 — read+write.** Adds create/edit incidents, add notes, add artifacts, edit tasks, invoke actions | Kept separate and only used deliberately. |
| D2 | **API key #3 — config admin.** Adds configuration import/export | Only used in Phase 4+. Three keys, three blast radii. |
| D3 | **A disposable organisation** (e.g. `MCP-TEST`) for mutating tests | Never test writes against an org with real data. |
| D4 | **A second disposable org** for config-import tests | Imports aren't cleanly reversible. |
| D5 | **VM snapshot capability** on the appliance, or a confirmed full-config-export restore path | Needed before the first import. Untested restore = no restore. |
| D6 | **A mock AppHost host** — one small VM/container | See below. Most important item in this table. |

### D6 — The mock AppHost

One host running a `resilient-circuits` app that implements
`fn_edr_isolate_endpoint`, `fn_firewall_block_ip`, `fn_disable_account` as
**loggers that touch nothing**, bound to their own message destinations in the
disposable org.

This is what makes the Tier-3 paths testable end-to-end: we can prove the
approval gate blocks an isolation request by asserting the mock received zero
calls, rather than asserting our own logs say we didn't call it. Without it,
those code paths get their first real exercise in someone's production SOC.

A small VM or even a container alongside the existing AppHost is enough. It
should **not** be the real AppHost at any point.

---

## E. What I do not want access to

Stating this explicitly because it shapes the design:

- **No access to the real AppHost / Integration Server.** App installation and
  function-code modification are Tier 5 architectural non-goals. If I can't
  reach it, I can't accidentally design toward it.
- **No production SOAR.** Lab only, for the whole roadmap.
- **No credentials for downstream controls** (EDR, firewall, IAM) — the whole
  point is that SOAR holds those and we only ever reach them through
  pre-classified, approved actions.
- **No client environments.** Given the sectors you consult in, nothing from a
  client deployment should enter a public repo, including in test fixtures.
  Every fixture in this project comes from your own lab and gets sanitised.

---

## F. GitHub side — what you do, what I produce

I can't create repos or push. Split:

**You:**
1. Create `github.com/lancyandrade/qradar-soar-mcp` (or org), public, no
   auto-generated README.
2. Branch protection on `main`: require PR, require CI green.
3. Enable secret scanning + push protection (free on public repos — this is the
   single highest-value setting for this project).
4. Add topics: `mcp`, `model-context-protocol`, `qradar`, `soar`, `resilient`,
   `ibm-qradar`, `security-automation`, `claude`.

**Me / Claude Code:** every file. The design docs I've already produced go in
`docs/design/`, and the Claude Code prompt in `CLAUDE-CODE-PROMPT.md` drives
the Phase 0–1 implementation.
