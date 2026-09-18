# 00 — Gap Analysis: Current vs. Target

> **Basis for this review.** No repository was mounted into this session. This
> analysis is reconstructed from the actual `qradar-soar-mcp` source produced
> earlier in this project (client + server + pyproject + `.env.example` +
> README). If the working tree has since diverged, re-run the checklist in
> §4 before accepting the roadmap.

---

## 1. What exists today (verified)

### 1.1 Actual file layout

```text
qradar-soar-mcp/
├── src/qradar_soar_mcp/
│   ├── __init__.py          # __version__ = "0.1.0"
│   ├── client.py            # single flat module — SoarClient
│   └── server.py            # single flat module — FastMCP + all 18 tools
├── pyproject.toml
├── .env.example
└── README.md
```

This is a **two-module prototype**, not the package structure in the brief.

### 1.2 `client.py` — genuinely good, keep it

| Capability | Status | Notes |
|---|---|---|
| Async `httpx` client over `/rest/orgs/{org_id}` | Done | Stateless, concurrency-safe |
| API-key HTTP Basic auth | Done | Deliberately avoids the `X-sess-id` CSRF handshake |
| `handle_format=names` on every request | Done | IDs ↔ labels in both directions |
| `text_content_output_format=always_text` | Done | Flattens rich text |
| `apply_patch()` optimistic-concurrency helper | Done | GET → build PatchDTO → PATCH → **raise on `success: false`** |
| `properties.<custom_field>` resolution in patches | Done | Correct handling of custom fields |
| `ping()` degrading gracefully when `/session` is restricted | Done | Probes `query_paged` for real reachability |
| `SoarError`, `now_ms()`, `text_content()` helpers | Done | |
| TLS verify as bool *or* CA-bundle path | Done | |

**These behaviours are the hard-won part of this codebase. Nothing in the
roadmap should rewrite them.** The refactor in Phase 1 moves this code, it does
not change its semantics.

### 1.3 `server.py` — 18 tools, one gate

All 10 read and 8 write tools from the brief exist and work. Response shaping
(`_summarise_incident`, `_trim`, `INCIDENT_SUMMARY_FIELDS`) is present and
worth keeping — projecting the ~150-field incident DTO is what makes this
usable rather than context-flooding.

The security model is a single module-level boolean:

```python
ALLOW_WRITES = _env("SOAR_ALLOW_WRITES", "false").lower() in {"1","true","yes","on"}

def _require_writes(action: str) -> None:
    if not ALLOW_WRITES:
        raise SoarError(...)
```

`soar_add_comment` (Tier 1, harmless) and `soar_invoke_action` (Tier 3–5,
reaches the AppHost and whatever it can touch — EDR, firewall, IAM) are behind
**the same flag**. This is the single most important defect in the current
build.

### 1.4 Known lab topology

| Host | Role |
|---|---|
| `soar.example.internal` | QRadar SOAR appliance, org `201` |
| `apphost.example.internal` | AppHost / Integration Server |
| `mcp.example.internal` | MCP server host |

---

## 2. What does not exist

| Brief requirement | Status |
|---|---|
| `config.py` (typed, validated settings) | **Missing** — env parsing is inline in `server.py` |
| `auth.py` | **Missing** — auth is inline in `SoarClient.__init__` |
| `client/` package split (incidents/tasks/artifacts/…/playbooks) | **Missing** — one flat `client.py` |
| `tools/` package split | **Missing** — one flat `server.py` |
| `playbook/` (schema, generator, validator, simulator, compiler, diff) | **Missing entirely** |
| `security/` (permissions, action_policy, approvals, audit) | **Missing entirely** |
| Tiered risk model (Tier 0–5) | **Missing** — one boolean |
| Granular capability flags | **Missing** — only `SOAR_ALLOW_WRITES` |
| Confirmation / approval flow | **Missing** |
| Audit log | **Missing** — no record of what Claude did |
| Log redaction | **Missing** — no logging framework at all |
| 15 playbook-discovery tools | **Missing** (0 of 15) |
| 8 playbook-authoring tools | **Missing** (0 of 8) |
| `tests/` | **Missing** — zero tests |
| `examples/`, `docs/` | **Missing** |
| `LICENSE` | **Missing** — blocks public release |
| `.gitignore` | **Missing** — `.env` is not ignored. **Blocking.** |
| CI | **Missing** |
| Rate limiting / bulk caps | **Missing** |
| Kill switch | **Missing** |

---

## 3. Risk register for the current build

| # | Risk | Severity | Fix |
|---|---|---|---|
| R1 | No `.gitignore`; `.env` with a live API secret can be committed on the first `git add .` | **Critical** | `P1-00` |
| R2 | `soar_invoke_action` gated identically to `soar_add_comment` | **Critical** | `P1-05`, `P1-06` |
| R3 | No audit trail — no answer to "what did the model do at 03:00?" | **High** | `P1-08` |
| R4 | Exceptions may carry URLs/headers containing the key into tool output | **High** | `P1-03`, `P1-09` |
| R5 | `.env.example` ships `SOAR_VERIFY_SSL=false` as the default | **Medium** | `P1-02` |
| R6 | No tests — refactor has no safety net | **High** | `P1-01` before any refactor |
| R7 | `soar_invoke_action` takes a raw `action_id` with no risk classification | **High** | `P1-06` |
| R8 | No cap on how many objects a single tool call can mutate | **Medium** | `P1-07` |
| R9 | Streamable-HTTP mode does zero caller authz; anyone reaching it inherits the SOAR key | **High** | `P1-11` (docs + refuse-to-start guard) |

---

## 4. Pre-flight checklist before starting the roadmap

Run these against the real working tree and record the answers in the tracking
issue:

```bash
git log --oneline -20
git ls-files | sort
git log --all --full-history -- .env          # must return nothing
grep -rn "SOAR_API_KEY_SECRET" --include="*.py" src/
python -c "import qradar_soar_mcp, sys; print(qradar_soar_mcp.__version__)"
uv run qradar-soar-mcp --check                 # against the lab
```

If `git log --all --full-history -- .env` returns **anything**, stop: rotate the
SOAR API key in Administrator Settings → API Keys before doing anything else.
History rewriting alone is not sufficient once a secret has been pushed.

---

## 5. Verdict

The existing code is a **sound Phase-0 foundation**. The REST-layer knowledge
embedded in `client.py` (patch semantics, handle formats, `query_paged`,
close-required fields) is the expensive part and it is already correct.

What is missing is everything between "the API calls work" and "a language
model can be trusted to use them": no risk model, no approval path, no audit,
no tests, no secret hygiene. Phase 1 is therefore **not** new features — it is
retrofitting a safety architecture around working code, then splitting that
code into the target package layout under test.

Phases 3–6 (playbook IR, compilation, deployment) must not begin until Phase 1
and 2 are complete and the security model is enforced by tests.
