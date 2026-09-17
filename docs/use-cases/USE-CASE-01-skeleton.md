# Use Case 01 — Skeleton for the public write-up

> **This is a scaffold, not the finished article.** Every `⟦FILL⟧` marker is
> something that must come from a real run against your lab. I've written the
> narrative, structure and all the parts determined by the design; I have not
> written the tool outputs, because a published use-case with invented SOAR
> responses would be the single fastest way to lose credibility on a security
> repo. People will try to reproduce it.
>
> Fill it in during Phase 5 (`P5-04`), which already requires an end-to-end lab
> walkthrough. This document and that ticket are the same piece of work.
>
> Target path in repo: `docs/use-cases/01-phishing-to-playbook.md`, linked from
> the README.

---

## Choosing the scenario

Your ask was "build a playbook on the fly and also take action if required".
The scenario needs to satisfy four constraints:

1. Common enough that every SOC reader recognises it.
2. Contains a genuine judgement call, so Claude's reasoning is visible.
3. Has a Tier-3 action worth gating, so the approval model is demonstrated
   rather than described.
4. Reproducible in a lab with a mock AppHost — no real EDR needed.

**Recommended: credential-phishing with a confirmed click.**

A user reports a phishing mail. The URL was clicked. Two artifacts (sender
domain, URL) and one affected user. The judgement call is whether the click led
to credential submission — which determines whether you disable the account
(Tier 3, disruptive, wakes someone up) or just reset at next logon (Tier 2).
That's a real decision a Tier-1 analyst gets wrong regularly, which makes it a
good showcase and an honest one.

Alternative if your lab has better malware data: the encoded-PowerShell
scenario from the design docs. Same shape, endpoint isolation instead of account
disable.

---

## Structure

### Part 0 — Framing (write this last, it's the part people read)

Two paragraphs. What this shows, and what it does **not** show. Be explicit:
this is a lab, the downstream actions hit a mock AppHost, and the playbook
produced is not a drop-in for anyone else's environment. A reader who feels
oversold in paragraph one won't reach the interesting part.

### Part 1 — The environment

- SOAR version ⟦FILL⟧, MCP server version, transport (stdio)
- Which tiers were enabled and why: start at Tier 0–1 only
- `action_policy.yaml` excerpt showing `fn_disable_account` classified Tier 3
  `require_approval` with `deny_values` covering break-glass and service
  accounts ⟦FILL: your real classification⟧
- Diagram: Claude Desktop → MCP → SOAR → mock AppHost → (nothing)

Show the mock AppHost explicitly. It's the detail that tells a reader you were
careful, and the thing most people replicating this will skip.

### Part 2 — Investigation (Tier 0)

The prompt, verbatim:

> Investigate SOAR incident ⟦ID⟧. Review all artifacts, comments, tasks and
> attachment metadata. Then find how similar incidents were handled previously.
> Tell me whether this is malicious and what you'd recommend. Don't change
> anything yet.

Then: ⟦FILL: the actual transcript⟧ — tool calls made, in order, and Claude's
conclusion.

**Include one thing that went wrong.** A tool call that returned nothing useful,
a field Claude misread, a wrong initial assumption it corrected. Every polished
AI demo omits this and every practitioner notices. The write-up is more
persuasive with it in.

### Part 3 — Documenting the finding (Tier 1)

Enable `SOAR_ALLOW_COMMENTS=true`. Claude writes findings to the incident.
⟦FILL: the comment as written, and the audit log record for it⟧

Show the audit record here — it's the first concrete evidence of the control
model, and it's cheap to show at Tier 1.

### Part 4 — The Tier-3 action and the gate

The interesting part. Prompt:

> Based on your findings, disable the affected user's account.

Show:
1. Claude calling `soar_invoke_action`
2. The tool returning an approval reference, not a result ⟦FILL⟧
3. The mock AppHost log showing **zero** calls received at this point ⟦FILL⟧
4. The `qradar-soar-approve` CLI output — the full rendered plan a human sees
5. Approval, then the action executing exactly once ⟦FILL⟧
6. Replaying the same approval → rejected ⟦FILL⟧
7. The audit chain across all of it ⟦FILL⟧

Step 3 is the load-bearing evidence. Asserting from our own logs that we didn't
call the AppHost proves only that we believe we didn't. Showing the AppHost's
own log is proof.

### Part 5 — Playbook on the fly

Prompt:

> Generate a SOAR playbook so future incidents like this are handled
> automatically. Validate it and simulate it against the last 25 phishing
> incidents. Do not deploy or enable anything until I explicitly approve.

Show, in order:

1. **The IR Claude produced** ⟦FILL⟧ — the full YAML. This is the centrepiece.
   Readers should be able to look at 40 lines and understand the whole playbook,
   which is the entire argument for having an IR.
2. **Validation failing the first time** ⟦FILL⟧. Almost certainly it will —
   missing message destination, unresolved reference, or a function name that
   doesn't exist. Show the structured errors with their `hint` fields, show
   Claude calling the discovery tool the hint named, and show the corrected
   version. **This is the most convincing section in the document** because it
   demonstrates the model cannot deploy something broken, and that the failure
   mode is a useful error rather than a silent success.
3. **Simulation over 25 historical incidents** ⟦FILL⟧ — fire rate, branch
   coverage, and the `would_touch` set. If the playbook would have fired on 22
   of 25 and disabled 4 accounts, say so, including if that number is
   uncomfortable.
4. **The diff** ⟦FILL⟧ against anything already deployed.
5. **Deployment stopping at import-PENDING** ⟦FILL⟧, with SOAR's own breakdown
   next to our diff.
6. **Human approval, then commit — playbook lands disabled** ⟦FILL⟧. Show it
   disabled in the SOAR UI. Screenshot.
7. **Separate enable step** ⟦FILL⟧, or — if `P5-00` concludes there's no
   supported enable API — the instruction to enable it by hand, framed honestly
   as a deliberate control rather than a missing feature.

### Part 6 — What this doesn't do

Non-negotiable section. Cover at minimum:

- Simulation is our own offline interpreter. SOAR has no dry-run API. A green
  simulation proves the logic, not the AppHost functions.
- Config imports have no rollback. Snapshot and manual restore only.
- Playbooks with inline scripts can't be fully read back, so they can't be
  safely modified through this server.
- `deny_values` classification is the operator's judgement and the mechanism
  can't validate it.
- In-band confirmation isn't human approval, and incident artifacts are
  attacker-influenced text — so prompt injection is a live concern, which is
  why the demo uses out-of-band approval throughout.

### Part 7 — Reproducing it

Exact steps, the seed script from `tests/lab/seed.py`, the mock AppHost app, and
the config used. Someone with a SOAR lab should be able to follow it end to end.
If they can't, the use-case is marketing rather than documentation.

---

## Practical notes

**Format.** Markdown in-repo, not a blog post. Asciinema or a short screen
recording for Parts 4–5 helps enormously — the approval gate is much more
convincing seen than read. Link it, don't embed video in the repo.

**Sanitisation.** Every transcript passes through the same sanitiser as the API
fixtures. Real usernames, hostnames, domains and incident content out; generic
placeholders in. Given the sectors you work in, do this with a script, review
the diff, and never hand-edit.

**Length.** Aim for something a SOC lead reads in fifteen minutes. The IR YAML,
the validation-failure loop, and the approval gate are the three things that
must land. Everything else can be trimmed.

**One repo-level suggestion.** Put a 90-second version of Part 4 in the README
itself — the approval prompt with the mock AppHost showing zero calls. It's the
clearest possible statement of what makes this project different from a REST
wrapper, and it belongs above the fold.
