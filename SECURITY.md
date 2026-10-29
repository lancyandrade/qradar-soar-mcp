# Security policy

## What this project is

`qradar-soar-mcp` lets a language model operate IBM QRadar SOAR through the
Model Context Protocol. **When its write capabilities are enabled, it grants an
LLM write access to a security platform**, and — through SOAR manual actions —
potentially to the EDR, firewall and identity systems SOAR integrates with. A
vulnerability here can have consequences well beyond this codebase.

Everything except reading is off by default. Read
[docs/design/02-SECURITY-MODEL.md](docs/design/02-SECURITY-MODEL.md) and
[docs/threat-model.md](docs/threat-model.md) before enabling anything above
Tier 1.

## Security properties of this release (0.2.0)

What the code enforces today. The threat model names the module behind each item
and what each one does **not** cover.

- **Deny by default.** Every capability flag is off. A value that cannot be parsed
  resolves to the safe side, and settings that cannot be resolved safely refuse to
  start.
- **One enforcement pipeline.** Every tool runs through it, in this order:
  capability flag, policy classification, tier, transport, kill switch, circuit
  breaker, one-object cap, approval, audit record, hourly cap, the SOAR call, audit
  record, redaction. An AST test fails the build if a tool reaches the SOAR client any
  other way.
- **Caps.** One object per call; 25 Tier-2 and 5 Tier-3 mutations per hour, rebuilt
  from the audit log on restart (Tier 1 is not capped); a circuit breaker after three
  consecutive Tier ≥2 failures; a kill-switch file that stops every mutation without
  a restart.
- **Credential custody.** The SOAR key and the HTTP bearer token are redacted from
  logs, errors, tool output and audit records. The server holds only the Ed25519
  **public** approval key; the private key stays with the approver.
- **Audit.** A hash-chained, append-only JSONL log of every denial, approval event and
  mutation attempt, verifiable with `qradar-soar-audit verify`. An unwritable log
  refuses the mutation. Successful reads are not audited.
- **Untrusted content.** Incident text and SOAR configuration (scripts, workflow and
  playbook XML, descriptions) are treated as data. The server never runs a script,
  and no request that writes a script exists.

Not implemented, or deliberately blocked, in this release:

- **Manual-action invocation.** `soar_invoke_action` refuses every call
  (`DENY_UNSUPPORTED`): SOAR's invocation contract is unverified. So the out-of-band
  approval flow, though built and tested offline, is never reached.
- **Playbook and configuration changes** (Tier 4): no tools; the flags are reserved.
- **Tier 5** (bulk mutation, deletion, script writes, AppHost or app changes): no
  flag and no tool, by design. `SOAR_ALLOW_SCRIPT_WRITES=true` refuses to start.
- **A permission probe** of the SOAR API key: no endpoint a read-only key can use
  reports it, so the key's own SOAR permission set is the operator's control.
- **Attachment contents** are never fetched.

## Reporting a vulnerability

Email **lancy@gulfsoftware.com** with:

- a description of the issue and the component involved (`security/`,
  `client/`, `tools/`, `catalog/`, transport, CLI);
- steps to reproduce, ideally against the offline test harness
  (`tests/fake_soar.py`) so no real SOAR instance is needed;
- the impact as you understand it (secret disclosure, permission bypass,
  approval bypass, audit tampering, unintended mutation).

Please **do not open a public GitHub issue** for anything that could be used
against a live SOAR deployment. You will get an acknowledgement within five
working days.

## In scope

- Any path by which a tool call can mutate SOAR without passing the
  `@soar_tool` chokepoint, or without the capability flag, policy decision,
  cap, approval or audit record the security model requires.
- Any way around the kill switch, the hourly caps, the one-object cap or the
  circuit breaker.
- Any request to SOAR outside the documented REST surface, in particular one that
  creates, changes or runs a script, workflow or playbook.
- Any path by which the API key, an approval key, or a bearer token reaches
  MCP output, a log line, an audit record or an exception message.
- Approval replay, forgery, or argument-hash mismatch acceptance.
- Audit chain tampering that `qradar-soar-audit verify` does not detect.
- Configuration values that fail *open* (a parse error granting a capability).
- The HTTP transport accepting a request without the bearer token, binding all
  interfaces without the acknowledgement, or permitting Tier ≥3.

## Out of scope

- The security of IBM QRadar SOAR itself, the App Host, or the integrations
  SOAR drives. Report those to IBM.
- Deployments that set `SOAR_LAB_MODE=true`, `SOAR_APPROVAL_MODE=in_band` or
  `disabled`, `SOAR_VERIFY_SSL=false`, or a confirmation switch
  (`SOAR_REQUIRE_ACTION_CONFIRMATION`, `SOAR_REQUIRE_PLAYBOOK_CONFIRMATION`) to
  `false`; those settings exist for labs and are documented as unsafe. The server
  starting with any of them *without* `SOAR_LAB_MODE=true` (approval modes: with
  actions or a Tier-4 flag enabled) is a bug and in scope.
- Operator-authored `action_policy.yaml` content. The mechanism enforcing the
  file is in scope; the correctness of your classifications is not.
- What the SOAR API key's own permission set allows. The recommended two-instance
  deployment exists because this server cannot narrow it.
- A model being persuaded by incident text to *propose* something. What is in scope
  is any way that persuasion gets past a control above.

## Supported versions

Only the latest release on `main` receives fixes.
