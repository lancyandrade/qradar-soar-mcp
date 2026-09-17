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

## Reporting a vulnerability

Email **lancy@gulfsoftware.com** with:

- a description of the issue and the component involved (`security/`,
  `client/`, `tools/`, transport, CLI);
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
- Any path by which the API key, an approval key, or a bearer token reaches
  MCP output, a log line, an audit record or an exception message.
- Approval replay, forgery, or argument-hash mismatch acceptance.
- Audit chain tampering that `qradar-soar-audit verify` does not detect.
- Configuration values that fail *open* (a parse error granting a capability).

## Out of scope

- The security of IBM QRadar SOAR itself, the App Host, or the integrations
  SOAR drives. Report those to IBM.
- Deployments that set `SOAR_LAB_MODE=true` or `SOAR_APPROVAL_MODE=disabled`;
  those settings exist for labs and are documented as unsafe.
- Operator-authored `action_policy.yaml` content. The mechanism enforcing the
  file is in scope; the correctness of your classifications is not.

## Supported versions

Only the latest release on `main` receives fixes.
