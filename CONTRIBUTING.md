# Contributing

Thank you for considering a contribution. Two rules are not negotiable; read
them first.

## 1. No secrets, anywhere, ever

This is a public repository for a tool that holds a SOAR API key.

- Never commit `.env`, keys, certificates, tokens, or anything captured from a
  real appliance. `.gitignore` covers the obvious names; that is not an excuse
  to skip checking.
- Use `soar.example.internal` and org `201` as generic examples. No real
  hostnames, IP addresses or org ids.
- Captured responses (Phase 2) go through the sanitiser script before they are
  committed, never hand-edited.
- CI runs a secret scanner over the tree. A hit fails the build.

If you realise you have pushed a secret: rotate it first, then tell us. History
rewriting does not un-leak anything.

## 2. Deny by default

Every capability is off until an operator turns it on. A change that makes an
absent, empty, or unparseable configuration value grant something is a bug of
the highest class, and the permission-matrix test exists to catch it. Do not
"fix" a failing matrix test by editing the expected table unless the design
document changed first.

## Ground rules for code

- The design lives in `docs/design/`. Read `01-ARCHITECTURE.md`,
  `02-SECURITY-MODEL.md` and `08-GREENFIELD-AMENDMENTS.md` before proposing
  a structural change; propose the change to the design document first.
- **No invented APIs.** `client/` may only call REST endpoints the design marks
  as known-good for the current phase. If you need another endpoint, add it to
  `docs/open-questions.md` with the reason and stop; an AST test will reject it
  otherwise.
- Every tool goes through `@soar_tool`. Every mutating tool has a tier and a
  capability. A new tool must be added to the permission-matrix expectations or
  the suite will not collect.
- Nothing prints to stdout. In stdio transport, stdout is the MCP channel.
- Tests are offline. The suite must pass on a fresh clone with no environment
  variables set and no network.

## Workflow

```bash
uv sync --extra dev
uv run pre-commit install
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

Open a pull request against `main`. Keep PRs to one ticket where possible and
name the ticket (`P1-07`) in the commit message.

### Golden files and snapshots (T3)

Expected outputs live in `tests/golden/` (golden files, LAB-03 pilot) and
`tests/__snapshots__/` (syrupy). A normal test run never rewrites them. To regenerate:

```bash
uv run pytest -m golden --golden-update
```

```bash
uv run pytest --snapshot-update
```

CI never passes either flag (`tests/test_golden.py` asserts it). A pull request that
changes any expected file must say why in its description, and a human reads every
changed expected file before merge. Under REL-03 phase 1 this review is a **manual
maintainer responsibility, not an enforced control**: the ruleset requires a pull
request but no approval or code-owner review, so a regenerated expectation can make an
output regression pass CI. Changes to the tool manifest (G1) are security-relevant and
go in the changelog.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
