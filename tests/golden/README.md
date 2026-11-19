# T3 golden files (PILOT, LAB-03, D22 open)

Expected outputs compared byte for byte by `tests/test_golden.py` through
`tests/golden_support.py`. Canonical JSON: sorted keys, two-space indent, UTF-8, `\n`,
one final newline.

| Group | File | Generator test | Input |
|---|---|---|---|
| G1 | `g1_tool_manifest/manifest.json` | `test_g1_tool_manifest` | the tool registry, via the MCP server's `list_tools` |
| G7 | `g7_catalog/lab_v51_summary.json` | `test_g7_offline_catalog_summary` | `tests/fixtures/catalog/lab-v51.json` |
| G9 | `g9_errors/error_shapes.json` | `test_g9_error_shapes` | every `SoarError` class, fixed synthetic message |

**This pilot does not meet the `07 §7.5` T3 release gate.** The gate needs the owner's
D22 decision, the approved output list (LAB-03 §3) and the LAB-03 §9 evidence.

Regenerate only on purpose, and review every changed file before merge:

```bash
uv run pytest -m golden --golden-update
```

CI never passes `--golden-update` (asserted). Under REL-03 phase 1 the review of a
changed expected file is a manual maintainer responsibility, not an enforced control
(LAB-03 §7). Changes to G1 are security-relevant and go in the changelog.
