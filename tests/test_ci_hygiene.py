"""P1-12: the CI pipeline's local pieces are present, consistent, and clean."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent


def test_ci_workflow_has_every_gate():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for needle in (
        "ruff check",
        "ruff format --check",
        "uv run mypy",
        "--cov-fail-under=80",
        "security/*",
        "--fail-under=95",
        "gitleaks",
        "uv export --locked --extra dev --no-emit-project",
        "pip-audit --strict --desc --disable-pip --require-hashes",
        "check_no_secrets.py",
    ):
        assert needle in text, needle
    doc = yaml.safe_load(text)
    assert set(doc["jobs"]) == {"secrets", "test", "audit"}
    assert doc["jobs"]["test"]["strategy"]["matrix"]["python"] == ["3.12", "3.13"]


def test_precommit_mirrors_ci():
    doc = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hook_ids = {h["id"] for repo in doc["repos"] for h in repo["hooks"]}
    assert {"ruff", "ruff-format", "gitleaks", "mypy", "check-no-secrets"} <= hook_ids


def test_gitleaks_allowlist_covers_the_sentinel_only():
    text = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    assert "SENTINEL-SECRET-DO-NOT-LEAK-7f3a" in text and "useDefault = true" in text


def test_secret_scanner_is_clean_and_scans_the_design_baseline():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_no_secrets.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "clean" in proc.stderr and "design baseline included" in proc.stderr
    assert "NOT scanned" not in proc.stderr


def test_secret_scanner_exempts_no_path(tmp_path: Path):
    """Being authoritative is no pass: a private address in a baseline-named doc is a hit."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("cns", ROOT / "scripts" / "check_no_secrets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert not hasattr(mod, "EXCLUDED_PENDING_OWNER_DECISION")
    baseline = [
        f
        for f in mod.tracked_files(ROOT)
        if f.startswith("docs/design/0")
        or f in ("docs/ACCESS-CHECKLIST.md", "CLAUDE-CODE-PROMPT.md")
    ]
    assert len(baseline) >= 10 and mod.collect_hits(ROOT, baseline) == []

    doc = "docs/design/00-GAP-ANALYSIS.md"
    (tmp_path / "docs" / "design").mkdir(parents=True)
    private = ".".join(["172", "20", "9", "20"])  # assembled so this file stays clean
    (tmp_path / doc).write_text(f"| `{private}` | SOAR appliance |\n", encoding="utf-8")
    hits = mod.collect_hits(tmp_path, [doc])
    assert len(hits) == 1 and "rfc1918 172.16/12" in hits[0]

    # The one illustrative address is allowed only in the file that documents it.
    ((allowed_in, values),) = mod.ALLOWED_EXAMPLES.items()
    example = next(iter(values))
    (tmp_path / allowed_in).write_text(f"blocks `{example}`.\n", encoding="utf-8")
    (tmp_path / doc).write_text(f"blocks `{example}`.\n", encoding="utf-8")
    assert mod.collect_hits(tmp_path, [allowed_in]) == []
    assert len(mod.collect_hits(tmp_path, [doc])) == 1


def test_secret_scanner_catches_a_planted_key(tmp_path: Path):
    """A hardcoded key in a tracked file must fail the scan (P1-12 AC)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("cns", ROOT / "scripts" / "check_no_secrets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    planted = tmp_path / "leak.py"
    # Deliberately fake values. Each line carries the marker of the scanner that would
    # otherwise flag this file: our tree scanner, and gitleaks for the key-shaped one.
    lines = [
        'SOAR_API_KEY_SECRET = "abcdef0123456789abcdef"',  # check_no_secrets:allow gitleaks:allow
        'host = "soar.lab.corp"',  # check_no_secrets:allow
        'ip = "10.1.2.3"',  # check_no_secrets:allow
    ]
    planted.write_text("\n".join(lines) + "\n", encoding="utf-8")
    hits = mod.scan(tmp_path, "leak.py")
    labels = {h.split(": ")[1] for h in hits}
    assert {"api key assignment", "internal hostname", "rfc1918 10/8"} <= labels
    clean = tmp_path / "ok.py"
    clean.write_text(
        'deny = ["10.0.0.0/8", "172.16.0.0/12"]\nurl = "https://soar.example.internal"\n',
        encoding="utf-8",
    )
    assert mod.scan(tmp_path, "ok.py") == []
