"""P0-01 / P0-02 / P0-03 acceptance criteria."""

from __future__ import annotations

import importlib
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


# ----------------------------------------------------------------- P0-01


def test_env_is_ignored():
    assert _git("check-ignore", "-v", ".env").endswith("\t.env")


@pytest.mark.parametrize(
    "name",
    [
        "secret.pem",
        "id.key",
        "cert.p12",
        "export.resz",
        "export.res",
        "audit.jsonl",
        "snapshots/x",
        "approvals/x",
        "config/action_policy.yaml",
        "dist/x",
        ".venv/x",
    ],
)
def test_ticket_patterns_are_ignored(name: str):
    assert _git("check-ignore", name) == name


def test_env_never_committed_in_any_ref():
    assert _git("log", "--all", "--full-history", "--oneline", "--", ".env") == ""


# ----------------------------------------------------------------- P0-02


def test_governance_files_present_and_consistent():
    for name in ("LICENSE", "CODE_OF_CONDUCT.md", "SECURITY.md", "CONTRIBUTING.md"):
        assert (ROOT / name).is_file(), name
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text and "Version 2.0" in license_text
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["license"] == "Apache-2.0"
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "lancy@gulfsoftware.com" in security
    assert "write access to a security platform" in security
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "No secrets" in contributing and "Deny by default" in contributing


# ----------------------------------------------------------------- P0-03


@pytest.mark.parametrize(
    "package",
    [
        "qradar_soar_mcp",
        "qradar_soar_mcp.client",
        "qradar_soar_mcp.tools",
        "qradar_soar_mcp.playbook",
        "qradar_soar_mcp.security",
        "qradar_soar_mcp.catalog",
    ],
)
def test_skeleton_packages_import(package: str):
    importlib.import_module(package)


def test_version_is_the_phase_one_milestone():
    import qradar_soar_mcp

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert qradar_soar_mcp.__version__ == pyproject["project"]["version"] == "0.2.0"


@pytest.mark.parametrize("package", ["playbook"])
def test_future_phase_packages_hold_no_behaviour(package: str):
    """``catalog/`` left this list with P2-01 (08 §25); ``playbook/`` is Phase 3."""
    files = sorted(p.name for p in (ROOT / "src" / "qradar_soar_mcp" / package).glob("*.py"))
    assert files == ["__init__.py"], f"{package}/ must stay empty until its phase: {files}"


@pytest.mark.parametrize("directory", ["tests", "docs", "examples", "config"])
def test_support_directories_exist(directory: str):
    assert (ROOT / directory).is_dir()
