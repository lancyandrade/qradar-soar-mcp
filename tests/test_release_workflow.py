"""REL-04: the tag-triggered release workflow and its archive checker.

The workflow checks below pin the properties the release runbook promises (CI-only
build from a clean checkout of a main commit, locked backend, draft-only release,
no index upload, least privilege), so a later edit cannot quietly drop one. The
checker tests build synthetic archives; ``tests/test_packaging.py`` also runs the
checker over the real sdist and wheel.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")
DOC: dict[str, Any] = yaml.safe_load(TEXT)


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


crd = _load("check_release_dist", ROOT / "scripts" / "check_release_dist.py")


def _steps(job: str) -> list[dict[str, Any]]:
    return DOC["jobs"][job]["steps"]


def _runs(job: str) -> str:
    return "\n".join(s.get("run", "") for s in _steps(job))


# ------------------------------------------------------------ workflow


def test_triggered_only_by_a_version_tag_push():
    on = DOC.get("on", DOC.get(True))  # PyYAML reads the key `on` as True
    assert on == {"push": {"tags": ["v*"]}}


def test_jobs_run_in_order_with_least_privilege():
    jobs = DOC["jobs"]
    assert set(jobs) == {"verify", "build", "release"}
    assert DOC["permissions"] == {"contents": "read"}
    assert jobs["verify"]["permissions"] == {"contents": "read", "actions": "read"}
    assert jobs["build"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
        "attestations": "write",
    }
    assert jobs["release"]["permissions"] == {"contents": "write"}
    assert "needs" not in jobs["verify"]
    assert jobs["build"]["needs"] == "verify"
    assert jobs["release"]["needs"] == "build"
    assert DOC["concurrency"]["cancel-in-progress"] is False


def test_only_the_release_job_runs_in_the_protected_environment():
    """D25 (d): `release` waits for a reviewer; no other job names an environment."""
    jobs = DOC["jobs"]
    assert jobs["release"]["environment"] == "release"
    assert "environment" not in jobs["verify"] and "environment" not in jobs["build"]


def test_verify_refuses_an_unprotected_release_environment_before_building():
    """A missing environment would be created unprotected, so verify fails closed."""
    steps = _steps("verify")
    names = [s.get("name", "") for s in steps]
    idx = names.index("The release environment needs a reviewer and allows only v* tags")
    first_uv = next(i for i, s in enumerate(steps) if "setup-uv" in str(s.get("uses", "")))
    assert idx < first_uv
    run = steps[idx]["run"]
    assert run.startswith("set -euo pipefail")
    assert 'envurl="repos/$GITHUB_REPOSITORY/environments/release"' in run
    assert 'select(.type == "required_reviewers") | .reviewers | length' in run
    assert '[[ "$reviewers" =~ ^[1-9][0-9]*$ ]]' in run
    assert ".deployment_branch_policy.custom_branch_policies // false" in run
    assert '[[ "$custom" == "true" ]]' in run
    assert "$envurl/deployment-branch-policies" in run
    assert '[[ "$policies" == "tag:v*" ]]' in run
    assert steps[idx]["env"] == {"GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}


def test_draft_notes_point_at_the_publication_checklist():
    runs = _runs("release")
    assert "checklist in docs/runbooks/release.md" in runs
    assert "deleted from the draft first" in runs


def test_no_expression_is_interpolated_into_a_shell_script():
    for job in DOC["jobs"]:
        for step in _steps(job):
            assert "${{" not in step.get("run", ""), (job, step.get("name"))


def test_checkouts_keep_no_credentials_and_release_checks_out_nothing():
    for job in ("verify", "build"):
        checkouts = [
            s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/checkout@")
        ]
        assert len(checkouts) == 1
        assert checkouts[0]["with"]["persist-credentials"] is False
    release = _steps("release")
    assert not any(str(s.get("uses", "")).startswith("actions/checkout@") for s in release)
    assert "uv " not in _runs("release") and "python" not in _runs("release")


def test_verify_requires_a_main_commit_with_green_ci_and_reruns_every_gate():
    runs = _runs("verify")
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main' in runs
    assert r"^v[0-9]+\.[0-9]+\.[0-9]+$" in runs
    assert "actions/workflows/ci.yml/runs?head_sha=$GITHUB_SHA&event=push&status=success" in runs
    checkout = _steps("verify")[0]
    assert checkout["with"]["fetch-depth"] == 0
    for needle in (
        "uv sync --locked --extra dev",
        "uv run ruff check .",
        "uv run ruff format --check .",
        "uv run mypy",
        "--cov-fail-under=80",
        "--fail-under=95",
        "scripts/check_no_secrets.py",
        "scripts/check_artifact_hygiene.py",
        "uv export --locked --extra dev --no-emit-project",
        "pip-audit --strict --desc --disable-pip --require-hashes",
    ):
        assert needle in runs, needle


def test_build_uses_the_locked_backend_on_a_clean_checkout():
    runs = _runs("build")
    assert "uv sync --locked --extra dev" in runs
    assert "git status --porcelain --untracked-files=all" in runs
    assert "uv build --no-build-isolation" in runs
    assert "SOURCE_DATE_EPOCH" in runs
    assert (
        'scripts/check_release_dist.py --dist "$RUNNER_TEMP/dist" --tag "$TAG" '
        '--ref "$GITHUB_SHA" --write-sums'
    ) in runs
    names = [s.get("name", "") for s in _steps("build")]
    assert names.index("uv build with the locked hatchling") < next(
        i for i, n in enumerate(names) if n.startswith("Check tag, version")
    )
    uses = [str(s.get("uses", "")) for s in _steps("build")]
    assert any(u.startswith("actions/attest-build-provenance@") for u in uses)
    assert uses[-1].startswith("actions/upload-artifact@")


def test_release_is_a_draft_pre_release_that_never_overwrites():
    runs = _runs("release")
    assert "sha256sum --check --strict SHA256SUMS" in runs
    assert "gh release create" in runs
    # --draft bypasses gh's own existing-release check, so the step looks first,
    # drafts included, and the lookup comes before the create.
    lookup = 'repos/$GITHUB_REPOSITORY/releases?per_page=100"'
    assert "gh api --paginate" in runs and lookup in runs
    assert "select(.tag_name == env.TAG)" in runs
    assert runs.index(lookup) < runs.index('gh release create "$TAG"')
    for flag in ("--draft", "--prerelease", "--verify-tag"):
        assert flag in runs, flag
    for forbidden in ("--clobber", "gh release upload", "gh release edit", "--latest"):
        assert forbidden not in runs, forbidden


def test_nothing_is_published_to_an_index():
    lowered = TEXT.lower()
    for needle in ("pypi-publish", "twine", "uv publish", "upload.pypi.org", "test.pypi.org"):
        assert needle not in lowered, needle


# ------------------------------------------------------------ checker constants


def test_checker_allow_list_matches_the_packaging_tests():
    tp = _load("tp_constants", ROOT / "tests" / "test_packaging.py")
    assert crd.SDIST_TOP_LEVEL == tp.SDIST_TOP_LEVEL
    assert crd.WHEEL_DIST_INFO == tp.WHEEL_DIST_INFO
    assert crd.FORBIDDEN_COMPONENTS == tp.FORBIDDEN_COMPONENTS
    assert crd.FORBIDDEN_SUFFIXES == tp.FORBIDDEN_SUFFIXES
    assert crd.PACKAGE_DIR == tp.PACKAGE_DIR


def test_package_and_project_versions_agree():
    name, version = crd.project_metadata(ROOT)
    assert name == "qradar-soar-mcp"
    assert crd.package_version(ROOT) == version


# ------------------------------------------------------------ checker behaviour

NAME, VERSION = crd.project_metadata(ROOT)
DIST = NAME.replace("-", "_")
PACKAGE_FILES = crd.tracked_package_files(ROOT)


DIST_INFO = f"{DIST}-{VERSION}.dist-info"
SCRIPTS = crd.project_scripts(crd.Source(ROOT, None))


def _pkg_info(version: str = VERSION) -> bytes:
    return f"Metadata-Version: 2.4\nName: {NAME}\nVersion: {version}\n".encode()


def _entry_points(scripts: dict[str, str] = SCRIPTS) -> bytes:
    body = "".join(f"{k} = {v}\n" for k, v in scripts.items())
    return f"[console_scripts]\n{body}".encode()


def _write_sdist(
    path: Path,
    extra: tuple[str, ...] = (),
    drop: str | None = None,
    override: dict[str, bytes] | None = None,
) -> None:
    """An sdist with the working tree's bytes (what `ref=None` compares against)."""
    prefix = f"{DIST}-{VERSION}/"
    names = sorted((crd.SDIST_TOP_LEVEL | PACKAGE_FILES) - {drop}) + list(extra)
    override = override or {}
    with tarfile.open(path, "w:gz") as tar:
        for rel in names:
            if rel in override:
                data = override[rel]
            elif rel == "PKG-INFO":
                data = _pkg_info()
            elif (ROOT / rel).is_file():
                data = (ROOT / rel).read_bytes()
            else:
                data = b"x"
            info = tarfile.TarInfo(prefix + rel)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def _wheel_contents() -> dict[str, bytes]:
    contents = {p.removeprefix("src/"): (ROOT / p).read_bytes() for p in PACKAGE_FILES}
    contents[f"{DIST_INFO}/METADATA"] = _pkg_info()
    contents[f"{DIST_INFO}/WHEEL"] = b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
    contents[f"{DIST_INFO}/entry_points.txt"] = _entry_points()
    contents[f"{DIST_INFO}/licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    return contents


def _record(contents: dict[str, bytes]) -> bytes:
    lines = [
        f"{m},{crd._record_digest(d)},{len(d)}"
        for m, d in contents.items()
        if m != f"{DIST_INFO}/RECORD"
    ]
    return ("\n".join([*lines, f"{DIST_INFO}/RECORD,,"]) + "\n").encode()


def _write_wheel(
    path: Path,
    extra: tuple[str, ...] = (),
    override: dict[str, bytes] | None = None,
    record: bytes | None = None,
) -> None:
    """A wheel whose RECORD is correct for its members unless `record` is given."""
    contents = _wheel_contents()
    contents.update({rel: b"x" for rel in extra})
    contents.update(override or {})
    contents[f"{DIST_INFO}/RECORD"] = record if record is not None else _record(contents)
    with zipfile.ZipFile(path, "w") as whl:
        for rel, data in contents.items():
            whl.writestr(rel, data)


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    _write_sdist(tmp_path / f"{DIST}-{VERSION}.tar.gz")
    _write_wheel(tmp_path / f"{DIST}-{VERSION}-py3-none-any.whl")
    (tmp_path / ".gitignore").write_text("*\n", encoding="utf-8")
    return tmp_path


def test_a_good_build_passes_and_gets_sha256sums(dist: Path):
    files = crd.check(ROOT, dist, f"v{VERSION}", write_sums=True)
    assert [p.name for p in files] == [
        f"{DIST}-{VERSION}.tar.gz",
        f"{DIST}-{VERSION}-py3-none-any.whl",
    ]
    lines = (dist / crd.SUMS_NAME).read_text(encoding="utf-8").splitlines()
    by_name = sorted(files, key=lambda p: p.name)
    expected = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in by_name]
    assert lines == expected


@pytest.mark.parametrize(
    ("tag", "message"),
    [
        ("0.2.0", "is not v<major>"),
        (f"v{VERSION}-rc1", "is not v<major>"),
        ("v99.0.0", "does not match pyproject version"),
    ],
)
def test_bad_tags_are_refused(dist: Path, tag: str, message: str):
    with pytest.raises(crd.DistError, match=message):
        crd.check(ROOT, dist, tag, write_sums=True)
    assert not (dist / crd.SUMS_NAME).exists()


def test_version_mismatch_with_the_package_is_refused():
    with pytest.raises(crd.DistError, match="__version__"):
        crd.check_versions(f"v{VERSION}", VERSION, "0.0.1")


def test_an_extra_file_in_the_build_directory_is_refused(dist: Path):
    (dist / "stray.txt").write_text("x", encoding="utf-8")
    with pytest.raises(crd.DistError, match="unexpected files"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_a_missing_archive_is_refused(dist: Path):
    (dist / f"{DIST}-{VERSION}-py3-none-any.whl").unlink()
    with pytest.raises(crd.DistError, match="missing release files"):
        crd.check(ROOT, dist, None, write_sums=False)


@pytest.mark.parametrize(
    "member",
    [
        ".claude/settings.local.json",
        "src/qradar_soar_mcp/canary.log",
        "src/qradar_soar_mcp/__pycache__/x.cpython-312.pyc",
        "tests/test_x.py",
        ".env",
        "src/qradar_soar_mcp/extra.py",
    ],
)
def test_sdist_with_an_unlisted_member_is_refused(dist: Path, member: str):
    _write_sdist(dist / f"{DIST}-{VERSION}.tar.gz", extra=(member,))
    with pytest.raises(crd.DistError, match=r"forbidden member|unexpected \["):
        crd.check(ROOT, dist, None, write_sums=False)


def test_sdist_missing_a_package_file_is_refused(dist: Path):
    victim = sorted(PACKAGE_FILES)[0]
    _write_sdist(dist / f"{DIST}-{VERSION}.tar.gz", drop=victim)
    with pytest.raises(crd.DistError, match="missing"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_sdist_link_and_traversal_members_are_refused(dist: Path):
    path = dist / f"{DIST}-{VERSION}.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        link = tarfile.TarInfo(f"{DIST}-{VERSION}/LICENSE")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
    with pytest.raises(crd.DistError, match="non-regular member"):
        crd.check(ROOT, dist, None, write_sums=False)
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(f"{DIST}-{VERSION}/../escape.py")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(crd.DistError, match="unsafe member path"):
        crd.check(ROOT, dist, None, write_sums=False)
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("other-1.0/LICENSE")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(crd.DistError, match="member outside"):
        crd.check(ROOT, dist, None, write_sums=False)


@pytest.mark.parametrize("member", ["qradar_soar_mcp/notes.log", "docs/x.md", "/abs.py"])
def test_wheel_with_an_unlisted_member_is_refused(dist: Path, member: str):
    _write_wheel(dist / f"{DIST}-{VERSION}-py3-none-any.whl", extra=(member,))
    with pytest.raises(crd.DistError, match=r"forbidden member|unsafe member path"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_symlink_member_is_refused(dist: Path):
    path = dist / f"{DIST}-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(path, "a") as whl:
        info = zipfile.ZipInfo("qradar_soar_mcp/link.py")
        info.external_attr = 0o120777 << 16
        whl.writestr(info, "/etc/passwd")
    with pytest.raises(crd.DistError, match="symlink member"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_cli_reports_failure_without_writing_sums(dist: Path, capsys: pytest.CaptureFixture[str]):
    assert crd.main(["--dist", str(dist), "--tag", "v99.0.0", "--write-sums"]) == 1
    assert "FAIL" in capsys.readouterr().err
    assert not (dist / crd.SUMS_NAME).exists()
    assert crd.main(["--dist", str(dist), "--tag", f"v{VERSION}", "--write-sums"]) == 0
    assert (dist / crd.SUMS_NAME).is_file()


# ------------------------------------------------------------ checker: content

A_MODULE = f"{crd.PACKAGE_DIR}/__init__.py"


def test_sdist_file_that_differs_from_the_source_is_refused(dist: Path):
    tampered = (ROOT / A_MODULE).read_bytes() + b"\n# injected\n"
    _write_sdist(dist / f"{DIST}-{VERSION}.tar.gz", override={A_MODULE: tampered})
    with pytest.raises(crd.DistError, match="differs from"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_sdist_build_config_that_differs_from_the_source_is_refused(dist: Path):
    tampered = (ROOT / "pyproject.toml").read_bytes().replace(b"\n", b"\r\n")
    _write_sdist(dist / f"{DIST}-{VERSION}.tar.gz", override={"pyproject.toml": tampered})
    with pytest.raises(crd.DistError, match=r"pyproject\.toml differs"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_sdist_pkg_info_for_another_version_is_refused(dist: Path):
    _write_sdist(dist / f"{DIST}-{VERSION}.tar.gz", override={"PKG-INFO": _pkg_info("9.9.9")})
    with pytest.raises(crd.DistError, match="PKG-INFO does not name"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_file_that_differs_from_the_source_is_refused_even_with_a_good_record(
    dist: Path,
):
    member = A_MODULE.removeprefix("src/")
    tampered = (ROOT / A_MODULE).read_bytes() + b"\n# injected\n"
    _write_wheel(dist / f"{DIST}-{VERSION}-py3-none-any.whl", override={member: tampered})
    with pytest.raises(crd.DistError, match="differs from"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_licence_that_differs_from_the_source_is_refused(dist: Path):
    _write_wheel(
        dist / f"{DIST}-{VERSION}-py3-none-any.whl",
        override={f"{DIST_INFO}/licenses/LICENSE": b"not the licence\n"},
    )
    with pytest.raises(crd.DistError, match="LICENSE differs"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_metadata_for_another_version_is_refused(dist: Path):
    _write_wheel(
        dist / f"{DIST}-{VERSION}-py3-none-any.whl",
        override={f"{DIST_INFO}/METADATA": _pkg_info("9.9.9")},
    )
    with pytest.raises(crd.DistError, match="METADATA does not name"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_entry_points_must_be_exactly_the_project_scripts(dist: Path):
    extra = {**SCRIPTS, "backdoor": "qradar_soar_mcp.server:main"}
    _write_wheel(
        dist / f"{DIST}-{VERSION}-py3-none-any.whl",
        override={f"{DIST_INFO}/entry_points.txt": _entry_points(extra)},
    )
    with pytest.raises(crd.DistError, match=r"differs from \[project\.scripts\]"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_record_with_a_wrong_hash_is_refused(dist: Path):
    contents = _wheel_contents()
    member = A_MODULE.removeprefix("src/")
    bad = dict(contents)
    bad[member] = b"something else"
    record = _record(bad)  # hashes a different body than the one stored
    _write_wheel(dist / f"{DIST}-{VERSION}-py3-none-any.whl", record=record)
    with pytest.raises(crd.DistError, match="RECORD hash or size wrong"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_record_that_omits_a_member_is_refused(dist: Path):
    contents = _wheel_contents()
    member = A_MODULE.removeprefix("src/")
    record = _record({m: d for m, d in contents.items() if m != member})
    _write_wheel(dist / f"{DIST}-{VERSION}-py3-none-any.whl", record=record)
    with pytest.raises(crd.DistError, match="omits"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_wheel_record_must_list_itself_unhashed(dist: Path):
    contents = _wheel_contents()
    lines = [f"{m},{crd._record_digest(d)},{len(d)}" for m, d in contents.items()]
    _write_wheel(
        dist / f"{DIST}-{VERSION}-py3-none-any.whl",
        record=("\n".join(lines) + "\n").encode(),
    )
    with pytest.raises(crd.DistError, match="RECORD must list itself"):
        crd.check(ROOT, dist, None, write_sums=False)


def test_source_at_a_ref_reads_git_blobs_and_refuses_unknown_paths():
    source = crd.Source(ROOT, "HEAD")
    assert source.read("pyproject.toml").startswith(b"[build-system]")
    with pytest.raises(crd.DistError, match="is not in git at 'HEAD'"):
        source.read("no/such/file.txt")
    assert f"{crd.PACKAGE_DIR}/__init__.py" in source.package_files()


def test_cli_compares_against_head_by_default(dist: Path, monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, object] = {}

    def fake_check(root: Path, d: Path, tag: str | None, write: bool, ref: str | None = None):
        seen["ref"] = ref
        return []

    monkeypatch.setattr(crd, "check", fake_check)
    assert crd.main(["--dist", str(dist)]) == 0
    assert seen["ref"] == "HEAD"
    assert crd.main(["--dist", str(dist), "--ref", "abc123"]) == 0
    assert seen["ref"] == "abc123"
