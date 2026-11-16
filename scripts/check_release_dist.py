"""REL-04: check a release build directory, then write its SHA-256 sums.

Run by `.github/workflows/release.yml` after `uv build`, on the clean checkout of the
tagged commit, before anything is uploaded. It fails (exit 1) unless:

* the tag is ``v<version>`` and ``<version>`` is both the ``pyproject.toml`` version
  and ``qradar_soar_mcp.__version__``;
* the directory holds exactly one sdist and one wheel for that name and version (plus
  the ``.gitignore`` uv writes into its output directory, nothing else);
* every archive member is on the REL-06 allow-list: the git-tracked files of the
  package, the build config, readme and licence in the sdist, the package and
  ``dist-info`` in the wheel; no forbidden component or suffix, no absolute path, no
  ``..``, no link or device member.

With ``--write-sums`` it then writes ``SHA256SUMS`` (``sha256sum`` format, one line
per archive) into the directory. Output names members and files only, never content.
The allow-list constants mirror ``tests/test_packaging.py``; a test keeps them equal.

    uv run python scripts/check_release_dist.py --dist dist --tag v0.2.0 --write-sums
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = "src/qradar_soar_mcp"
SUMS_NAME = "SHA256SUMS"
TAG_RE = re.compile(r"v(\d+\.\d+\.\d+)")

SDIST_TOP_LEVEL = frozenset({"pyproject.toml", "README.md", "LICENSE", "PKG-INFO", ".gitignore"})
WHEEL_DIST_INFO = frozenset({"METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE"})
FORBIDDEN_COMPONENTS = frozenset(
    {
        ".claude",
        ".playwright-mcp",
        ".git",
        ".github",
        ".venv",
        "__pycache__",
        "worktrees",
        "automation",
        "tests",
        "docs",
        "scripts",
        "credentials",
        "screenshots",
    }
)
FORBIDDEN_SUFFIXES = (".log", ".png", ".pem", ".key", ".pyc", ".jsonl", ".env")
# uv build writes a one-line "*" .gitignore into its output directory.
UV_OUT_DIR_IGNORE = ".gitignore"


class DistError(Exception):
    """A release build directory that must not be uploaded."""


def project_metadata(root: Path) -> tuple[str, str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(project["name"]), str(project["version"])


def package_version(root: Path) -> str:
    """``__version__`` read statically from the package (nothing is imported)."""
    tree = ast.parse((root / PACKAGE_DIR / "__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise DistError(f"{PACKAGE_DIR}/__init__.py has no literal __version__")


def tracked_package_files(root: Path) -> frozenset[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z", "--", PACKAGE_DIR],  # noqa: S607 - git from PATH, fixed argv
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    files = frozenset(p for p in out.split("\0") if p)
    if not files:
        raise DistError("git lists no tracked package files")
    return files


def check_versions(tag: str | None, version: str, init_version: str) -> None:
    if init_version != version:
        raise DistError(f"__version__ {init_version!r} != pyproject version {version!r}")
    if tag is None:
        return
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise DistError(f"tag {tag!r} is not v<major>.<minor>.<patch>")
    if match.group(1) != version:
        raise DistError(f"tag {tag!r} does not match pyproject version {version!r}")


def _check_name(name: str, archive: str) -> None:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or "\\" in name:
        raise DistError(f"{archive}: unsafe member path {name!r}")
    if (
        FORBIDDEN_COMPONENTS.intersection(pure.parts)
        or name.endswith(FORBIDDEN_SUFFIXES)
        or pure.name.startswith(".env")
    ):
        raise DistError(f"{archive}: forbidden member {name!r}")


def _compare(archive: str, names: list[str], expected: set[str]) -> None:
    if len(names) != len(set(names)):
        raise DistError(f"{archive}: duplicate members")
    unexpected = sorted(set(names) - expected)
    missing = sorted(expected - set(names))
    if unexpected or missing:
        raise DistError(f"{archive}: unexpected {unexpected}, missing {missing}")


def check_sdist(path: Path, dist: str, version: str, package_files: frozenset[str]) -> None:
    prefix = f"{dist}-{version}/"
    names: list[str] = []
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.isdir()):
                raise DistError(f"{path.name}: non-regular member {member.name!r}")
            if not member.name.startswith(prefix):
                raise DistError(f"{path.name}: member outside {prefix!r}: {member.name!r}")
            rel = member.name.removeprefix(prefix)
            if member.isfile():
                _check_name(rel, path.name)
                names.append(rel)
    _compare(path.name, names, set(SDIST_TOP_LEVEL | package_files))


def check_wheel(path: Path, dist: str, version: str, package_files: frozenset[str]) -> None:
    with zipfile.ZipFile(path) as whl:
        infos = whl.infolist()
    names: list[str] = []
    for info in infos:
        # The high 16 bits of external_attr hold the Unix mode; 0o120000 is a symlink.
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise DistError(f"{path.name}: symlink member {info.filename!r}")
        _check_name(info.filename, path.name)
        names.append(info.filename)
    dist_info = f"{dist}-{version}.dist-info"
    expected = {p.removeprefix("src/") for p in package_files}
    expected |= {f"{dist_info}/{f}" for f in WHEEL_DIST_INFO}
    _compare(path.name, names, expected)


def release_files(dist_dir: Path, dist: str, version: str) -> tuple[Path, Path]:
    sdist_name = f"{dist}-{version}.tar.gz"
    wheel_name = f"{dist}-{version}-py3-none-any.whl"
    present = {p.name for p in dist_dir.iterdir()}
    allowed = {sdist_name, wheel_name, UV_OUT_DIR_IGNORE}
    if extra := sorted(present - allowed):
        raise DistError(f"unexpected files in the build directory: {extra}")
    if missing := sorted({sdist_name, wheel_name} - present):
        raise DistError(f"missing release files: {missing}")
    for name in (sdist_name, wheel_name):
        if (dist_dir / name).is_symlink() or not (dist_dir / name).is_file():
            raise DistError(f"{name} is not a regular file")
    return dist_dir / sdist_name, dist_dir / wheel_name


def sha256sums(paths: list[Path]) -> str:
    lines = []
    for path in sorted(paths, key=lambda p: p.name):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}\n")
    return "".join(lines)


def check(root: Path, dist_dir: Path, tag: str | None, write_sums: bool) -> list[Path]:
    name, version = project_metadata(root)
    check_versions(tag, version, package_version(root))
    dist = name.replace("-", "_")
    package_files = tracked_package_files(root)
    sdist, wheel = release_files(dist_dir, dist, version)
    check_sdist(sdist, dist, version, package_files)
    check_wheel(wheel, dist, version, package_files)
    if write_sums:
        (dist_dir / SUMS_NAME).write_text(sha256sums([sdist, wheel]), encoding="utf-8")
    return [sdist, wheel]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dist", type=Path, required=True, help="the uv build output directory")
    parser.add_argument("--tag", help="the release tag; must be v<pyproject version>")
    parser.add_argument("--write-sums", action="store_true", help=f"write {SUMS_NAME}")
    args = parser.parse_args(argv)
    try:
        files = check(ROOT, args.dist, args.tag, args.write_sums)
    except (DistError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        sys.stderr.write(f"check_release_dist: FAIL: {exc}\n")
        return 1
    names = ", ".join(p.name for p in files)
    sums = f"; wrote {SUMS_NAME}" if args.write_sums else ""
    sys.stderr.write(f"check_release_dist: ok: {names}{sums}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
