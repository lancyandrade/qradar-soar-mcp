"""REL-04: check a release build directory, then write its SHA-256 sums.

Run by `.github/workflows/release.yml` after `uv build`, on the clean checkout of the
tagged commit, before anything is uploaded. It fails (exit 1) unless:

* the tag is ``v<version>`` and ``<version>`` is both the ``pyproject.toml`` version
  and ``qradar_soar_mcp.__version__``;
* the directory holds exactly one sdist and one wheel for that name and version (plus
  the ``.gitignore`` uv writes into its output directory, nothing else);
* **paths and structure:** every archive member is on the REL-06 allow-list: the
  git-tracked files of the package, the build config, readme and licence in the sdist,
  the package and ``dist-info`` in the wheel; no forbidden component or suffix, no
  absolute path, no ``..``, no link or device member;
* **content:** every member copied from the source is byte-for-byte the file git holds
  at ``--ref`` (default ``HEAD``; the workflow passes the tagged commit): in the sdist
  everything but ``PKG-INFO``, in the wheel every package file and the licence. The
  generated files are checked for what they must say: ``PKG-INFO`` and ``METADATA``
  name the project and version, ``entry_points.txt`` holds exactly the
  ``[project.scripts]`` of ``pyproject.toml``, and ``RECORD`` lists every other wheel
  member exactly once with its correct SHA-256 and size.

Not checked: the rest of the generated metadata (for example the dependency list in
``METADATA``), which hatchling derives from the checked ``pyproject.toml``.

With ``--write-sums`` it then writes ``SHA256SUMS`` (``sha256sum`` format, one line
per archive) into the directory. Output names members and files only, never content.
The allow-list constants mirror ``tests/test_packaging.py``; a test keeps them equal.

    uv run python scripts/check_release_dist.py --dist dist --tag v0.2.0 --ref HEAD --write-sums
"""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import email.parser
import hashlib
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

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


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", *args],  # noqa: S607 - git from PATH
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout


class Source:
    """The files an archive must reproduce: git's blobs at ``ref``, or the working tree.

    ``ref=None`` reads the working tree (the packaging tests build from it). A release
    passes the tagged commit, so a file that differs from that commit cannot pass.
    """

    def __init__(self, root: Path, ref: str | None) -> None:
        self.root = root
        self.ref = ref
        self._cache: dict[str, bytes] = {}

    def read(self, rel: str) -> bytes:
        if rel not in self._cache:
            if self.ref is None:
                self._cache[rel] = (self.root / rel).read_bytes()
            else:
                try:
                    self._cache[rel] = _git(self.root, "cat-file", "blob", f"{self.ref}:{rel}")
                except subprocess.CalledProcessError as exc:
                    raise DistError(f"{rel} is not in git at {self.ref!r}") from exc
        return self._cache[rel]

    def text(self, rel: str) -> str:
        return self.read(rel).decode("utf-8")

    def package_files(self) -> frozenset[str]:
        if self.ref is None:
            out = _git(self.root, "ls-files", "-z", "--", PACKAGE_DIR)
        else:
            out = _git(self.root, "ls-tree", "-r", "-z", "--name-only", self.ref, "--", PACKAGE_DIR)
        files = frozenset(p for p in out.decode("utf-8").split("\0") if p)
        if not files:
            raise DistError("git lists no tracked package files")
        return files


def _project(source: Source) -> dict[str, Any]:
    project = tomllib.loads(source.text("pyproject.toml")).get("project")
    if not isinstance(project, dict):
        raise DistError("pyproject.toml has no [project] table")
    return project


def project_metadata(root: Path, ref: str | None = None) -> tuple[str, str]:
    project = _project(Source(root, ref))
    return str(project["name"]), str(project["version"])


def project_scripts(source: Source) -> dict[str, str]:
    scripts = _project(source).get("scripts", {})
    return {str(k): str(v) for k, v in scripts.items()}


def package_version(root: Path, ref: str | None = None) -> str:
    """``__version__`` read statically from the package (nothing is imported)."""
    tree = ast.parse(Source(root, ref).text(f"{PACKAGE_DIR}/__init__.py"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise DistError(f"{PACKAGE_DIR}/__init__.py has no literal __version__")


def tracked_package_files(root: Path, ref: str | None = None) -> frozenset[str]:
    return Source(root, ref).package_files()


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


def _check_same(archive: str, member: str, data: bytes, source: Source, rel: str) -> None:
    if data != source.read(rel):
        raise DistError(f"{archive}: {member} differs from {rel} in the source")


def _check_core_metadata(archive: str, member: str, data: bytes, name: str, version: str) -> None:
    headers = email.parser.BytesHeaderParser().parsebytes(data)
    if headers.get_all("Name") != [name] or headers.get_all("Version") != [version]:
        raise DistError(f"{archive}: {member} does not name {name} {version}")


def check_sdist(
    path: Path, dist: str, name: str, version: str, package_files: frozenset[str], source: Source
) -> None:
    prefix = f"{dist}-{version}/"
    contents: dict[str, bytes] = {}
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
                handle = tar.extractfile(member)
                if handle is None:
                    raise DistError(f"{path.name}: unreadable member {rel!r}")
                contents[rel] = handle.read()
    _compare(path.name, names, set(SDIST_TOP_LEVEL | package_files))
    for rel, data in sorted(contents.items()):
        if rel == "PKG-INFO":
            _check_core_metadata(path.name, rel, data, name, version)
        else:
            _check_same(path.name, rel, data, source, rel)


def _record_digest(data: bytes) -> str:
    raw = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + raw.decode("ascii")


def _check_record(archive: str, record: str, contents: dict[str, bytes], dist_info: str) -> None:
    """RECORD lists every other member once with its SHA-256 and size, itself unhashed."""
    seen: dict[str, tuple[str, str]] = {}
    for line in record.splitlines():
        if not line:
            continue
        parts = line.rsplit(",", 2)
        if len(parts) != 3:
            raise DistError(f"{archive}: malformed RECORD line")
        member, digest, size = parts
        if member in seen:
            raise DistError(f"{archive}: RECORD lists {member!r} twice")
        seen[member] = (digest, size)
    record_name = f"{dist_info}/RECORD"
    if seen.pop(record_name, None) != ("", ""):
        raise DistError(f"{archive}: RECORD must list itself without a hash")
    expected = {m for m in contents if m != record_name}
    if set(seen) != expected:
        listed, omitted = sorted(set(seen) - expected), sorted(expected - set(seen))
        raise DistError(f"{archive}: RECORD lists {listed}, omits {omitted}")
    for member, (digest, size) in sorted(seen.items()):
        data = contents[member]
        if digest != _record_digest(data) or size != str(len(data)):
            raise DistError(f"{archive}: RECORD hash or size wrong for {member!r}")


def _check_entry_points(archive: str, data: bytes, scripts: dict[str, str]) -> None:
    parser = configparser.ConfigParser(interpolation=None, delimiters=("=",))
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    parser.read_string(data.decode("utf-8"))
    if parser.sections() != ["console_scripts"]:
        raise DistError(f"{archive}: entry_points.txt sections {parser.sections()}")
    if dict(parser["console_scripts"]) != scripts:
        raise DistError(f"{archive}: entry_points.txt differs from [project.scripts]")


def check_wheel(
    path: Path, dist: str, name: str, version: str, package_files: frozenset[str], source: Source
) -> None:
    contents: dict[str, bytes] = {}
    names: list[str] = []
    with zipfile.ZipFile(path) as whl:
        for info in whl.infolist():
            # The high 16 bits of external_attr hold the Unix mode; 0o120000 is a symlink.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise DistError(f"{path.name}: symlink member {info.filename!r}")
            _check_name(info.filename, path.name)
            names.append(info.filename)
            contents[info.filename] = whl.read(info)
    dist_info = f"{dist}-{version}.dist-info"
    expected = {p.removeprefix("src/") for p in package_files}
    expected |= {f"{dist_info}/{f}" for f in WHEEL_DIST_INFO}
    _compare(path.name, names, expected)
    for member, data in sorted(contents.items()):
        if not member.startswith(f"{dist_info}/"):
            _check_same(path.name, member, data, source, f"src/{member}")
    licence = f"{dist_info}/licenses/LICENSE"
    _check_same(path.name, licence, contents[licence], source, "LICENSE")
    _check_core_metadata(path.name, "METADATA", contents[f"{dist_info}/METADATA"], name, version)
    scripts = project_scripts(source)
    _check_entry_points(path.name, contents[f"{dist_info}/entry_points.txt"], scripts)
    record = contents[f"{dist_info}/RECORD"].decode("utf-8")
    _check_record(path.name, record, contents, dist_info)


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


def check(
    root: Path, dist_dir: Path, tag: str | None, write_sums: bool, ref: str | None = None
) -> list[Path]:
    """Check ``dist_dir`` against the source at ``ref`` (``None``: the working tree)."""
    source = Source(root, ref)
    name, version = project_metadata(root, ref)
    check_versions(tag, version, package_version(root, ref))
    dist = name.replace("-", "_")
    package_files = source.package_files()
    sdist, wheel = release_files(dist_dir, dist, version)
    check_sdist(sdist, dist, name, version, package_files, source)
    check_wheel(wheel, dist, name, version, package_files, source)
    if write_sums:
        (dist_dir / SUMS_NAME).write_text(sha256sums([sdist, wheel]), encoding="utf-8")
    return [sdist, wheel]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dist", type=Path, required=True, help="the uv build output directory")
    parser.add_argument("--tag", help="the release tag; must be v<pyproject version>")
    parser.add_argument(
        "--ref", default="HEAD", help="the commit the archives must reproduce (default HEAD)"
    )
    parser.add_argument("--write-sums", action="store_true", help=f"write {SUMS_NAME}")
    args = parser.parse_args(argv)
    try:
        files = check(ROOT, args.dist, args.tag, args.write_sums, ref=args.ref)
    except (
        DistError,
        OSError,
        UnicodeDecodeError,
        configparser.Error,
        subprocess.CalledProcessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        sys.stderr.write(f"check_release_dist: FAIL: {exc}\n")
        return 1
    names = ", ".join(p.name for p in files)
    sums = f"; wrote {SUMS_NAME}" if args.write_sums else ""
    sys.stderr.write(f"check_release_dist: ok: {names}{sums}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
