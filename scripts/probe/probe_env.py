"""Connection values for the P2-00 probe. They are read, used and never shown.

Source order: the process environment, then a git-ignored ``.env`` at the
repository root. Only names are ever reported. ``ProbeEnv`` has no useful
``repr`` on purpose.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = ("SOAR_BASE_URL", "SOAR_ORG_ID", "SOAR_API_KEY_ID", "SOAR_API_KEY_SECRET")
OPTIONAL = (
    "SOAR_VERIFY_SSL",
    "SOAR_TIMEOUT",
    "P2_PROBE_TLS_MODE",
    "P2_PROBE_CA_BUNDLE",
    # The package's own CA-bundle variable (P2-TLS, 08 §22). P2-00b accepts either name.
    "SOAR_CA_BUNDLE",
    # An incident the owner picked (for example one known to carry an attachment).
    # Used in memory to build paths; never printed or recorded.
    "P2_PROBE_INCIDENT_ID",
    # P2-00b: a disposable task the owner designated, inside P2_PROBE_INCIDENT_ID.
    # Used in memory only, like the incident id.
    "P2_PROBE_TASK_ID",
)


class ProbeEnvError(RuntimeError):
    """Names the missing variables; never a value."""


def _dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    data = path.read_bytes()
    boms = (bytes([0xFF, 0xFE]), bytes([0xFE, 0xFF]))  # UTF-16 LE / BE
    encoding = "utf-16" if data[:2] in boms else "utf-8-sig"
    for raw in data.decode(encoding, errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key = key.strip()
        if key in REQUIRED or key in OPTIONAL:
            values[key] = value.strip().strip("'\"")
    return values


@dataclass(frozen=True, slots=True)
class ProbeEnv:
    base_url: str = field(repr=False)
    org_id: str = field(repr=False)
    key_id: str = field(repr=False)
    key_secret: str = field(repr=False)
    verify_ssl: str = field(default="true", repr=False)
    timeout: float = 30.0
    tls_mode: str = "auto"
    ca_bundle: str = field(default="", repr=False)
    incident_id: str = field(default="", repr=False)
    source: str = "environment"
    soar_ca_bundle: str = field(default="", repr=False)
    task_id: str = field(default="", repr=False)

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def port(self) -> int:
        parts = urlsplit(self.base_url)
        return parts.port or (443 if parts.scheme == "https" else 80)

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme

    def literals(self) -> dict[str, str]:
        """Label -> literal, for the verifier. Used for matching only."""
        out = {
            "base url": self.base_url.rstrip("/"),
            "host": self.host,
            "org id": self.org_id,
            "api key id": self.key_id,
            "api key secret": self.key_secret,
        }
        if self.incident_id:
            out["chosen incident id"] = self.incident_id
        if self.task_id:
            out["chosen task id"] = self.task_id
        if self.ca_bundle:
            out["ca bundle path"] = self.ca_bundle
            out["ca bundle name"] = Path(self.ca_bundle).name
        if self.soar_ca_bundle:
            out["soar ca bundle path"] = self.soar_ca_bundle
            out["soar ca bundle name"] = Path(self.soar_ca_bundle).name
        if self.verify_ssl.lower() not in ("true", "false", ""):
            out["verify path"] = self.verify_ssl
            out["verify name"] = Path(self.verify_ssl).name
        return {k: v for k, v in out.items() if v}


def load_env(*, required: bool = True) -> ProbeEnv:
    merged = _dotenv(ROOT / ".env")
    source = ".env" if merged else "environment"
    for name in (*REQUIRED, *OPTIONAL):
        if os.environ.get(name):
            merged[name] = os.environ[name]
            source = "environment" if name in REQUIRED else source
    missing = [n for n in REQUIRED if not merged.get(n)]
    if missing:
        if required:
            raise ProbeEnvError("missing: " + ", ".join(missing))
        return ProbeEnv("", "", "", "")
    try:
        timeout = float(merged.get("SOAR_TIMEOUT") or 30)
    except ValueError:
        timeout = 30.0
    return ProbeEnv(
        base_url=merged["SOAR_BASE_URL"].rstrip("/"),
        org_id=merged["SOAR_ORG_ID"].strip(),
        key_id=merged["SOAR_API_KEY_ID"],
        key_secret=merged["SOAR_API_KEY_SECRET"],
        verify_ssl=merged.get("SOAR_VERIFY_SSL") or "true",
        timeout=timeout,
        tls_mode=(merged.get("P2_PROBE_TLS_MODE") or "auto").strip().lower(),
        ca_bundle=merged.get("P2_PROBE_CA_BUNDLE") or "",
        incident_id=(merged.get("P2_PROBE_INCIDENT_ID") or "").strip(),
        source=source,
        soar_ca_bundle=merged.get("SOAR_CA_BUNDLE") or "",
        task_id=(merged.get("P2_PROBE_TASK_ID") or "").strip(),
    )


def describe_presence() -> list[str]:
    """Names and presence only."""
    dotenv = _dotenv(ROOT / ".env")
    lines = []
    for name in (*REQUIRED, *OPTIONAL):
        where = "environment" if os.environ.get(name) else ".env" if dotenv.get(name) else "not set"
        lines.append(f"{name}: {where}")
    return lines


if __name__ == "__main__":
    for line in describe_presence():
        print(line)
