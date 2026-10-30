"""LAB-01: the lab-tier guards, tested offline (docs/lab-validation-plan.md §5).

Proves, with no network: a lab tier that is not enabled is skipped; an enabled tier
with a missing, ambiguous or unsafe target fails instead of falling back (to the
server's own ``SOAR_*`` target, to another organisation, or from a mock AppHost to a
real one); the T4 transport filter lets only reads leave; and the lab suite as a
whole skips everything when no ``SOAR_TEST_*`` variable is set (how CI runs it).
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from tests.lab.guard import (
    ENABLE_VAR,
    LabNotEnabledError,
    LabRefusedError,
    LabTier,
    LabWriteBlocked,
    ReadOnlyTransport,
    capture_env,
    enabled_tiers,
    resolve,
)

ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = ROOT / "tests" / "lab"
SECRET = "lab-secret-value"
WRITE_SECRET = "lab-write-secret"
HOST = "soar.example.com"

T4 = {
    ENABLE_VAR: "lab",
    "SOAR_TEST_BASE_URL": f"https://{HOST}",
    "SOAR_TEST_TARGET_ACK": HOST,
    "SOAR_TEST_ORG_ID": "201",
    "SOAR_TEST_API_KEY_ID": "read-key",
    "SOAR_TEST_API_KEY_SECRET": SECRET,
}
T5 = {
    **T4,
    ENABLE_VAR: "lab_write",
    "SOAR_TEST_WRITE_ORG_ID": "301",
    "SOAR_TEST_DISPOSABLE_ORG_ACK": "301",
    "SOAR_TEST_WRITE_API_KEY_ID": "write-key",
    "SOAR_TEST_WRITE_API_KEY_SECRET": WRITE_SECRET,
}
T6 = {
    **T5,
    ENABLE_VAR: "lab_destructive",
    "SOAR_TEST_MOCK_APPHOST_URL": "https://mock-apphost.example.com",
    "SOAR_TEST_MOCK_APPHOST_ACK": "mock-apphost.example.com",
    "SOAR_TEST_REAL_APPHOST_HOSTS": "apphost.example.com",
}
FULL = {LabTier.READ_ONLY: T4, LabTier.WRITE: T5, LabTier.DESTRUCTIVE: T6}


def _refused(env: dict[str, str], tier: LabTier, needle: str, **kw) -> str:
    with pytest.raises(LabRefusedError) as info:
        resolve(env, tier, **kw)
    message = str(info.value)
    assert needle in message, message
    assert SECRET not in message and WRITE_SECRET not in message
    return message


# --------------------------------------------------------------- opt-in
@pytest.mark.parametrize("tier", list(LabTier))
def test_not_enabled_skips_even_with_a_complete_target(tier: LabTier):
    env = {k: v for k, v in FULL[tier].items() if k != ENABLE_VAR}
    with pytest.raises(LabNotEnabledError):
        resolve(env, tier)


@pytest.mark.parametrize("tier", list(LabTier))
def test_enabling_one_tier_does_not_enable_another(tier: LabTier):
    for other in LabTier:
        if other is not tier:
            with pytest.raises(LabNotEnabledError):
                resolve({**T6, ENABLE_VAR: tier.value}, other)


def test_unknown_tier_name_refuses_rather_than_skipping():
    with pytest.raises(LabRefusedError, match="unknown tier"):
        enabled_tiers({ENABLE_VAR: "lab,lab_wirte"})
    assert enabled_tiers({ENABLE_VAR: " lab , lab_write "}) == {LabTier.READ_ONLY, LabTier.WRITE}


@pytest.mark.parametrize("tier", list(LabTier))
def test_a_complete_target_resolves_and_hides_its_secret(tier: LabTier):
    target = resolve(FULL[tier], tier)
    assert target.tier is tier and target.host == HOST
    assert SECRET not in repr(target) and WRITE_SECRET not in repr(target)


# -------------------------------------------------- incomplete ⇒ refuse
@pytest.mark.parametrize("tier", list(LabTier))
def test_every_required_variable_missing_refuses(tier: LabTier):
    env = FULL[tier]
    # T5/T6 run with the write key; the read-only secret is not used there.
    optional = {ENABLE_VAR} | (
        {"SOAR_TEST_API_KEY_SECRET"} if tier is not LabTier.READ_ONLY else set()
    )
    for var in sorted(set(env) - optional):
        broken = {k: v for k, v in env.items() if k != var}
        with pytest.raises(LabRefusedError) as info:
            resolve(broken, tier)
        assert SECRET not in str(info.value) and WRITE_SECRET not in str(info.value)


@pytest.mark.parametrize(
    ("url", "needle"),
    [
        (f"http://{HOST}", "https"),
        (f"https://user:pw@{HOST}", "credentials"),
        (f"https://{HOST}/rest", "without a path"),
        (f"https://{HOST}/?x=1", "query"),
        ("https://", "no host"),
    ],
)
def test_unsafe_base_urls_refuse(url: str, needle: str):
    _refused({**T4, "SOAR_TEST_BASE_URL": url}, LabTier.READ_ONLY, needle)


def test_target_must_be_acknowledged_by_host():
    _refused({**T4, "SOAR_TEST_TARGET_ACK": "other.example.com"}, LabTier.READ_ONLY, "TARGET_ACK")


def test_forbidden_host_refuses():
    env = {**T4, "SOAR_TEST_FORBIDDEN_HOSTS": f"prod.example.com, {HOST.upper()}"}
    _refused(env, LabTier.READ_ONLY, "FORBIDDEN_HOSTS")


@pytest.mark.parametrize(
    "runtime_url", [f"https://{HOST}", f"https://{HOST}:443/", f"http://{HOST}"]
)
def test_the_servers_own_target_is_never_the_lab_target(runtime_url: str):
    """The no-fallback-to-production rule: the host the server is configured for on
    this machine (``SOAR_BASE_URL``) can never be the lab target."""
    for tier in LabTier:
        _refused(FULL[tier], tier, "SOAR_BASE_URL", runtime_env={"SOAR_BASE_URL": runtime_url})
    resolve(T4, LabTier.READ_ONLY, runtime_env={"SOAR_BASE_URL": "https://other.example.com"})


def test_runtime_env_is_built_from_the_target_only(tmp_path: Path):
    target = resolve(T4, LabTier.READ_ONLY, runtime_env={"SOAR_BASE_URL": "https://x.example.com"})
    env = target.runtime_env(tmp_path)
    assert env["SOAR_BASE_URL"] == f"https://{HOST}" and env["SOAR_ORG_ID"] == "201"
    assert env["SOAR_VERIFY_SSL"] == "true" and env["SOAR_AUDIT_REQUIRED"] == "true"
    assert not [k for k in env if k.startswith("SOAR_ALLOW_")]
    assert all(str(tmp_path) in env[k] for k in ("SOAR_AUDIT_LOG_PATH", "SOAR_KILL_SWITCH_FILE"))


# ----------------------------------------------- T5 / T6 isolation rules
def test_t5_needs_a_different_acknowledged_disposable_org_and_key():
    _refused({**T5, "SOAR_TEST_WRITE_ORG_ID": "201"}, LabTier.WRITE, "must differ")
    _refused({**T5, "SOAR_TEST_DISPOSABLE_ORG_ACK": "yes"}, LabTier.WRITE, "DISPOSABLE_ORG_ACK")
    _refused({**T5, "SOAR_TEST_WRITE_API_KEY_ID": "read-key"}, LabTier.WRITE, "key must differ")
    target = resolve(T5, LabTier.WRITE)
    assert target.org_id == 301 and target.api_key_id == "write-key"


def test_t6_never_falls_back_from_the_mock_apphost():
    without_mock = {k: v for k, v in T6.items() if not k.startswith("SOAR_TEST_MOCK_")}
    _refused(without_mock, LabTier.DESTRUCTIVE, "SOAR_TEST_MOCK_APPHOST_URL")
    real = {**T6, "SOAR_TEST_MOCK_APPHOST_URL": "https://apphost.example.com"}
    _refused(
        {**real, "SOAR_TEST_MOCK_APPHOST_ACK": "apphost.example.com"},
        LabTier.DESTRUCTIVE,
        "not a mock",
    )
    same = {
        **T6,
        "SOAR_TEST_MOCK_APPHOST_URL": f"https://{HOST}",
        "SOAR_TEST_MOCK_APPHOST_ACK": HOST,
    }
    _refused(same, LabTier.DESTRUCTIVE, "not a mock")
    no_real = {k: v for k, v in T6.items() if k != "SOAR_TEST_REAL_APPHOST_HOSTS"}
    _refused(no_real, LabTier.DESTRUCTIVE, "REAL_APPHOST_HOSTS")
    _refused({**T6, "SOAR_TEST_MOCK_APPHOST_ACK": "x"}, LabTier.DESTRUCTIVE, "MOCK_APPHOST_ACK")
    forbidden = {**T6, "SOAR_TEST_FORBIDDEN_HOSTS": "mock-apphost.example.com"}
    _refused(forbidden, LabTier.DESTRUCTIVE, "FORBIDDEN_HOSTS")
    target = resolve(T6, LabTier.DESTRUCTIVE)
    assert target.mock_apphost_url == "https://mock-apphost.example.com" and target.org_id == 301


# ------------------------------------------------------- read-only wire
class _Recorder(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.seen.append((request.method, request.url.path))
        return httpx.Response(200, json={})


ALLOWED = [
    ("GET", f"https://{HOST}/rest/session"),
    ("GET", f"https://{HOST}/rest/const"),
    ("GET", f"https://{HOST}/rest/orgs/201/incidents/7"),
    ("POST", f"https://{HOST}/rest/orgs/201/incidents/query_paged"),
    ("POST", f"https://{HOST}/rest/orgs/201/playbooks/query_paged"),
]
BLOCKED = [
    ("POST", f"https://{HOST}/rest/orgs/201/incidents"),
    ("POST", f"https://{HOST}/rest/orgs/201/incidents/7/comments"),
    ("POST", f"https://{HOST}/rest/orgs/201/incidents/7/artifacts"),
    ("PATCH", f"https://{HOST}/rest/orgs/201/incidents/7"),
    ("PUT", f"https://{HOST}/rest/orgs/201/tasks/9"),
    ("DELETE", f"https://{HOST}/rest/orgs/201/incidents/7"),
    ("POST", f"https://{HOST}/rest/orgs/301/incidents/query_paged"),
    ("GET", f"https://{HOST}/rest/orgs/301/incidents/7"),
    ("GET", "https://apphost.example.com/rest/session"),
    ("GET", f"https://{HOST}/elsewhere"),
    # Final review of PR #22: wrong org without a trailing slash, the org list, plain
    # HTTP (credentials in clear), another port, traversal and encoded separators.
    ("GET", f"https://{HOST}/rest/orgs/301"),
    ("GET", f"https://{HOST}/rest/orgs"),
    ("GET", f"http://{HOST}/rest/session"),
    ("GET", f"https://{HOST}:8443/rest/session"),
    ("GET", f"https://{HOST}/rest/orgs/201/%2E%2E/301/incidents"),
    ("GET", f"https://{HOST}/rest/orgs/201%2F..%2F301/incidents"),
    ("GET", f"https://{HOST}/rest/orgs/201/x%5C..%5C301"),
    ("GET", f"https://{HOST}/rest/users"),
    ("OPTIONS", f"https://{HOST}/rest/session"),
    ("POST", f"https://{HOST}/rest/orgs/201/incidents/query_paged/"),
]


async def test_read_only_transport_lets_only_reads_leave():
    inner = _Recorder()
    guard = ReadOnlyTransport(inner, host=HOST, org_id=201)
    async with httpx.AsyncClient(transport=guard) as client:
        for method, url in ALLOWED:
            assert (await client.request(method, url)).status_code == 200
        for method, url in BLOCKED:
            with pytest.raises(LabWriteBlocked):
                await client.request(method, url)
    # Only the allowed requests reached the inner transport; a blocked one never did.
    assert inner.seen == guard.sent == [(m, httpx.URL(u).path) for m, u in ALLOWED]
    assert guard.blocked == [(m, httpx.URL(u).path) for m, u in BLOCKED]


def test_capture_env_separates_lab_and_runtime_variables():
    lab, runtime = capture_env({"SOAR_TEST_BASE_URL": "a", "SOAR_BASE_URL": "b", "PATH": "c"})
    assert lab == {"SOAR_TEST_BASE_URL": "a"} and runtime == {"SOAR_BASE_URL": "b"}


# ---------------------------------------------------------- the suite
def test_every_lab_module_declares_a_lab_marker():
    modules = sorted(p for p in LAB_DIR.glob("test_*.py"))
    assert modules, "LAB-01 ships at least the T4 module"
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        marks = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets)
        ]
        assert marks, f"{path.name}: no module-level pytestmark"
        text = ast.unparse(marks[0].value)
        assert any(f"pytest.mark.{m.value}" == text for m in LabTier), (path.name, text)


def _run_lab_suite(extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOAR_")}
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rs", str(LAB_DIR)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_with_no_lab_variables_every_lab_test_skips():
    """How CI runs: nothing enabled ⇒ every T4 test skips, none passes or fails.
    ``SOAR_BASE_URL`` is set to show the suite ignores the server's own target."""
    proc = _run_lab_suite({"SOAR_BASE_URL": f"https://{HOST}"})
    tail = proc.stdout.strip().splitlines()[-1]
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert "skipped" in tail and "passed" not in tail and "failed" not in tail, tail


def test_enabled_without_a_target_fails_instead_of_skipping():
    """Opting in without a complete target is an error, never a silent skip."""
    proc = _run_lab_suite({ENABLE_VAR: "lab"})
    tail = proc.stdout.strip().splitlines()[-1]
    assert proc.returncode != 0 and ("error" in tail or "failed" in tail), tail
    assert "passed" not in tail, tail
    assert "lab guard refused" in proc.stdout


def test_lab_audit_evidence_is_kept_without_overwriting(tmp_path: Path, monkeypatch):
    """Lab plan §6: the run's audit log survives pytest's temp-dir rotation."""
    from tests.lab import conftest as lab_conftest

    audit = tmp_path / "state" / "audit.jsonl"
    audit.parent.mkdir()
    audit.write_text('{"seq": 1}\n', encoding="utf-8")
    assert lab_conftest.keep_evidence(audit, request_nodeid="x") is None  # unset: nothing
    evidence = tmp_path / "evidence"
    monkeypatch.setitem(lab_conftest.LAB_ENV, "SOAR_TEST_EVIDENCE_DIR", str(evidence))
    node = "tests/lab/test_t4_read_only.py::test_read_tool_answers[soar_list_users] (call)"
    first = lab_conftest.keep_evidence(audit, request_nodeid=node)
    second = lab_conftest.keep_evidence(audit, request_nodeid=node)
    assert first and second and first != second and first.parent == second.parent == evidence
    assert first.read_bytes() == second.read_bytes() == audit.read_bytes()
    assert first.with_suffix(".sha256").read_text(encoding="utf-8").split()[1] == first.name
    assert audit.exists()  # the original is copied, never moved


async def test_runtimes_sharing_a_state_dir_write_one_verifiable_chain(tmp_path: Path):
    """Review m6: T4 uses one state directory per run, so successive runtimes append to
    one audit chain that verifies end to end. Denials only: nothing reaches a network."""
    import json

    from qradar_soar_mcp.security.audit import verify
    from qradar_soar_mcp.tools import TOOL_REGISTRY, Runtime, run_pipeline

    target = resolve(T4, LabTier.READ_ONLY)
    state = tmp_path / "state"
    for _ in range(2):
        rt = Runtime.build(target.runtime_env(state), transport="stdio")
        assert rt.usable
        out = await run_pipeline(
            TOOL_REGISTRY["soar_add_comment"], rt, {"incident_id": 1, "text": "x"}
        )
        assert out["error"]["code"] == "DENY_DISABLED"
        await rt.aclose()
    audit = state / "audit.jsonl"
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line]
    assert [r["seq"] for r in records] == [1, 2]
    assert records[1]["prev_hash"] == records[0]["hash"]
    result = verify(audit)
    assert result.ok and result.records == 2


async def test_read_only_transport_honours_an_explicit_target_port():
    inner = _Recorder()
    guard = ReadOnlyTransport(inner, host=HOST, org_id=201, port=8443)
    async with httpx.AsyncClient(transport=guard) as client:
        assert (await client.get(f"https://{HOST}:8443/rest/session")).status_code == 200
        with pytest.raises(LabWriteBlocked):
            await client.get(f"https://{HOST}/rest/session")  # 443 is not the target
    assert inner.seen == [("GET", "/rest/session")]


def test_target_port_comes_from_the_base_url_and_must_be_valid():
    assert resolve(T4, LabTier.READ_ONLY).port == 443
    explicit = {**T4, "SOAR_TEST_BASE_URL": f"https://{HOST}:8443"}
    assert resolve(explicit, LabTier.READ_ONLY).port == 8443
    _refused({**T4, "SOAR_TEST_BASE_URL": f"https://{HOST}:99999"}, LabTier.READ_ONLY, "port")


@pytest.mark.parametrize("tier", list(LabTier))
def test_the_lab_runtime_never_uses_the_servers_own_credentials(tier: LabTier, tmp_path: Path):
    """No fallback to production credentials: the server's own SOAR_* values (here a
    different host, org and key) never reach the lab runtime environment."""
    production = {
        "SOAR_BASE_URL": "https://prod.example.com",
        "SOAR_ORG_ID": "999",
        "SOAR_API_KEY_ID": "prod-key",
        "SOAR_API_KEY_SECRET": "prod-secret-value",
    }
    target = resolve(FULL[tier], tier, runtime_env=production)
    env = target.runtime_env(tmp_path)
    assert not set(production.values()) & set(env.values())
    assert env["SOAR_API_KEY_SECRET"] in (SECRET, WRITE_SECRET)
