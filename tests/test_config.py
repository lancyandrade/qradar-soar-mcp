"""P1-02: typed settings with granular capability flags; deny by default."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

from qradar_soar_mcp.config import (
    CAPABILITY_FLAGS,
    LEGACY_WRITES_TARGETS,
    TRUE_VALUES,
    ConfigError,
    Settings,
    is_loopback_host,
    load_settings,
)
from tests.conftest import SENTINEL, connection_env

ROOT = Path(__file__).parent.parent
GARBAGE = ["", "maybe", "TRUE ", None]  # the P1-02 AC list; None = absent
BOOL_FLAGS = (
    *CAPABILITY_FLAGS,
    "SOAR_ALLOW_WRITES",
    "SOAR_HTTP_ACKNOWLEDGE_EXPOSURE",
    "SOAR_LAB_MODE",
)


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "action_policy.yaml"
    p.write_text("version: 1\n", encoding="utf-8")
    return p


def _load(env: dict[str, str], policy_file: Path | None = None) -> Settings:
    if policy_file is not None and env.get("SOAR_ALLOW_ACTIONS", "").lower() in TRUE_VALUES:
        env = {**env, "SOAR_ACTION_POLICY_FILE": str(policy_file)}
    return Settings.load(env)


# ------------------------------------------------------------ deny by default


def test_empty_environment_enables_nothing():
    s = Settings.load({})
    assert s.enabled_capabilities() == []
    assert s.allow_writes is False and s.lab_mode is False
    assert s.mcp_transport == "stdio" and s.approval_mode == "out_of_band"
    assert s.verify_ssl is True and s.ca_bundle is None and s.tls_trust == "python_default"
    assert s.require_action_confirmation is True and s.audit_required is True
    assert s.warnings == ()
    assert not s.connection_ready


@pytest.mark.parametrize("flag", BOOL_FLAGS)
@pytest.mark.parametrize("raw", GARBAGE)
def test_absent_empty_and_garbage_resolve_to_false(flag: str, raw: str | None, policy_file):
    env = {} if raw is None else {flag: raw}
    s = _load(env, policy_file)
    assert s.capability_enabled(flag) is False
    assert not any(s.capability_enabled(f) for f in CAPABILITY_FLAGS)
    if raw is None:
        assert s.warnings == ()
    else:
        assert len(s.warnings) == 1 and flag in s.warnings[0]


@pytest.mark.parametrize("flag", CAPABILITY_FLAGS)
@pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "on", "On"])
def test_recognised_true_values_enable_exactly_that_flag(flag: str, raw: str, policy_file):
    s = _load({flag: raw}, policy_file)
    assert s.enabled_capabilities() == [flag]
    assert s.warnings == ()


@pytest.mark.parametrize("flag", CAPABILITY_FLAGS)
@pytest.mark.parametrize("raw", ["false", "0", "no", "off", "OFF"])
def test_recognised_false_values_do_not_warn(flag: str, raw: str):
    s = Settings.load({flag: raw})
    assert s.enabled_capabilities() == [] and s.warnings == ()


@hyp_settings(max_examples=200, deadline=None)
@given(
    st.text(min_size=0, max_size=12).filter(
        lambda t: "\x00" not in t and t.lower() not in TRUE_VALUES
    )
)
def test_property_no_other_string_enables_comments(text: str):
    s = Settings.load({"SOAR_ALLOW_COMMENTS": text})
    assert s.allow_comments is False


@pytest.mark.parametrize(
    ("flag", "raw"),
    [
        ("SOAR_REQUIRE_ACTION_CONFIRMATION", "nah"),
        ("SOAR_REQUIRE_PLAYBOOK_CONFIRMATION", ""),
        ("SOAR_AUDIT_REQUIRED", "TRUE "),
    ],
)
def test_safety_switches_resolve_to_true_on_garbage(flag: str, raw: str):
    s = Settings.load({flag: raw})
    attr = flag.removeprefix("SOAR_").lower()
    assert getattr(s, attr) is True
    assert flag in s.warnings[0]


def test_safety_switches_can_be_disabled_explicitly():
    s = Settings.load({"SOAR_REQUIRE_ACTION_CONFIRMATION": "false", "SOAR_AUDIT_REQUIRED": "0"})
    assert s.require_action_confirmation is False and s.audit_required is False


# ---------------------------------------------------------------- legacy flag


def test_legacy_writes_maps_to_tier_one_and_two_and_drops_actions(caplog):
    with caplog.at_level(logging.WARNING, logger="qradar_soar_mcp.config"):
        s = Settings.load({"SOAR_ALLOW_WRITES": "true"})
    assert s.enabled_capabilities() == list(LEGACY_WRITES_TARGETS)
    assert s.allow_actions is False
    assert len(s.warnings) == 1
    assert "deprecated" in s.warnings[0] and "SOAR_ALLOW_ACTIONS" in s.warnings[0]
    assert any("SOAR_ALLOW_ACTIONS" in r.getMessage() for r in caplog.records)


def test_legacy_writes_false_or_garbage_maps_nothing():
    assert Settings.load({"SOAR_ALLOW_WRITES": "false"}).enabled_capabilities() == []
    s = Settings.load({"SOAR_ALLOW_WRITES": "TRUE "})
    assert s.enabled_capabilities() == [] and "SOAR_ALLOW_WRITES" in s.warnings[0]


# ------------------------------------------------------------------ secrets


def test_repr_str_and_dumps_never_contain_the_secret():
    s = Settings.load({"SOAR_API_KEY_SECRET": SENTINEL, "SOAR_HTTP_AUTH_TOKEN": SENTINEL})
    renderings = [
        repr(s),
        str(s),
        repr(s.model_dump()),
        json.dumps(s.model_dump(mode="json")),
        json.dumps(s.safe_dump()),
        repr(s.api_key_secret),
        str(s.http_auth_token),
    ]
    for text in renderings:
        assert SENTINEL not in text
    assert s.secret_values() == [SENTINEL, SENTINEL]
    assert s.safe_dump()["api_key_secret"] == "***"
    assert Settings.load({}).safe_dump()["api_key_secret"] == ""


def test_startup_self_test_passes_and_detects_leaks(monkeypatch):
    s = Settings.load({"SOAR_API_KEY_SECRET": SENTINEL, "SOAR_HTTP_AUTH_TOKEN": SENTINEL})
    s.assert_secrets_hidden()
    # Simulate a future regression that renders the secret somewhere.
    monkeypatch.setattr(Settings, "startup_summary", lambda self: f"caps {SENTINEL}")
    with pytest.raises(ConfigError, match="self-test failed") as info:
        s.assert_secrets_hidden()
    assert SENTINEL not in str(info.value)


def test_config_error_never_echoes_the_secret():
    with pytest.raises(ConfigError) as info:
        Settings.load({"SOAR_BASE_URL": "ftp://x", "SOAR_API_KEY_SECRET": SENTINEL})
    assert SENTINEL not in str(info.value)
    assert "SOAR_BASE_URL" in str(info.value)


# ---------------------------------------------------------- startup summary


def test_startup_summary_lists_exactly_the_enabled_capabilities(policy_file):
    s = _load({"SOAR_ALLOW_COMMENTS": "true", "SOAR_ALLOW_TASK_WRITES": "yes"}, policy_file)
    line = s.startup_summary()
    assert "\n" not in line
    listed = re.search(r"capabilities enabled: (.*?);", line).group(1)
    assert listed == "SOAR_ALLOW_COMMENTS, SOAR_ALLOW_TASK_WRITES"
    assert "approval_mode=out_of_band" in line and "transport=stdio" in line
    assert "none (read-only)" in Settings.load({}).startup_summary()


# ------------------------------------------------------- cross-field rules


def test_actions_requires_policy_file_that_exists(tmp_path: Path):
    with pytest.raises(ConfigError, match="SOAR_ACTION_POLICY_FILE"):
        Settings.load({"SOAR_ALLOW_ACTIONS": "true"})
    with pytest.raises(ConfigError, match="does not exist"):
        Settings.load(
            {"SOAR_ALLOW_ACTIONS": "true", "SOAR_ACTION_POLICY_FILE": str(tmp_path / "nope.yaml")}
        )


@pytest.mark.parametrize("mode", ["in_band", "disabled"])
def test_non_out_of_band_approval_with_actions_requires_lab_mode(mode: str, policy_file):
    env = {"SOAR_ALLOW_ACTIONS": "true", "SOAR_APPROVAL_MODE": mode}
    with pytest.raises(ConfigError, match="SOAR_LAB_MODE"):
        _load(env, policy_file)
    s = _load({**env, "SOAR_LAB_MODE": "true"}, policy_file)
    assert s.approval_mode == mode and s.lab_mode is True


def test_in_band_without_actions_is_allowed_without_lab_mode():
    assert Settings.load({"SOAR_APPROVAL_MODE": "in_band"}).approval_mode == "in_band"


@pytest.mark.parametrize("raw", ["true", "1", "yes", "ON"])
def test_script_writes_true_refuses_to_start(raw: str):
    with pytest.raises(ConfigError, match="non-goal"):
        Settings.load({"SOAR_ALLOW_SCRIPT_WRITES": raw})


def test_script_writes_garbage_is_false_not_fatal():
    s = Settings.load({"SOAR_ALLOW_SCRIPT_WRITES": "definitely"})
    assert s.allow_script_writes is False and "SOAR_ALLOW_SCRIPT_WRITES" in s.warnings[0]


# ------------------------------------------------------------------- TLS


def test_verify_ssl_bool_or_path(tmp_path: Path):
    """The Phase-1 forms still parse; the trust model on top is in test_tls.py (08 §22)."""
    assert Settings.load({"SOAR_VERIFY_SSL": "true"}).verify_ssl is True
    # ``false`` still parses, but is no longer accepted on its own: it is lab-only.
    with pytest.raises(ConfigError, match="SOAR_LAB_MODE=true"):
        Settings.load({"SOAR_VERIFY_SSL": "false"})
    lab = Settings.load({"SOAR_VERIFY_SSL": "false", "SOAR_LAB_MODE": "true"})
    assert lab.verify_ssl is False and lab.tls_verify is False
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    legacy = Settings.load({"SOAR_VERIFY_SSL": str(bundle)})
    assert legacy.verify_ssl == bundle and legacy.tls_verify is True
    assert legacy.tls_ca_bundle == bundle and any("deprecated" in w for w in legacy.warnings)
    with pytest.raises(ConfigError, match="SOAR_VERIFY_SSL"):
        Settings.load({"SOAR_VERIFY_SSL": str(tmp_path / "missing.pem")})
    with pytest.raises(ConfigError, match="SOAR_VERIFY_SSL"):
        Settings.load({"SOAR_VERIFY_SSL": "nope"})
    with pytest.raises(ConfigError, match="SOAR_VERIFY_SSL"):
        Settings.load({"SOAR_VERIFY_SSL": ""})


# ---------------------------------------------------------------- numbers


@pytest.mark.parametrize(
    ("name", "raw", "attr", "expected"),
    [
        ("SOAR_TIMEOUT", "abc", "timeout", 30.0),
        ("SOAR_TIMEOUT", "0", "timeout", 30.0),
        ("SOAR_MAX_RESULTS", "1000", "max_results", 500),
        ("SOAR_MAX_RESULTS", "x", "max_results", 50),
        ("SOAR_MAX_MUTATIONS_PER_CALL", "5", "max_mutations_per_call", 1),
        ("SOAR_MAX_TIER2_PER_HOUR", "-1", "max_tier2_per_hour", 25),
        ("SOAR_MAX_TIER3_PER_HOUR", "lots", "max_tier3_per_hour", 5),
        ("SOAR_APPROVAL_TTL_SECONDS", "1", "approval_ttl_seconds", 900),
        ("SOAR_CATALOG_TTL_SECONDS", "-1", "catalog_ttl_seconds", 300),
        ("SOAR_CATALOG_TTL_SECONDS", "soon", "catalog_ttl_seconds", 300),
        ("SOAR_CATALOG_TTL_SECONDS", "1.5", "catalog_ttl_seconds", 300),
        ("SOAR_CATALOG_TTL_SECONDS", "999999", "catalog_ttl_seconds", 86_400),
        ("SOAR_MCP_PORT", "70000", "mcp_port", 65535),
        ("SOAR_ORG_ID", "two", "org_id", None),
        ("SOAR_ORG_ID", "0", "org_id", None),
    ],
)
def test_bad_numbers_fall_back_with_a_warning(name, raw, attr, expected):
    s = Settings.load({name: raw})
    assert getattr(s, attr) == expected
    assert any(name in w for w in s.warnings)


def test_good_numbers_parse():
    s = Settings.load(
        {"SOAR_MAX_TIER3_PER_HOUR": "0", "SOAR_ORG_ID": "201", "SOAR_TIMEOUT": "12.5"}
    )
    assert s.max_tier3_per_hour == 0 and s.org_id == 201 and s.timeout == 12.5
    assert s.warnings == ()


# ------------------------------------------------------------------ enums


def test_transport_alias_and_garbage():
    assert Settings.load({"SOAR_MCP_TRANSPORT": "http"}).mcp_transport == "streamable-http"
    assert (
        Settings.load({"SOAR_MCP_TRANSPORT": "streamable-http"}).mcp_transport == "streamable-http"
    )
    s = Settings.load({"SOAR_MCP_TRANSPORT": "websocket"})
    assert s.mcp_transport == "stdio" and "SOAR_MCP_TRANSPORT" in s.warnings[0]


def test_approval_mode_and_log_level_garbage():
    s = Settings.load({"SOAR_APPROVAL_MODE": "maybe", "SOAR_LOG_LEVEL": "loud"})
    assert s.approval_mode == "out_of_band" and s.log_level == "INFO"
    assert len(s.warnings) == 2
    assert Settings.load({"SOAR_LOG_LEVEL": "debug"}).log_level == "DEBUG"


# ---------------------------------------------------------------- catalog


def test_the_catalog_defaults_are_collections_and_300_seconds():
    """P2-01 (08 §25): P2-00 reversed 05 §2.1, so ``collections`` is the default source."""
    s = Settings.load({})
    assert s.catalog_source == "collections" and s.catalog_ttl_seconds == 300
    assert s.warnings == ()
    assert Settings.model_fields["catalog_source"].default == "collections"
    assert Settings.model_fields["catalog_ttl_seconds"].default == 300


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("collections", "collections"),
        ("COLLECTIONS", "collections"),
        (" collections ", "collections"),
        ("export", "export"),
        ("Export", "export"),
    ],
)
def test_an_explicit_catalog_source_is_honoured_without_a_warning(raw: str, expected: str):
    s = Settings.load({"SOAR_CATALOG_SOURCE": raw})
    assert s.catalog_source == expected and s.warnings == ()


@pytest.mark.parametrize("raw", ["", "exports", "both", "export,collections", "auto", "0"])
def test_an_invalid_catalog_source_fails_safe_to_collections_never_to_export(raw: str):
    s = Settings.load({"SOAR_CATALOG_SOURCE": raw})
    assert s.catalog_source == "collections"
    assert len(s.warnings) == 1 and "SOAR_CATALOG_SOURCE" in s.warnings[0]
    assert "using collections" in s.warnings[0]


@pytest.mark.parametrize(("raw", "expected"), [("0", 0), ("1", 1), ("60", 60), ("86400", 86_400)])
def test_a_valid_catalog_ttl_parses(raw: str, expected: int):
    s = Settings.load({"SOAR_CATALOG_TTL_SECONDS": raw})
    assert s.catalog_ttl_seconds == expected and s.warnings == ()


def test_an_empty_catalog_ttl_is_the_default():
    assert Settings.load({"SOAR_CATALOG_TTL_SECONDS": ""}).catalog_ttl_seconds == 300


def test_the_catalog_settings_are_frozen_and_carry_no_secret():
    s = Settings.load({"SOAR_CATALOG_SOURCE": "export"})
    with pytest.raises(Exception, match="frozen"):
        s.catalog_source = "collections"  # type: ignore[misc]
    assert s.safe_dump()["catalog_source"] == "export"
    assert not [name for name in CAPABILITY_FLAGS if "CATALOG" in name]


# --------------------------------------------------------------- base URL


@pytest.mark.parametrize(
    "url",
    [
        "http://soar.example.internal",
        "soar.example.internal",
        "ftp://x",
        "https://u:p@soar.example.internal",
        "https://soar.example.internal/?a=1",
    ],
)
def test_base_url_rules(url: str):
    with pytest.raises(ConfigError, match="SOAR_BASE_URL"):
        Settings.load({"SOAR_BASE_URL": url})


def test_base_url_https_and_loopback_http_ok():
    assert (
        Settings.load({"SOAR_BASE_URL": "https://soar.example.internal/"}).base_url_clean
        == "https://soar.example.internal"
    )
    assert (
        Settings.load({"SOAR_BASE_URL": "http://127.0.0.1:8080"}).base_url_clean
        == "http://127.0.0.1:8080"
    )


def test_connection_ready_needs_all_four():
    assert Settings.load(connection_env()).connection_ready
    for key in ("SOAR_BASE_URL", "SOAR_ORG_ID", "SOAR_API_KEY_ID", "SOAR_API_KEY_SECRET"):
        assert not Settings.load({**connection_env(), key: ""}).connection_ready


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("::", False),
        ("198.51.100.7", False),
        ("example.com", False),
        ("", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool):
    assert is_loopback_host(host) is expected


# ------------------------------------------------------------- environment


def test_load_reads_the_process_environment_by_default(monkeypatch):
    monkeypatch.setenv("SOAR_ALLOW_COMMENTS", "true")
    assert Settings.load().allow_comments is True
    assert load_settings().allow_comments is True
    assert load_settings({}).allow_comments is False


def test_settings_are_frozen():
    s = Settings.load({})
    with pytest.raises(Exception, match="frozen"):
        s.allow_comments = True  # type: ignore[misc]


# ------------------------------------------------------------ .env.example


def _keys(text: str) -> set[str]:
    return set(re.findall(r"^([A-Z_]+)=", text, flags=re.MULTILINE))


def test_env_example_is_the_baseline_with_only_the_documented_changes():
    """The frozen design copy, plus exactly the changes 08 records: the Ed25519 rename
    (§5) and ``SOAR_CA_BUNDLE`` (§22)."""
    ours = _keys((ROOT / ".env.example").read_text(encoding="utf-8"))
    baseline = _keys((ROOT / "docs" / "design" / "env.example").read_text(encoding="utf-8"))
    expected = (baseline - {"SOAR_APPROVAL_HMAC_KEY_FILE"}) | {
        "SOAR_APPROVAL_PUBLIC_KEY_FILE",
        "SOAR_CA_BUNDLE",
    }
    assert ours == expected
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    # Secure TLS defaults: verification on, no bundle, and no insecure value anywhere.
    assert "SOAR_VERIFY_SSL=true" in text and re.search(r"^SOAR_CA_BUNDLE=$", text, flags=re.M)
    assert re.search(r"^SOAR_VERIFY_SSL=false", text, flags=re.M) is None
    assert re.search(r"^SOAR_LAB_MODE=false$", text, flags=re.M)
    assert re.search(r"^SOAR_ALLOW_[A-Z_]+=true", text, flags=re.MULTILINE) is None or (
        set(re.findall(r"^(SOAR_ALLOW_[A-Z_]+)=true", text, flags=re.MULTILINE))
        == {"SOAR_ALLOW_PLAYBOOK_DRAFT"}
    )


def test_every_env_example_variable_is_a_known_setting():
    ours = _keys((ROOT / ".env.example").read_text(encoding="utf-8"))
    fields = set(Settings.model_fields)
    unknown = {k for k in ours if k.removeprefix("SOAR_").lower() not in fields}
    assert unknown == set(), (
        f"variables in .env.example that Settings does not read: {sorted(unknown)}"
    )


def test_env_example_loads_as_a_safe_default(tmp_path: Path):
    """The example file, with placeholders, must load and enable only DRAFT (local, safe)."""
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    env = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Z_]+)=(.*?)(\s+#.*)?$", line)
        if m:
            env[m.group(1)] = m.group(2).strip()
    # Paths in the example point at /etc and /var; substitute so validation can pass offline.
    env["SOAR_ACTION_POLICY_FILE"] = ""
    s = Settings.load(env)
    assert s.enabled_capabilities() == ["SOAR_ALLOW_PLAYBOOK_DRAFT"]
    assert s.approval_mode == "out_of_band" and s.audit_required is True
