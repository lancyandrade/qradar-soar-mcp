"""The structural redaction primitive shared by tool output and the audit log (08 §27)."""

from __future__ import annotations

import json

import pytest

from qradar_soar_mcp.redaction import KeyCollisionError, redact_strings
from tests.conftest import SENTINEL


def _redact(text: str) -> str:
    return text.replace(SENTINEL, "[REDACTED]")


def test_every_string_and_key_is_redacted_and_the_structure_is_kept():
    value = {
        "note": f"k {SENTINEL}",
        f"key {SENTINEL}": {"inner": [f"{SENTINEL}", {"deep": f"x{SENTINEL}y"}]},
        "scalars": [1, 2.5, True, False, None],
        "empty": {},
    }
    before = json.dumps(value)
    out = redact_strings(value, _redact)
    assert out == {
        "note": "k [REDACTED]",
        "key [REDACTED]": {"inner": ["[REDACTED]", {"deep": "x[REDACTED]y"}]},
        "scalars": [1, 2.5, True, False, None],
        "empty": {},
    }
    assert [type(v) for v in out["scalars"]] == [int, float, bool, bool, type(None)]
    assert json.dumps(value) == before  # a new value is built; the input is untouched
    assert redact_strings(out, _redact) == out


@pytest.mark.parametrize("scalar", ["plain", 7, 1.5, True, None])
def test_a_bare_scalar_is_returned_redacted_or_unchanged(scalar):
    assert redact_strings(scalar, _redact) == scalar
    assert redact_strings(SENTINEL, _redact) == "[REDACTED]"


def test_a_key_that_is_no_string_is_left_alone():
    assert redact_strings({1: SENTINEL}, _redact) == {1: "[REDACTED]"}


def test_colliding_keys_the_later_wins_unless_keys_must_stay_unique():
    value = {f"k {SENTINEL}": 1, "k [REDACTED]": 2, "nested": [{f"{SENTINEL}": 1, "[REDACTED]": 2}]}
    assert redact_strings(value, _redact) == {"k [REDACTED]": 2, "nested": [{"[REDACTED]": 2}]}
    for bad in (value, {"nested": value["nested"]}):
        with pytest.raises(KeyCollisionError) as info:
            redact_strings(bad, _redact, unique_keys=True)
        assert SENTINEL not in str(info.value) and "REDACTED" not in str(info.value)
    unique = {f"k {SENTINEL}": 1, "other": 2}
    assert redact_strings(unique, _redact, unique_keys=True) == {"k [REDACTED]": 1, "other": 2}


def test_a_redactor_that_returns_no_string_is_an_error_not_a_broken_structure():
    with pytest.raises(TypeError) as info:
        redact_strings({"a": SENTINEL}, lambda text: None)  # type: ignore[arg-type, return-value]
    assert SENTINEL not in str(info.value)
    with pytest.raises(TypeError):
        redact_strings({SENTINEL: 1}, lambda text: ["unhashable"])  # type: ignore[arg-type, return-value]
