"""Apply a string redactor to structured data (08 §27).

The one implementation behind the pipeline's output redaction (``tools/registry``,
step 12) and the audit log (``security/audit``). What counts as a credential is the
redactor's business (``logging.redact`` in the running server); this module only
decides *where* it is applied: to every string of a JSON-native value, keys included,
each as the text it is.

A serialised document is never redacted as one string. There a pattern can run past
the end of a value into the JSON around it, which removes text that is no credential
and can leave a document that no longer parses, and JSON escaping can hide a
credential that holds a quote or a backslash.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class KeyCollisionError(ValueError):
    """Two keys of one mapping are equal after redaction.

    The message never names the keys: one of them held something the redactor removed.
    """


def _text(redact: Callable[[str], str], text: str) -> str:
    safe = redact(text)
    if not isinstance(safe, str):
        raise TypeError("the redactor did not return a string")
    return safe


def redact_strings(value: Any, redact: Callable[[str], str], *, unique_keys: bool = False) -> Any:
    """Return ``value`` with every string, dictionary keys included, passed through ``redact``.

    ``value`` is JSON-native (``dict``, ``list``, ``str``, numbers, booleans, ``None``); the
    structure and every non-string scalar are kept as they are, and a new value is built.

    Two keys of one dictionary can be equal once redacted. With ``unique_keys`` that raises
    :class:`KeyCollisionError`, for a caller that must not lose a value; without it the later
    key wins, as in any dictionary built from repeated keys.
    """
    if isinstance(value, str):
        return _text(redact, value)
    if isinstance(value, list):
        return [redact_strings(item, redact, unique_keys=unique_keys) for item in value]
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            safe = _text(redact, key) if isinstance(key, str) else key
            if unique_keys and safe in out:
                raise KeyCollisionError("two keys are equal after redaction")
            out[safe] = redact_strings(item, redact, unique_keys=unique_keys)
        return out
    return value
