"""Structured logging to stderr with a redaction filter (P1-09; 02 §7).

In stdio transport stdout *is* the MCP channel; nothing here writes to it.
The filter rewrites every record before any handler formats it: the
interpolated message, the traceback and stack info have each configured
secret, every ``Basic <b64>`` credential and every ``Authorization`` value
replaced by ``[REDACTED]``. It sits on the handler, so it sees records from
every logger in the process, including third-party libraries.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Iterable
from datetime import UTC, datetime

REDACTED = "[REDACTED]"
_MIN_SECRET_LENGTH = 4  # anything shorter would redact ordinary text
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Basic\s+[A-Za-z0-9+/=_-]{8,}"), f"Basic {REDACTED}"),
    (re.compile(r"(?i)(authorization\s*[:=]\s*)['\"]?\S+"), rf"\1{REDACTED}"),
)


class RedactingFilter(logging.Filter):
    """Replace configured secrets and credential patterns in every record."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._secrets: tuple[str, ...] = ()
        self.set_secrets(secrets)

    def set_secrets(self, secrets: Iterable[str]) -> None:
        # Longest first so a secret that is a prefix of another is still fully hidden.
        self._secrets = tuple(
            sorted(
                {s for s in secrets if s and len(s) >= _MIN_SECRET_LENGTH}, key=len, reverse=True
            )
        )

    def add_secrets(self, secrets: Iterable[str]) -> None:
        self.set_secrets((*self._secrets, *secrets))

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, REDACTED)
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # a broken format string must not crash logging
            message = str(record.msg)
        record.msg = self.redact(message)
        record.args = ()
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = self.redact(formatted)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self.redact(record.exc_text)
        if record.stack_info:
            record.stack_info = self.redact(record.stack_info)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, msg (+ exc / stack)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_text:
            payload["exc"] = record.exc_text
        if record.stack_info:
            payload["stack"] = record.stack_info
        return json.dumps(payload, ensure_ascii=False, default=str)


_FILTER = RedactingFilter()
_HANDLER: logging.Handler | None = None


def configure_logging(level: str = "INFO", secrets: Iterable[str] = ()) -> logging.Handler:
    """Install the single stderr handler on the root logger.

    Safe to call more than once: the handler is replaced, not duplicated. Call
    this *before* constructing ``MCPServer`` so the SDK's ``logging.basicConfig``
    is a no-op (the root already has a handler).
    """
    global _HANDLER
    root = logging.getLogger()
    if _HANDLER is not None:
        root.removeHandler(_HANDLER)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    _FILTER.set_secrets(secrets)
    handler.addFilter(_FILTER)
    root.addHandler(handler)
    root.setLevel(level.upper())
    # Never let the lastResort handler (also stderr, but unfiltered) see records.
    logging.lastResort = None
    _HANDLER = handler
    return handler


def add_secrets(secrets: Iterable[str]) -> None:
    """Extend the redaction set (for secrets learned after startup)."""
    _FILTER.add_secrets(secrets)


def redact(text: str) -> str:
    """Redact configured secrets and credential patterns from arbitrary text."""
    return _FILTER.redact(text)
