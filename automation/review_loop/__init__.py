"""Codex review -> Claude Code fix -> CI -> Codex re-review automation.

This package runs only inside GitHub Actions jobs that check out the default
branch. It is stdlib-only on purpose: the privileged jobs install nothing.
It is not part of the ``qradar_soar_mcp`` wheel and never talks to SOAR.
"""

from __future__ import annotations
