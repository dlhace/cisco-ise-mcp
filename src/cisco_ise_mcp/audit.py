"""Audit logging of tool invocations. Redacts params; never logs credentials."""
from __future__ import annotations

import logging

from .redaction import redact

_log = logging.getLogger("cisco_ise_mcp.audit")


def audit(
    *,
    enabled: bool,
    actor: str,
    tool: str,
    params: dict | None = None,
    status: str,
    detail: str | None = None,
) -> None:
    if not enabled:
        return
    _log.info(
        "audit",
        extra={
            "event": "tool_call",
            "actor": actor,
            "tool": tool,
            "params": redact(params or {}),
            "status": status,
            "detail": detail,
        },
    )
