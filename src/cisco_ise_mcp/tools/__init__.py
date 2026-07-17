"""MCP tool registration.

Deps bundles everything a tool needs. `run()` centralizes gating, auth resolution,
auditing, and error shaping so individual tools stay tiny.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

from ..audit import audit
from ..auth.base import AuthContext, AuthProvider
from ..config import Config
from ..ise.ers import ErsApi
from ..ise.mnt import MntApi
from .. import responses, validation

_log = logging.getLogger("cisco_ise_mcp.tools")


def mcp_session_id(header_name: str) -> str | None:
    """Read the MCP session id from the CURRENT request's headers.

    Uses the SDK request context (set in the tool's own task) rather than an ASGI
    contextvar, because FastMCP's streamable-HTTP runs tool calls in a different
    task than the ASGI request. Falls back to `Authorization: Bearer`. Returns None
    off an HTTP transport (e.g. stdio). mcp is imported lazily so this module stays
    importable without runtime deps."""
    try:
        from mcp.server.lowlevel.server import request_ctx

        rc = request_ctx.get()
    except (LookupError, ImportError):
        return None
    headers = getattr(getattr(rc, "request", None), "headers", None)
    if not headers:
        return None
    sid = headers.get(header_name) or headers.get(header_name.lower())
    if not sid:
        authz = headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            sid = authz[7:].strip()
    return sid


@dataclass
class Deps:
    cfg: Config
    ers: ErsApi
    mnt: MntApi
    provider: AuthProvider

    def session_id(self) -> str | None:
        return mcp_session_id(self.cfg.session_header)

    def session_valid(self, sid: str | None) -> bool:
        """True if `sid` maps to a live session (passthrough). Used by the HTTP
        auth gate to decide whether to 401."""
        fn = getattr(self.provider, "session_valid", None)
        return bool(fn) and fn(sid)

    async def resolve_auth(self) -> AuthContext:
        return await self.provider.resolve(session_id=self.session_id())


async def run(
    deps: Deps,
    name: str,
    params: dict,
    fn: Callable[[AuthContext], Awaitable[dict]],
    *,
    write: bool = False,
) -> dict:
    actor = "unknown"
    try:
        validation.assert_tool_enabled(deps.cfg, name)
        if write:
            validation.assert_write_allowed(deps.cfg, name)
        auth = await deps.resolve_auth()
        actor = auth.username
        result = await fn(auth)
        audit(enabled=deps.cfg.audit_log_enabled, actor=actor, tool=name, params=params, status="ok")
        return result
    except Exception as exc:  # noqa: BLE001 - shape every error for the client
        audit(
            enabled=deps.cfg.audit_log_enabled,
            actor=actor,
            tool=name,
            params=params,
            status="error",
            detail=type(exc).__name__,
        )
        _log.warning("tool_error", extra={"tool": name, "error": type(exc).__name__})
        return responses.error(exc)


def register_all(mcp, deps: Deps) -> None:
    from . import (
        endpoint,
        health,
        identity,
        network_device,
        policy,
        session,
        sgt,
        write_endpoint,
    )

    for mod in (health, endpoint, session, policy, network_device, identity, sgt, write_endpoint):
        mod.register(mcp, deps)
