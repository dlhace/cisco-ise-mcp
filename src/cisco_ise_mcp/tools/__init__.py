"""MCP tool registration.

Deps bundles everything a tool needs. `run()` centralizes gating, auth resolution,
auditing, and error shaping so individual tools stay tiny.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

from ..audit import audit
from ..auth.base import AuthContext, AuthProvider, current_session_id
from ..config import Config
from ..ise.ers import ErsApi
from ..ise.mnt import MntApi
from .. import responses, validation

_log = logging.getLogger("cisco_ise_mcp.tools")


@dataclass
class Deps:
    cfg: Config
    ers: ErsApi
    mnt: MntApi
    provider: AuthProvider

    async def resolve_auth(self) -> AuthContext:
        return await self.provider.resolve(session_id=current_session_id.get())


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
