"""Health + auth/session tools."""
from __future__ import annotations

from .. import responses
from ..auth.passthrough import PassthroughProvider
from . import Deps, run


def register(mcp, deps: Deps) -> None:
    cfg = deps.cfg

    @mcp.tool()
    async def ise_health_check() -> dict:
        """Liveness + effective (non-secret) configuration summary."""
        return responses.ok(
            {
                "status": "ok",
                "ise_base_url": cfg.ise_base_url,
                "ise_version": cfg.ise_version,
                "auth_mode": cfg.auth_mode,
                "mcp_mode": cfg.mcp_mode,
                "readonly": cfg.is_readonly,
            }
        )

    @mcp.tool()
    async def ise_auth_status() -> dict:
        """Report the current caller's resolved ISE identity (no secrets)."""
        async def _fn(auth):
            return responses.ok({"authenticated": True, "username": auth.username, "mode": auth.mode})

        return await run(deps, "ise_auth_status", {}, _fn)

    @mcp.tool()
    async def ise_login(username: str, password: str) -> dict:
        """Validate ISE credentials and return an MCP session id (passthrough mode).

        The password is used only to authenticate against ISE and is never stored on
        disk, logged, or returned.
        """
        if not isinstance(deps.provider, PassthroughProvider):
            return responses.error(
                RuntimeError("ise_login is only available when ISE_AUTH_MODE=passthrough")
            )
        try:
            sess = await deps.provider.login(username, password)
        except Exception as exc:  # noqa: BLE001
            return responses.error(exc)
        return responses.ok(
            {"session_id": sess.session_id, "username": sess.username},
            note=f"Present this id in the {cfg.session_header} header (or Authorization: Bearer).",
        )

    @mcp.tool()
    async def ise_validate_session() -> dict:
        """Check whether the presented MCP session id is still valid."""
        async def _fn(auth):
            return responses.ok({"valid": True, "username": auth.username, "mode": auth.mode})

        return await run(deps, "ise_validate_session", {}, _fn)

    @mcp.tool()
    async def ise_logout() -> dict:
        """Invalidate the current MCP session (passthrough mode)."""
        if not isinstance(deps.provider, PassthroughProvider):
            return responses.ok({"logged_out": False, "reason": "not in passthrough mode"})
        deleted = deps.provider.logout(deps.session_id())
        return responses.ok({"logged_out": bool(deleted)})

    @mcp.tool()
    async def ise_whoami() -> dict:
        """Return caller identity + effective permissions view."""
        async def _fn(auth):
            return responses.ok(
                {
                    "username": auth.username,
                    "mode": auth.mode,
                    "mcp_mode": cfg.mcp_mode,
                    "can_write": not cfg.is_readonly,
                }
            )

        return await run(deps, "ise_whoami", {}, _fn)
