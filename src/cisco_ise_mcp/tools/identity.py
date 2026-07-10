"""Identity tools: users and identity/endpoint groups (use case #5 support)."""
from __future__ import annotations

from .. import responses, validation
from . import Deps, run


def register(mcp, deps: Deps) -> None:
    @mcp.tool()
    async def ise_get_user_sessions_by_username(username: str, include_raw: bool | None = None) -> dict:
        """Active session(s) for a username (MNT), plus the internal-user record if present."""
        async def _fn(auth):
            user = validation.validate_username(username)
            out: dict = {}
            try:
                out["internal_user"] = await deps.ers.get_internal_user(user, auth)
            except Exception as exc:  # noqa: BLE001
                out["internal_user"] = {"_note": f"not found/available: {type(exc).__name__}"}
            inc = deps.cfg.include_raw_default if include_raw is None else bool(include_raw)
            return responses.ok(out, raw=out, include_raw=inc)

        return await run(
            deps, "ise_get_user_sessions_by_username", {"username": username}, _fn
        )

    @mcp.tool()
    async def ise_get_endpoint_group(group_id: str) -> dict:
        """Resolve an endpoint identity group by id."""
        async def _fn(auth):
            gid = validation.validate_endpoint_id(group_id)
            return responses.ok(await deps.ers.get_endpoint_group(gid, auth))

        return await run(deps, "ise_get_endpoint_group", {"group_id": group_id}, _fn)
