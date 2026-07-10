"""Endpoint write tools. Gated by ISE_MCP_MODE=readwrite (and, for delete, by
ISE_ENABLE_DANGEROUS_TOOLS). ISE also enforces the caller's own permissions.

Registered unconditionally so a readonly server returns a clear write_not_allowed
error rather than an opaque "unknown tool"."""
from __future__ import annotations

from .. import responses, validation
from . import Deps, run


def register(mcp, deps: Deps) -> None:
    @mcp.tool()
    async def ise_create_endpoint(
        mac: str, group_id: str | None = None, description: str = ""
    ) -> dict:
        """Create an endpoint. Requires readwrite mode."""
        async def _fn(auth):
            m = validation.normalize_mac(mac)
            body = {"mac": m, "description": description}
            if group_id:
                body["groupId"] = validation.validate_endpoint_id(group_id)
                body["staticGroupAssignment"] = True
            return responses.ok(await deps.ers.create_endpoint(body, auth))

        return await run(deps, "ise_create_endpoint", {"mac": mac}, _fn, write=True)

    @mcp.tool()
    async def ise_assign_endpoint_group(endpoint_id: str, group_id: str) -> dict:
        """Statically assign an endpoint to an identity group. Requires readwrite mode."""
        async def _fn(auth):
            eid = validation.validate_endpoint_id(endpoint_id)
            gid = validation.validate_endpoint_id(group_id)
            body = {"id": eid, "groupId": gid, "staticGroupAssignment": True}
            return responses.ok(await deps.ers.update_endpoint(eid, body, auth))

        return await run(
            deps, "ise_assign_endpoint_group",
            {"endpoint_id": endpoint_id, "group_id": group_id}, _fn, write=True,
        )

    @mcp.tool()
    async def ise_delete_endpoint(endpoint_id: str) -> dict:
        """Delete an endpoint. Requires readwrite mode AND ISE_ENABLE_DANGEROUS_TOOLS=true."""
        async def _fn(auth):
            eid = validation.validate_endpoint_id(endpoint_id)
            return responses.ok(await deps.ers.delete_endpoint(eid, auth))

        return await run(deps, "ise_delete_endpoint", {"endpoint_id": endpoint_id}, _fn, write=True)
