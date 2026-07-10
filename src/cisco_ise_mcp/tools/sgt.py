"""TrustSec tools: Security Group Tags (SGT), SGACLs, authorization profiles."""
from __future__ import annotations

from .. import responses, validation
from . import Deps, run


def register(mcp, deps: Deps) -> None:
    def _list_tool(name, fetch, wrapper):
        async def tool(page: int = 1, page_size: int | None = None,
                       include_raw: bool | None = None) -> dict:
            async def _fn(auth):
                size = validation.clamp_page_size(deps.cfg, page_size)
                raw = await fetch(auth, page=page, size=size)
                res = raw.get("SearchResult", {}) if isinstance(raw, dict) else {}
                items = [
                    {"id": r.get("id"), "name": r.get("name")}
                    for r in res.get("resources", []) or []
                ]
                inc = deps.cfg.include_raw_default if include_raw is None else bool(include_raw)
                return responses.paged(items, page=page, page_size=size,
                                       total=res.get("total"), raw=raw, include_raw=inc)

            return await run(deps, name, {"page": page}, _fn)

        tool.__name__ = name
        tool.__doc__ = f"List {wrapper} from ISE (read-only)."
        return tool

    mcp.tool()(_list_tool("ise_list_security_groups", deps.ers.list_security_groups, "SGTs"))
    mcp.tool()(_list_tool("ise_list_sgacls", deps.ers.list_sgacls, "SGACLs"))
    mcp.tool()(
        _list_tool(
            "ise_list_authorization_profiles",
            deps.ers.list_authorization_profiles,
            "authorization profiles",
        )
    )
