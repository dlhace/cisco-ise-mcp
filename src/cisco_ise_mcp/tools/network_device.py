"""Network device (NAD) query tools. Read-only ERS lookups.

NOTE: this is ISE's view of RADIUS/TACACS network devices only — NOT topology or
device discovery. Use Catalyst Center / Arista CVaaS / NetBox MCPs for those.
"""
from __future__ import annotations

from .. import responses, validation
from . import Deps, run


def register(mcp, deps: Deps) -> None:
    @mcp.tool()
    async def ise_list_network_devices(
        filter_expression: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        include_raw: bool | None = None,
    ) -> dict:
        """List network devices registered in ISE (RADIUS/TACACS NADs)."""
        async def _fn(auth):
            size = validation.clamp_page_size(deps.cfg, page_size)
            raw = await deps.ers.list_network_devices(filter_expression, auth, page=page, size=size)
            res = raw.get("SearchResult", {}) if isinstance(raw, dict) else {}
            items = [
                {"id": r.get("id"), "name": r.get("name")} for r in res.get("resources", []) or []
            ]
            inc = deps.cfg.include_raw_default if include_raw is None else bool(include_raw)
            return responses.paged(
                items, page=page, page_size=size, total=res.get("total"),
                raw=raw, include_raw=inc,
            )

        return await run(
            deps, "ise_list_network_devices",
            {"filter": filter_expression, "page": page}, _fn,
        )
