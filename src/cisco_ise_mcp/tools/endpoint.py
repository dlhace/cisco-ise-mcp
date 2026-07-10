"""Endpoint query tools (use case #1)."""
from __future__ import annotations

from .. import responses, validation
from ..ise.ers import name_of, summarize_endpoint
from . import Deps, run


async def _enrich(deps: Deps, summary, auth) -> dict:
    """Resolve group/profile ids to names; tolerate missing resources."""
    out = summary.dict()
    if summary.identity_group_id:
        try:
            g = await deps.ers.get_endpoint_group(summary.identity_group_id, auth)
            out["identity_group"] = name_of(g, "EndPointGroup")
        except Exception:  # noqa: BLE001
            pass
    if summary.profile_id:
        try:
            p = await deps.ers.get_profiler_profile(summary.profile_id, auth)
            out["profile"] = name_of(p, "ProfilerProfile")
        except Exception:  # noqa: BLE001
            pass
    return out


def register(mcp, deps: Deps) -> None:
    def _include_raw(v: bool | None) -> bool:
        return deps.cfg.include_raw_default if v is None else bool(v)

    @mcp.tool()
    async def ise_get_endpoint_by_mac(mac: str, include_raw: bool | None = None) -> dict:
        """Look up an endpoint by MAC address (canonical /endpoint/name/{mac} path)."""
        async def _fn(auth):
            m = validation.normalize_mac(mac)
            raw = await deps.ers.get_endpoint_by_mac(m, auth)
            data = await _enrich(deps, summarize_endpoint(raw), auth)
            return responses.ok(data, raw=raw, include_raw=_include_raw(include_raw))

        return await run(deps, "ise_get_endpoint_by_mac", {"mac": mac}, _fn)

    @mcp.tool()
    async def ise_get_endpoint_by_id(endpoint_id: str, include_raw: bool | None = None) -> dict:
        """Look up an endpoint by ISE endpoint id (UUID)."""
        async def _fn(auth):
            eid = validation.validate_endpoint_id(endpoint_id)
            raw = await deps.ers.get_endpoint_by_id(eid, auth)
            data = await _enrich(deps, summarize_endpoint(raw), auth)
            return responses.ok(data, raw=raw, include_raw=_include_raw(include_raw))

        return await run(deps, "ise_get_endpoint_by_id", {"endpoint_id": endpoint_id}, _fn)

    @mcp.tool()
    async def ise_get_endpoint_by_ip(ip: str, include_raw: bool | None = None) -> dict:
        """Find an endpoint by IP address (ERS filter ipAddress.EQUALS)."""
        async def _fn(auth):
            addr = validation.validate_ip(ip)
            raw = await deps.ers.search_endpoints(
                f"ipAddress.EQUALS.{addr}", auth,
                page=1, size=validation.clamp_page_size(deps.cfg, None),
            )
            items = [summarize_endpoint(r).dict() for r in _resources(raw)]
            return responses.ok(items, raw=raw, include_raw=_include_raw(include_raw))

        return await run(deps, "ise_get_endpoint_by_ip", {"ip": ip}, _fn)

    @mcp.tool()
    async def ise_search_endpoints(
        filter_expression: str | None = None,
        page: int = 1,
        page_size: int | None = None,
        include_raw: bool | None = None,
    ) -> dict:
        """Search endpoints. filter_expression uses ERS 'field.OP.value'
        (e.g. 'mac.CONTAINS.F8', 'groupId.EQUALS.<id>')."""
        async def _fn(auth):
            size = validation.clamp_page_size(deps.cfg, page_size)
            raw = await deps.ers.search_endpoints(filter_expression, auth, page=page, size=size)
            items = [summarize_endpoint(r).dict() for r in _resources(raw)]
            total = raw.get("SearchResult", {}).get("total") if isinstance(raw, dict) else None
            return responses.paged(
                items, page=page, page_size=size, total=total,
                raw=raw, include_raw=_include_raw(include_raw),
            )

        return await run(
            deps, "ise_search_endpoints",
            {"filter": filter_expression, "page": page}, _fn,
        )


def _resources(raw: dict) -> list:
    if not isinstance(raw, dict):
        return []
    return raw.get("SearchResult", {}).get("resources", []) or []
