"""Session + authentication-log tools (use cases #2, #3) via the MNT API."""
from __future__ import annotations

from .. import responses, validation
from ..ise.mnt import summarize_session
from . import Deps, run


def register(mcp, deps: Deps) -> None:
    def _raw(v):
        return deps.cfg.include_raw_default if v is None else bool(v)

    @mcp.tool()
    async def ise_get_active_session_by_mac(mac: str, include_raw: bool | None = None) -> dict:
        """Current active session for a MAC (MNT Session/MACAddress)."""
        async def _fn(auth):
            m = validation.normalize_mac(mac)
            raw = await deps.mnt.session_by_mac(m, auth)
            return responses.ok(summarize_session(raw).dict(), raw=raw, include_raw=_raw(include_raw))

        return await run(deps, "ise_get_active_session_by_mac", {"mac": mac}, _fn)

    @mcp.tool()
    async def ise_get_active_session_by_ip(ip: str, include_raw: bool | None = None) -> dict:
        """Current active session for an IP (MNT Session/IPAddress)."""
        async def _fn(auth):
            addr = validation.validate_ip(ip)
            raw = await deps.mnt.session_by_ip(addr, auth)
            return responses.ok(summarize_session(raw).dict(), raw=raw, include_raw=_raw(include_raw))

        return await run(deps, "ise_get_active_session_by_ip", {"ip": ip}, _fn)

    @mcp.tool()
    async def ise_get_auth_logs_by_mac(
        mac: str, seconds: int = 86400, records: int = 50, include_raw: bool | None = None
    ) -> dict:
        """Recent authentication/RADIUS status for a MAC (MNT AuthStatus)."""
        async def _fn(auth):
            m = validation.normalize_mac(mac)
            records_n = max(1, min(records, 500))
            raw = await deps.mnt.auth_status_by_mac(m, auth, seconds=seconds, records=records_n)
            return responses.ok(raw, raw=raw, include_raw=_raw(include_raw))

        return await run(
            deps, "ise_get_auth_logs_by_mac",
            {"mac": mac, "seconds": seconds, "records": records}, _fn,
        )
