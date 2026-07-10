"""Aggregated policy/context + incident summaries (use cases #4, #5, #6).

This is the value-add of the ISE sub-agent: one MAC in, a consolidated identity/
policy/session picture out. Topology/device-discovery is intentionally NOT here —
that belongs to Catalyst Center / Arista CVaaS / NetBox MCPs (see docs/architecture.md).
"""
from __future__ import annotations

from .. import responses, validation
from ..ise.ers import name_of, summarize_endpoint
from ..ise.mnt import summarize_session
from ..ise.models import PolicyContext
from . import Deps, run


async def _build_context(deps: Deps, mac: str, auth) -> PolicyContext:
    ctx = PolicyContext(mac=mac)

    # Endpoint (ERS) — required-ish; note if absent.
    try:
        raw_ep = await deps.ers.get_endpoint_by_mac(mac, auth)
        summary = summarize_endpoint(raw_ep)
        ep = summary
        if summary.identity_group_id:
            try:
                g = await deps.ers.get_endpoint_group(summary.identity_group_id, auth)
                ep.identity_group = name_of(g, "EndPointGroup")
            except Exception:  # noqa: BLE001
                pass
        if summary.profile_id:
            try:
                p = await deps.ers.get_profiler_profile(summary.profile_id, auth)
                ep.profile = name_of(p, "ProfilerProfile")
            except Exception:  # noqa: BLE001
                pass
        ctx.endpoint = ep
    except Exception as exc:  # noqa: BLE001
        ctx.notes.append(f"endpoint lookup failed: {type(exc).__name__}")

    # Active session (MNT) — may 401 without monitoring rights.
    try:
        raw_sess = await deps.mnt.session_by_mac(mac, auth)
        sess = summarize_session(raw_sess)
        ctx.active_session = sess
        ctx.security_group = sess.security_group
    except Exception as exc:  # noqa: BLE001
        ctx.notes.append(f"active session unavailable (MNT): {type(exc).__name__}")

    # Recent auth (MNT).
    try:
        raw_auth = await deps.mnt.auth_status_by_mac(mac, auth, seconds=86400, records=10)
        ctx.recent_auth = [raw_auth] if raw_auth else []
    except Exception as exc:  # noqa: BLE001
        ctx.notes.append(f"auth history unavailable (MNT): {type(exc).__name__}")

    return ctx


def register(mcp, deps: Deps) -> None:
    @mcp.tool()
    async def ise_get_policy_context_by_mac(mac: str) -> dict:
        """Consolidated ISE context for a MAC: endpoint, identity/endpoint group,
        profile, active session, authorization profile, SGT, and recent auth."""
        async def _fn(auth):
            m = validation.normalize_mac(mac)
            ctx = await _build_context(deps, m, auth)
            return responses.ok(ctx.dict())

        return await run(deps, "ise_get_policy_context_by_mac", {"mac": mac}, _fn)

    @mcp.tool()
    async def ise_get_incident_summary_by_mac(mac: str) -> dict:
        """NOC/incident-style narrative summary for a MAC, plus the structured
        context it was built from (for orchestration with other network MCPs)."""
        async def _fn(auth):
            m = validation.normalize_mac(mac)
            ctx = await _build_context(deps, m, auth)
            return responses.ok({"summary": _narrative(ctx), "context": ctx.dict()})

        return await run(deps, "ise_get_incident_summary_by_mac", {"mac": mac}, _fn)


def _narrative(ctx: PolicyContext) -> str:
    lines = [f"ISE context for {ctx.mac}:"]
    ep = ctx.endpoint
    if ep:
        lines.append(
            f"- Endpoint: {ep.name or ep.mac}"
            + (f", IP {ep.ip_address}" if ep.ip_address else "")
            + (f", group '{ep.identity_group}'" if ep.identity_group else "")
            + (f", profiled as '{ep.profile}'" if ep.profile else "")
            + (" [statically grouped]" if ep.static_group_assignment else "")
        )
    else:
        lines.append("- Endpoint: not found in ISE.")
    s = ctx.active_session
    if s and (s.username or s.nas_ip or s.state):
        lines.append(
            f"- Active session: user '{s.username}' on NAS {s.nas_ip} port {s.nas_port}, "
            f"authz '{s.authz_profile}', state {s.state}."
        )
    else:
        lines.append("- Active session: none reported (or MNT not accessible).")
    if ctx.security_group:
        lines.append(f"- SGT: {ctx.security_group}.")
    for note in ctx.notes:
        lines.append(f"- Note: {note}")
    return "\n".join(lines)
