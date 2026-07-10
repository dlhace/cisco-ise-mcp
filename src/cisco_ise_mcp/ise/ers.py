"""ERS (External RESTful Services) API wrapper.

Defensive by design: not every resource exists on every 3.x patch. Callers get
NotFoundError / IseApiError with helpful messages rather than crashes.

MAC lookup uses the canonical /ers/config/endpoint/name/{mac} path (reliable),
not filter=mac.EQUALS which some deployments reject with HTTP 400.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..config import Config
from .models import EndpointSummary

if TYPE_CHECKING:
    from .client import IseClient


class ErsApi:
    def __init__(self, cfg: Config, client: "IseClient"):
        self._cfg = cfg
        self._c = client

    async def _get(self, path: str, auth, params: dict | None = None) -> Any:
        return await self._c.request("GET", self._cfg.ers_base, path, auth, params=params)

    # ---------- endpoints ----------
    async def get_endpoint_by_mac(self, mac: str, auth) -> dict:
        return await self._get(f"/ers/config/endpoint/name/{mac}", auth)

    async def get_endpoint_by_id(self, endpoint_id: str, auth) -> dict:
        return await self._get(f"/ers/config/endpoint/{endpoint_id}", auth)

    async def search_endpoints(self, filter_expr: str | None, auth, *, page: int, size: int) -> dict:
        params = {"page": page, "size": size}
        if filter_expr:
            params["filter"] = filter_expr
        return await self._get("/ers/config/endpoint", auth, params)

    # ---------- groups / profiles / identity ----------
    async def get_endpoint_group(self, group_id: str, auth) -> dict:
        return await self._get(f"/ers/config/endpointgroup/{group_id}", auth)

    async def get_profiler_profile(self, profile_id: str, auth) -> dict:
        return await self._get(f"/ers/config/profilerprofile/{profile_id}", auth)

    async def get_identity_group(self, group_id: str, auth) -> dict:
        return await self._get(f"/ers/config/identitygroup/{group_id}", auth)

    async def get_internal_user(self, name: str, auth) -> dict:
        return await self._get(f"/ers/config/internaluser/name/{name}", auth)

    # ---------- network devices ----------
    async def list_network_devices(self, filter_expr: str | None, auth, *, page: int, size: int) -> dict:
        params = {"page": page, "size": size}
        if filter_expr:
            params["filter"] = filter_expr
        return await self._get("/ers/config/networkdevice", auth, params)

    # ---------- policy / trustsec ----------
    async def list_authorization_profiles(self, auth, *, page: int, size: int) -> dict:
        return await self._get("/ers/config/authorizationprofile", auth, {"page": page, "size": size})

    async def list_security_groups(self, auth, *, page: int, size: int) -> dict:
        return await self._get("/ers/config/sgt", auth, {"page": page, "size": size})

    async def list_sgacls(self, auth, *, page: int, size: int) -> dict:
        return await self._get("/ers/config/sgacl", auth, {"page": page, "size": size})

    # ---------- writes (readwrite mode only) ----------
    async def create_endpoint(self, body: dict, auth) -> dict:
        return await self._c.request(
            "POST", self._cfg.ers_base, "/ers/config/endpoint", auth, json_body={"ERSEndPoint": body}
        )

    async def update_endpoint(self, endpoint_id: str, body: dict, auth) -> dict:
        return await self._c.request(
            "PUT", self._cfg.ers_base, f"/ers/config/endpoint/{endpoint_id}", auth,
            json_body={"ERSEndPoint": body},
        )

    async def delete_endpoint(self, endpoint_id: str, auth) -> dict:
        return await self._c.request(
            "DELETE", self._cfg.ers_base, f"/ers/config/endpoint/{endpoint_id}", auth
        )


def summarize_endpoint(raw: dict) -> EndpointSummary:
    """Normalize either an ERS `{ERSEndPoint:{...}}` wrapper or a flat Open-API-ish
    endpoint dict into EndpointSummary."""
    ep = raw.get("ERSEndPoint", raw) if isinstance(raw, dict) else {}
    ca = ep.get("customAttributes")
    if isinstance(ca, dict):
        ca = ca.get("customAttributes", ca)
    return EndpointSummary(
        mac=ep.get("mac"),
        endpoint_id=ep.get("id"),
        name=ep.get("name"),
        ip_address=ep.get("ipAddress"),
        identity_group_id=ep.get("groupId"),
        profile_id=ep.get("profileId"),
        static_group_assignment=ep.get("staticGroupAssignment"),
        static_profile_assignment=ep.get("staticProfileAssignment"),
        portal_user=ep.get("portalUser") or None,
        custom_attributes=ca if isinstance(ca, dict) else {},
    )


def name_of(raw: dict, wrapper: str) -> str | None:
    obj = raw.get(wrapper, raw) if isinstance(raw, dict) else {}
    return obj.get("name")
