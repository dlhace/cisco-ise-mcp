"""MNT (Monitoring) API wrapper. Returns session/auth telemetry.

MNT responses are XML. We parse to plain dicts with xml.etree (stdlib). MNT often
requires a monitoring-privileged account; a 401 here with an ERS-only account is
expected and surfaced clearly (see docs/ise-permissions.md).
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

from ..config import Config
from .models import SessionSummary

if TYPE_CHECKING:
    from .client import IseClient


class MntApi:
    def __init__(self, cfg: Config, client: "IseClient"):
        self._cfg = cfg
        self._c = client

    async def _get_xml(self, path: str, auth) -> str:
        return await self._c.request(
            "GET", self._cfg.mnt_base, path, auth, accept="application/xml", parse="text"
        )

    async def session_by_mac(self, mac: str, auth) -> dict:
        xml = await self._get_xml(f"/admin/API/mnt/Session/MACAddress/{mac}", auth)
        return _xml_to_dict(xml)

    async def session_by_ip(self, ip: str, auth) -> dict:
        xml = await self._get_xml(f"/admin/API/mnt/Session/IPAddress/{ip}", auth)
        return _xml_to_dict(xml)

    async def auth_status_by_mac(self, mac: str, auth, *, seconds: int = 86400, records: int = 50) -> dict:
        xml = await self._get_xml(
            f"/admin/API/mnt/AuthStatus/MACAddress/{mac}/{seconds}/{records}/All", auth
        )
        return _xml_to_dict(xml)

    async def active_list(self, auth) -> dict:
        xml = await self._get_xml("/admin/API/mnt/Session/ActiveList", auth)
        return _xml_to_dict(xml)


def _xml_to_dict(xml: str) -> dict:
    """Best-effort XML->dict. Returns {} on empty; keeps text + children."""
    if not xml or not xml.strip():
        return {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {"_text": xml[:1000]}
    return {root.tag: _elem(root)}


def _elem(node: ET.Element):
    children = list(node)
    if not children:
        text = (node.text or "").strip()
        return text or None
    out: dict = {}
    for child in children:
        val = _elem(child)
        if child.tag in out:
            if not isinstance(out[child.tag], list):
                out[child.tag] = [out[child.tag]]
            out[child.tag].append(val)
        else:
            out[child.tag] = val
    return out


def summarize_session(parsed: dict) -> SessionSummary:
    """Pull the common fields out of a parsed MNT session doc, tolerant of shape."""
    flat: dict[str, str] = {}

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                elif v is not None and k not in flat:
                    flat[k] = v
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(parsed)
    return SessionSummary(
        mac=flat.get("calling_station_id") or flat.get("macAddress"),
        ip_address=flat.get("framed_ip_address") or flat.get("ipAddress"),
        username=flat.get("user_name") or flat.get("userName"),
        nas_ip=flat.get("nas_ip_address") or flat.get("nasIpAddress"),
        nas_port=flat.get("nas_port_id") or flat.get("nasPortId"),
        authz_profile=flat.get("authorization_rule") or flat.get("authProfile"),
        posture_status=flat.get("posture_status"),
        security_group=flat.get("security_group"),
        state=flat.get("session_state") or flat.get("state"),
        server=flat.get("acs_server") or flat.get("server"),
    )
