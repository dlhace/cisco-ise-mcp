"""Lightweight normalized shapes returned to MCP clients. Dataclasses (stdlib)
keep summaries stable regardless of ISE patch-level field drift."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class EndpointSummary:
    mac: str | None = None
    endpoint_id: str | None = None
    name: str | None = None
    ip_address: str | None = None
    identity_group_id: str | None = None
    identity_group: str | None = None
    profile_id: str | None = None
    profile: str | None = None
    static_group_assignment: bool | None = None
    static_profile_assignment: bool | None = None
    portal_user: str | None = None
    custom_attributes: dict[str, Any] = field(default_factory=dict)

    def dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionSummary:
    mac: str | None = None
    ip_address: str | None = None
    username: str | None = None
    nas_ip: str | None = None
    nas_port: str | None = None
    authz_profile: str | None = None
    posture_status: str | None = None
    security_group: str | None = None
    state: str | None = None
    server: str | None = None

    def dict(self) -> dict:
        return asdict(self)


@dataclass
class PolicyContext:
    """Aggregated identity/policy context for one MAC (use case #5)."""

    mac: str
    endpoint: EndpointSummary | None = None
    active_session: SessionSummary | None = None
    recent_auth: list[dict] = field(default_factory=list)
    security_group: str | None = None
    notes: list[str] = field(default_factory=list)

    def dict(self) -> dict:
        return {
            "mac": self.mac,
            "endpoint": self.endpoint.dict() if self.endpoint else None,
            "active_session": self.active_session.dict() if self.active_session else None,
            "recent_auth": self.recent_auth,
            "security_group": self.security_group,
            "notes": self.notes,
        }
