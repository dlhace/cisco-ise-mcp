"""Input validation + tool/write gating. Stdlib only so the safety rules are
unit-testable without runtime deps."""
from __future__ import annotations

import re

from .config import Config
from .ise.errors import (
    ToolDisabledError,
    ValidationError,
    WriteNotAllowedError,
)

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$")
_MAC_PLAIN_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")
_USERNAME_RE = re.compile(r"^[^\s\x00-\x1f]{1,128}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")

# Write tools that require readwrite mode. Names are the MCP tool names.
WRITE_TOOLS = {
    "ise_create_endpoint",
    "ise_update_endpoint",
    "ise_delete_endpoint",
    "ise_assign_endpoint_group",
}
# Subset also gated by ISE_ENABLE_DANGEROUS_TOOLS.
DANGEROUS_TOOLS = {"ise_delete_endpoint"}


def normalize_mac(value: str) -> str:
    """Return canonical AA:BB:CC:DD:EE:FF or raise ValidationError."""
    if not isinstance(value, str):
        raise ValidationError("MAC must be a string")
    v = value.strip()
    if _MAC_PLAIN_RE.match(v):
        v = ":".join(v[i : i + 2] for i in range(0, 12, 2))
    if not _MAC_RE.match(v):
        raise ValidationError(f"Invalid MAC address: {value!r}")
    return v.replace("-", ":").upper()


def validate_ip(value: str) -> str:
    if not isinstance(value, str) or not _IPV4_RE.match(value.strip()):
        raise ValidationError(f"Invalid IPv4 address: {value!r}")
    return value.strip()


def validate_hostname(value: str) -> str:
    v = (value or "").strip()
    if not _HOSTNAME_RE.match(v):
        raise ValidationError(f"Invalid hostname: {value!r}")
    return v


def validate_username(value: str) -> str:
    v = (value or "").strip()
    if not _USERNAME_RE.match(v):
        raise ValidationError("Invalid username")
    return v


def validate_endpoint_id(value: str) -> str:
    v = (value or "").strip()
    if not _UUID_RE.match(v):
        raise ValidationError(f"Invalid endpoint id: {value!r}")
    return v


def clamp_page_size(cfg: Config, requested: int | None) -> int:
    n = cfg.default_page_size if requested is None else int(requested)
    return max(1, min(n, cfg.max_page_size))


def is_tool_enabled(cfg: Config, tool_name: str) -> bool:
    if cfg.disabled_tools and tool_name in cfg.disabled_tools:
        return False
    if cfg.allowed_tools:  # allowlist wins when set
        return tool_name in cfg.allowed_tools
    return True


def assert_tool_enabled(cfg: Config, tool_name: str) -> None:
    if not is_tool_enabled(cfg, tool_name):
        raise ToolDisabledError(f"Tool '{tool_name}' is disabled by configuration")


def assert_write_allowed(cfg: Config, tool_name: str) -> None:
    """Core write-safety gate. Raises unless the deployment permits this write.

    ISE user-permission enforcement still happens server-side at ISE; this is the
    MCP-side belt-and-suspenders check.
    """
    assert_tool_enabled(cfg, tool_name)
    if tool_name in WRITE_TOOLS and cfg.is_readonly:
        raise WriteNotAllowedError(
            f"Tool '{tool_name}' requires ISE_MCP_MODE=readwrite (server is readonly)"
        )
    if tool_name in DANGEROUS_TOOLS and not cfg.enable_dangerous_tools:
        raise WriteNotAllowedError(
            f"Tool '{tool_name}' requires ISE_ENABLE_DANGEROUS_TOOLS=true"
        )


def assert_group_allowed(cfg: Config, group: str | None) -> None:
    if group and cfg.allowed_endpoint_groups and group not in cfg.allowed_endpoint_groups:
        raise ValidationError(f"Endpoint group '{group}' not in ISE_ALLOWED_ENDPOINT_GROUPS")
