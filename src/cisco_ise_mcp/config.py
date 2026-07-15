"""Environment-driven configuration. Stdlib only (no pydantic) so it stays testable
without runtime deps installed."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping

TRUE = {"1", "true", "yes", "on"}


def _bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    v = env.get(key)
    return default if v is None or v == "" else v.strip().lower() in TRUE


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    v = env.get(key)
    try:
        return int(v) if v not in (None, "") else default
    except ValueError:
        return default


def _csv(env: Mapping[str, str], key: str) -> list[str]:
    v = env.get(key, "")
    return [x.strip() for x in v.split(",") if x.strip()]


@dataclass(frozen=True)
class Config:
    ise_base_url: str = ""
    ise_ers_base_url: str = ""
    ise_mnt_base_url: str = ""
    ise_username: str = ""
    ise_password: str = ""
    ise_encoded_auth: str = ""
    ise_version: str = "3.2"
    verify_ssl: bool = True
    timeout_seconds: int = 30
    rate_limit_wait: bool = True

    auth_mode: str = "passthrough"          # passthrough | service_account
    mcp_mode: str = "readonly"              # readonly | readwrite
    enable_dangerous_tools: bool = False

    session_ttl_seconds: int = 3600
    session_idle_timeout_seconds: int = 900
    session_header: str = "X-MCP-Session"

    log_level: str = "INFO"
    audit_log_enabled: bool = True

    allowed_tools: list[str] = field(default_factory=list)
    disabled_tools: list[str] = field(default_factory=list)
    allowed_endpoint_groups: list[str] = field(default_factory=list)
    allowed_device_groups: list[str] = field(default_factory=list)
    allowed_sites: list[str] = field(default_factory=list)

    default_page_size: int = 50
    max_page_size: int = 500
    include_raw_default: bool = False

    # OAuth2 "Manual" mode (authorization_code) — confidential client for Copilot
    # Studio etc. Empty client_id disables the /authorize + code/refresh grants.
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_redirect_uris: list[str] = field(default_factory=list)
    oauth_scopes: str = "ise.read"

    host: str = "0.0.0.0"
    port: int = 8005
    transport: str = "streamable-http"

    # ---- derived ----
    @property
    def ers_base(self) -> str:
        return (self.ise_ers_base_url or self.ise_base_url).rstrip("/")

    @property
    def mnt_base(self) -> str:
        return (self.ise_mnt_base_url or self.ise_base_url).rstrip("/")

    @property
    def is_readonly(self) -> bool:
        return self.mcp_mode.lower() != "readwrite"

    def validate(self) -> None:
        if self.auth_mode not in ("passthrough", "service_account"):
            raise ValueError(f"Unsupported ISE_AUTH_MODE: {self.auth_mode}")
        if self.mcp_mode.lower() not in ("readonly", "readwrite"):
            raise ValueError(f"Unsupported ISE_MCP_MODE: {self.mcp_mode}")
        if not self.ise_base_url:
            raise ValueError("ISE_BASE_URL is required")
        if self.auth_mode == "service_account" and not (
            self.ise_encoded_auth or (self.ise_username and self.ise_password)
        ):
            raise ValueError(
                "service_account mode requires ISE_USERNAME+ISE_PASSWORD or ISE_ENCODED_AUTH"
            )
        if self.max_page_size < self.default_page_size:
            raise ValueError("ISE_MAX_PAGE_SIZE must be >= ISE_DEFAULT_PAGE_SIZE")


def load_config(env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    return Config(
        ise_base_url=env.get("ISE_BASE_URL", "").rstrip("/"),
        ise_ers_base_url=env.get("ISE_ERS_BASE_URL", ""),
        ise_mnt_base_url=env.get("ISE_MNT_BASE_URL", ""),
        ise_username=env.get("ISE_USERNAME", ""),
        ise_password=env.get("ISE_PASSWORD", ""),
        ise_encoded_auth=env.get("ISE_ENCODED_AUTH", ""),
        ise_version=env.get("ISE_VERSION", "3.2"),
        verify_ssl=_bool(env, "ISE_VERIFY_SSL", True),
        timeout_seconds=_int(env, "ISE_TIMEOUT_SECONDS", 30),
        rate_limit_wait=_bool(env, "ISE_RATE_LIMIT_WAIT", True),
        auth_mode=env.get("ISE_AUTH_MODE", "passthrough").strip().lower(),
        mcp_mode=env.get("ISE_MCP_MODE", "readonly").strip().lower(),
        enable_dangerous_tools=_bool(env, "ISE_ENABLE_DANGEROUS_TOOLS", False),
        session_ttl_seconds=_int(env, "ISE_SESSION_TTL_SECONDS", 3600),
        session_idle_timeout_seconds=_int(env, "ISE_SESSION_IDLE_TIMEOUT_SECONDS", 900),
        session_header=env.get("MCP_SESSION_HEADER", "X-MCP-Session"),
        log_level=env.get("LOG_LEVEL", "INFO").upper(),
        audit_log_enabled=_bool(env, "AUDIT_LOG_ENABLED", True),
        allowed_tools=_csv(env, "ISE_ALLOWED_TOOLS"),
        disabled_tools=_csv(env, "ISE_DISABLED_TOOLS"),
        allowed_endpoint_groups=_csv(env, "ISE_ALLOWED_ENDPOINT_GROUPS"),
        allowed_device_groups=_csv(env, "ISE_ALLOWED_DEVICE_GROUPS"),
        allowed_sites=_csv(env, "ISE_ALLOWED_SITES"),
        default_page_size=_int(env, "ISE_DEFAULT_PAGE_SIZE", 50),
        max_page_size=_int(env, "ISE_MAX_PAGE_SIZE", 500),
        include_raw_default=_bool(env, "ISE_INCLUDE_RAW_DEFAULT", False),
        oauth_client_id=env.get("OAUTH_CLIENT_ID", ""),
        oauth_client_secret=env.get("OAUTH_CLIENT_SECRET", ""),
        oauth_redirect_uris=_csv(env, "OAUTH_REDIRECT_URIS"),
        oauth_scopes=env.get("OAUTH_SCOPES", "ise.read"),
        host=env.get("MCP_HOST", "0.0.0.0"),
        port=_int(env, "MCP_PORT", 8005),
        transport=env.get("MCP_TRANSPORT", "streamable-http"),
    )
