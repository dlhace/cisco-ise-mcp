"""Server assembly: build providers, ISE client, register tools, wire transport.

HTTP transport adds a tiny ASGI middleware that lifts the MCP session id from the
configured header (or `Authorization: Bearer`) into a contextvar the tools read.
"""
from __future__ import annotations

import logging

from .auth.base import current_session_id
from .auth.passthrough import PassthroughProvider
from .auth.service_account import ServiceAccountProvider
from .auth.session_store import SessionStore
from .config import Config, load_config
from .ise.client import IseClient
from .ise.ers import ErsApi
from .ise.mnt import MntApi
from .logging_config import configure_logging
from .tools import Deps, register_all

_log = logging.getLogger("cisco_ise_mcp.server")


class SessionHeaderMiddleware:
    """ASGI middleware: set current_session_id from the session header / Bearer."""

    def __init__(self, app, header: str):
        self.app = app
        self._header = header.lower().encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        sid = headers.get(self._header)
        sid = sid.decode() if sid else None
        if not sid:
            authz = headers.get(b"authorization", b"")
            if authz[:7].lower() == b"bearer ":
                sid = authz[7:].decode().strip()
        token = current_session_id.set(sid)
        try:
            await self.app(scope, receive, send)
        finally:
            current_session_id.reset(token)


def build(cfg: Config | None = None):
    """Construct (FastMCP, deps, client). Importing here keeps mcp/httpx optional
    for the stdlib-only unit tests."""
    from mcp.server.fastmcp import FastMCP

    cfg = cfg or load_config()
    cfg.validate()
    configure_logging(cfg.log_level)

    client = IseClient(cfg)
    ers, mnt = ErsApi(cfg, client), MntApi(cfg, client)

    if cfg.auth_mode == "service_account":
        provider = ServiceAccountProvider(cfg)
    else:
        store = SessionStore(cfg.session_ttl_seconds, cfg.session_idle_timeout_seconds)
        provider = PassthroughProvider(store, client.validate_credentials)

    mcp = FastMCP("cisco-ise-mcp", host=cfg.host, port=cfg.port)
    deps = Deps(cfg=cfg, ers=ers, mnt=mnt, provider=provider)
    register_all(mcp, deps)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def _healthz(_request):  # noqa: ANN001
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok", "mode": cfg.mcp_mode})

    _log.info(
        "server_built",
        extra={"auth_mode": cfg.auth_mode, "mcp_mode": cfg.mcp_mode, "readonly": cfg.is_readonly},
    )
    return mcp, deps, client


def build_http_app(cfg: Config | None = None):
    """Return a Starlette ASGI app for HTTP deployment (Docker / Cloud Foundry).

    /healthz is registered as a FastMCP custom route in build(); the httpx client is
    closed at process exit (no explicit shutdown hook needed)."""
    mcp, deps, _client = build(cfg)
    app = mcp.streamable_http_app()
    app.add_middleware(SessionHeaderMiddleware, header=deps.cfg.session_header)
    return app


def main() -> None:
    cfg = load_config()
    cfg.validate()
    configure_logging(cfg.log_level)

    if cfg.transport == "stdio":
        mcp, _deps, _client = build(cfg)
        mcp.run(transport="stdio")
        return

    import uvicorn

    uvicorn.run(build_http_app(cfg), host=cfg.host, port=cfg.port)


if __name__ == "__main__":
    main()
