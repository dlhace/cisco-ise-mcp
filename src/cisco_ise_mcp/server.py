"""Server assembly: build providers, ISE client, register tools, wire transport.

HTTP transport adds a tiny ASGI middleware that lifts the MCP session id from the
configured header (or `Authorization: Bearer`) into a contextvar the tools read.
"""
from __future__ import annotations

import logging

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

    @mcp.custom_route("/token", methods=["POST"])
    async def _token(request):  # noqa: ANN001
        """OAuth2 client-credentials token endpoint (passthrough mode).

        client_id/client_secret are the caller's ISE username/password (form body or
        HTTP Basic). On success returns the MCP session id as a Bearer access_token,
        which tools accept via `Authorization: Bearer` or the X-MCP-Session header.
        Lets non-interactive OAuth clients (Copilot Studio, Claude, etc.) authenticate
        with real ISE credentials. Secrets are never logged."""
        import base64

        from starlette.responses import JSONResponse

        if not isinstance(provider, PassthroughProvider):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "token endpoint requires passthrough mode"},
                status_code=400,
            )
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001
            form = {}
        grant = (form.get("grant_type") or "").strip()
        cid, csec = form.get("client_id"), form.get("client_secret")
        if not cid or not csec:  # RFC6749 client creds may arrive via HTTP Basic
            authz = request.headers.get("authorization", "")
            if authz[:6].lower() == "basic ":
                try:
                    u, _, p = base64.b64decode(authz[6:]).decode().partition(":")
                    cid, csec = cid or u, csec or p
                except Exception:  # noqa: BLE001
                    pass
        if grant != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        if not cid or not csec:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "missing client credentials"},
                status_code=400,
            )
        try:
            sess = await provider.login(cid, csec)
        except Exception:  # noqa: BLE001  (fail closed; do not leak why)
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        return JSONResponse(
            {"access_token": sess.session_id, "token_type": "Bearer",
             "expires_in": cfg.session_ttl_seconds},
            headers={"Cache-Control": "no-store"},
        )

    _log.info(
        "server_built",
        extra={"auth_mode": cfg.auth_mode, "mcp_mode": cfg.mcp_mode, "readonly": cfg.is_readonly},
    )
    return mcp, deps, client


def build_http_app(cfg: Config | None = None):
    """Return a Starlette ASGI app for HTTP deployment (Docker / Cloud Foundry).

    The MCP session id is read per-call from the request context inside the tools
    (see tools.mcp_session_id); /healthz is a FastMCP custom route registered in
    build(); the httpx client is closed at process exit."""
    mcp, _deps, _client = build(cfg)
    return mcp.streamable_http_app()


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
