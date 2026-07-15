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
from .oauth import OAuthServer
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

    oauth = OAuthServer(cfg, provider) if isinstance(provider, PassthroughProvider) else None

    @mcp.custom_route("/healthz", methods=["GET"])
    async def _healthz(_request):  # noqa: ANN001
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok", "mode": cfg.mcp_mode})

    def _client_creds(request, form):
        """Pull client_id/client_secret from form body or HTTP Basic."""
        import base64

        cid, csec = form.get("client_id"), form.get("client_secret")
        if not cid or not csec:
            authz = request.headers.get("authorization", "")
            if authz[:6].lower() == "basic ":
                try:
                    u, _, p = base64.b64decode(authz[6:]).decode().partition(":")
                    cid, csec = cid or u, csec or p
                except Exception:  # noqa: BLE001
                    pass
        return cid, csec

    @mcp.custom_route("/token", methods=["POST"])
    async def _token(request):  # noqa: ANN001
        """OAuth2 token endpoint. Grants:
          * client_credentials — client_id/secret ARE the ISE creds (Claude/programmatic).
          * authorization_code / refresh_token — confidential OAUTH_CLIENT for Copilot
            Studio etc.; the ISE identity was established at /authorize.
        Secrets are never logged."""
        from starlette.responses import JSONResponse

        def out(body, status=200):
            return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})

        if not isinstance(provider, PassthroughProvider):
            return out({"error": "invalid_request", "error_description": "requires passthrough mode"}, 400)
        try:
            form = await request.form()
        except Exception:  # noqa: BLE001
            form = {}
        grant = (form.get("grant_type") or "").strip()
        cid, csec = _client_creds(request, form)

        if grant == "client_credentials":
            if not cid or not csec:
                return out({"error": "invalid_request", "error_description": "missing client credentials"}, 400)
            try:
                sess = await provider.login(cid, csec)  # cid/csec == ISE creds here
            except Exception:  # noqa: BLE001
                return out({"error": "invalid_client"}, 401)
            return out({"access_token": sess.session_id, "token_type": "Bearer",
                        "expires_in": cfg.session_ttl_seconds})

        if grant == "authorization_code":
            if oauth is None:
                return out({"error": "invalid_request"}, 400)
            resp, err = await oauth.exchange_code(
                code=form.get("code"), redirect_uri=form.get("redirect_uri"),
                client_id=cid, client_secret=csec, verifier=form.get("code_verifier"))
            return out(resp) if resp else out({"error": err}, 401 if err == "invalid_client" else 400)

        if grant == "refresh_token":
            if oauth is None:
                return out({"error": "invalid_request"}, 400)
            resp, err = await oauth.refresh(
                refresh_token=form.get("refresh_token"), client_id=cid, client_secret=csec)
            return out(resp) if resp else out({"error": err}, 401 if err == "invalid_client" else 400)

        return out({"error": "unsupported_grant_type"}, 400)

    @mcp.custom_route("/authorize", methods=["GET"])
    async def _authorize_get(request):  # noqa: ANN001
        import secrets as _secrets

        from starlette.responses import HTMLResponse, PlainTextResponse

        if oauth is None:
            return PlainTextResponse("OAuth authorization is not enabled", status_code=404)
        q = request.query_params
        if q.get("response_type") != "code":
            return PlainTextResponse("unsupported_response_type", status_code=400)
        if not _secrets.compare_digest(q.get("client_id", ""), cfg.oauth_client_id):
            return PlainTextResponse("invalid client_id", status_code=400)
        if not oauth.redirect_ok(q.get("redirect_uri")):
            return PlainTextResponse("invalid redirect_uri", status_code=400)
        params = {k: q.get(k, "") for k in
                  ("client_id", "redirect_uri", "scope", "state", "code_challenge")}
        return HTMLResponse(oauth.login_page(params))

    @mcp.custom_route("/authorize", methods=["POST"])
    async def _authorize_post(request):  # noqa: ANN001
        import secrets as _secrets

        from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse

        if oauth is None:
            return PlainTextResponse("OAuth authorization is not enabled", status_code=404)
        form = await request.form()
        cid, redirect_uri = form.get("client_id", ""), form.get("redirect_uri", "")
        if not _secrets.compare_digest(cid, cfg.oauth_client_id) or not oauth.redirect_ok(redirect_uri):
            return PlainTextResponse("invalid client or redirect_uri", status_code=400)
        params = {k: form.get(k, "") for k in
                  ("client_id", "redirect_uri", "scope", "state", "code_challenge")}
        try:
            code = await oauth.login_and_issue_code(
                username=form.get("username", ""), password=form.get("password", ""),
                client_id=cid, redirect_uri=redirect_uri,
                scope=form.get("scope", ""), challenge=form.get("code_challenge", ""))
        except Exception:  # noqa: BLE001 - bad ISE creds
            return HTMLResponse(
                oauth.login_page(params, error="Invalid ISE credentials. Please try again."),
                status_code=401)
        return RedirectResponse(
            oauth.redirect_with_code(redirect_uri, code, form.get("state", "")), status_code=302)

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
