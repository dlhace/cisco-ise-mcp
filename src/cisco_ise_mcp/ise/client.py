"""Async ISE HTTP client. Handles TLS verify, timeout, retries, and rate limits.

Auth is per-request HTTP Basic derived from the caller's AuthContext (passthrough)
or the service account. The Authorization header is built by httpx and is never
logged or returned.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..auth.base import AuthContext
from ..config import Config
from .errors import IseApiError, NotFoundError, RateLimitError

_log = logging.getLogger("cisco_ise_mcp.ise.client")

_TRANSIENT = {502, 503, 504}
_MAX_RETRIES = 3


class IseClient:
    def __init__(self, cfg: Config, client: httpx.AsyncClient | None = None):
        self._cfg = cfg
        self._client = client or httpx.AsyncClient(
            verify=cfg.verify_ssl,
            timeout=cfg.timeout_seconds,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        base: str,
        path: str,
        auth: AuthContext,
        *,
        params: dict | None = None,
        json_body: Any = None,
        accept: str = "application/json",
        parse: str = "json",
    ) -> Any:
        url = f"{base}{path}"
        user, pwd = auth.basic_auth()
        headers = {"Accept": accept}
        if json_body is not None:
            headers["Content-Type"] = "application/json"

        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                    auth=(user, pwd),
                )
            except httpx.TransportError as exc:
                if attempt <= _MAX_RETRIES:
                    await self._backoff(attempt)
                    continue
                raise IseApiError(f"ISE transport error: {exc}") from exc

            # never log auth; log method/url/status only
            _log.debug("ise_request", extra={"method": method, "url": url, "status": resp.status_code})

            if resp.status_code == 429:
                if self._cfg.rate_limit_wait and attempt <= _MAX_RETRIES:
                    await self._backoff(attempt, resp.headers.get("Retry-After"))
                    continue
                raise RateLimitError("ISE rate limit exceeded", status=429)

            if resp.status_code in _TRANSIENT and attempt <= _MAX_RETRIES:
                await self._backoff(attempt)
                continue

            return self._handle(resp, parse)

    def _handle(self, resp: httpx.Response, parse: str) -> Any:
        if resp.status_code == 404:
            raise NotFoundError("ISE resource not found", status=404)
        if resp.status_code == 401:
            raise IseApiError("ISE authentication failed (401)", status=401)
        if resp.status_code == 403:
            raise IseApiError("ISE authorization denied (403)", status=403)
        if resp.status_code >= 400:
            raise IseApiError(
                f"ISE returned {resp.status_code}",
                status=resp.status_code,
                detail=_safe_body(resp),
            )
        if parse == "text":
            return resp.text
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {"_text": resp.text}

    async def _backoff(self, attempt: int, retry_after: str | None = None) -> None:
        if retry_after:
            try:
                await asyncio.sleep(min(float(retry_after), 30))
                return
            except ValueError:
                pass
        await asyncio.sleep(min(2 ** attempt * 0.5, 8))

    async def validate_credentials(self, username: str, password: str) -> bool:
        """Passthrough login probe. Fails CLOSED.

        Reject empty creds outright. Then probe /ers/config/node — the ERS resource
        that reliably returns 401 for bad/empty auth (unlike /endpoint, /internaluser,
        etc., which have been observed serving 200 without valid auth). Because ISE's
        ERS auth enforcement can be INCONSISTENT across the deployment VIP (the same
        request has been seen flapping 200<->401), probe several times and require
        EVERY probe to succeed; any single 401 => invalid. This makes an accidental
        permissive 200 insufficient to accept bad credentials.

        NOTE: this is defense-in-depth only. The real fix is ISE-side (enforce ERS
        auth uniformly on all PSNs) plus network-layer access control on the route.
        """
        if not username or not password:
            return False
        probe = AuthContext(username=username, mode="passthrough", _password=password)
        for _ in range(3):
            try:
                await self.request("GET", self._cfg.ers_base, "/ers/config/node?size=1", probe)
            except IseApiError as exc:
                if exc.status == 401:
                    return False
                raise  # transport/other error -> fail closed at caller
        return True


def _safe_body(resp: httpx.Response) -> str:
    body = resp.text or ""
    return body[:500]
