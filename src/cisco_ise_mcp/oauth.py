"""Minimal self-contained OAuth2 authorization server for Copilot Studio "Manual"
mode: authorization_code + refresh_token grants, plus the existing
client_credentials grant. In-memory, single-instance (v1). Never logs secrets.

Model:
  * authorization_code / refresh_token: confidential client = the configured
    OAUTH_CLIENT_ID/SECRET (e.g. Copilot Studio). The END USER authenticates with
    their ISE credentials on the /authorize login page; the access token is an MCP
    session id, so their own ISE identity is used (passthrough).
  * client_credentials: client_id/secret ARE the caller's ISE creds directly
    (kept for Claude Code / programmatic clients).

TODO(phase2): move code/refresh/session stores to a shared backend (Redis) for
multi-instance deployments; today a restart drops them.
"""
from __future__ import annotations

import base64
import hashlib
import html
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass

from .config import Config

CODE_TTL = 120  # seconds
REFRESH_TTL = 7 * 24 * 3600  # 7 days


@dataclass
class _Code:
    client_id: str
    redirect_uri: str
    scope: str
    session_id: str
    username: str
    password: str  # held in memory only, for refresh re-validation
    challenge: str
    created: float


class OAuthServer:
    def __init__(self, cfg: Config, provider):
        self.cfg = cfg
        self.provider = provider  # PassthroughProvider
        self._codes: dict[str, _Code] = {}
        self._refresh: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()  # ponytail: one global lock; fine single-instance

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.oauth_client_id and self.cfg.oauth_client_secret)

    # ---- client / redirect validation ----
    def client_ok(self, cid: str | None, csec: str | None) -> bool:
        if not cid or not csec:
            return False
        return secrets.compare_digest(cid, self.cfg.oauth_client_id) and secrets.compare_digest(
            csec, self.cfg.oauth_client_secret
        )

    def redirect_ok(self, uri: str | None) -> bool:
        return bool(uri) and uri in self.cfg.oauth_redirect_uris

    # ---- authorization_code issuance (after ISE login) ----
    async def login_and_issue_code(
        self, *, username, password, client_id, redirect_uri, scope, challenge
    ) -> str:
        sess = await self.provider.login(username, password)  # validates ISE; raises on bad
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._codes[code] = _Code(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope or self.cfg.oauth_scopes,
                session_id=sess.session_id,
                username=username,
                password=password,
                challenge=challenge or "",
                created=time.time(),
            )
        return code

    def _pop_code(self, code: str) -> _Code | None:
        with self._lock:
            rec = self._codes.pop(code, None)
        if rec is None or time.time() - rec.created > CODE_TTL:
            return None
        return rec

    @staticmethod
    def _pkce_ok(rec: _Code, verifier: str | None) -> bool:
        if not rec.challenge:
            return True  # PKCE not used (confidential client w/ secret)
        if not verifier:
            return False
        digest = hashlib.sha256(verifier.encode()).digest()
        calc = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return secrets.compare_digest(calc, rec.challenge)

    def _base_token(self, session_id: str, scope: str) -> dict:
        return {
            "access_token": session_id,
            "token_type": "Bearer",
            "expires_in": self.cfg.session_ttl_seconds,
            "scope": scope,
        }

    async def exchange_code(self, *, code, redirect_uri, client_id, client_secret, verifier):
        if not self.client_ok(client_id, client_secret):
            return None, "invalid_client"
        rec = self._pop_code(code)
        if rec is None or rec.client_id != client_id or rec.redirect_uri != redirect_uri:
            return None, "invalid_grant"
        if not self._pkce_ok(rec, verifier):
            return None, "invalid_grant"
        resp = self._base_token(rec.session_id, rec.scope)
        rt = secrets.token_urlsafe(32)
        with self._lock:
            self._refresh[rt] = (rec.username, rec.password, time.time())
        resp["refresh_token"] = rt
        return resp, None

    async def refresh(self, *, refresh_token, client_id, client_secret):
        if not self.client_ok(client_id, client_secret):
            return None, "invalid_client"
        with self._lock:
            rec = self._refresh.get(refresh_token)
        if not rec or time.time() - rec[2] > REFRESH_TTL:
            return None, "invalid_grant"
        username, password, _ = rec
        try:
            sess = await self.provider.login(username, password)  # re-validate against ISE
        except Exception:  # noqa: BLE001 - creds revoked/invalid now
            with self._lock:
                self._refresh.pop(refresh_token, None)
            return None, "invalid_grant"
        resp = self._base_token(sess.session_id, self.cfg.oauth_scopes)
        resp["refresh_token"] = refresh_token  # non-rotating (single-instance v1)
        return resp, None

    # ---- login page ----
    def login_page(self, params: dict, error: str = "") -> str:
        def h(k):
            return html.escape(params.get(k, "") or "", quote=True)

        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cisco ISE MCP — Sign in</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;background:#f3f2f1;margin:0}}
 .card{{max-width:360px;margin:8vh auto;background:#fff;padding:28px;border-radius:8px;
   box-shadow:0 2px 12px rgba(0,0,0,.12)}}
 h1{{font-size:18px;margin:0 0 4px}} p.sub{{color:#605e5c;font-size:13px;margin:0 0 18px}}
 label{{display:block;font-size:13px;margin:12px 0 4px}}
 input[type=text],input[type=password]{{width:100%;box-sizing:border-box;padding:9px;
   border:1px solid #c8c6c4;border-radius:4px;font-size:14px}}
 button{{margin-top:18px;width:100%;padding:10px;background:#0f6cbd;color:#fff;border:0;
   border-radius:4px;font-size:14px;cursor:pointer}}
 .err{{color:#a4262c;font-size:13px;background:#fde7e9;padding:8px;border-radius:4px}}
</style></head><body><div class="card">
<h1>Cisco ISE MCP</h1><p class="sub">Sign in with your Cisco ISE credentials.</p>
{err}
<form method="post" action="/authorize">
 <input type="hidden" name="client_id" value="{h('client_id')}">
 <input type="hidden" name="redirect_uri" value="{h('redirect_uri')}">
 <input type="hidden" name="scope" value="{h('scope')}">
 <input type="hidden" name="state" value="{h('state')}">
 <input type="hidden" name="code_challenge" value="{h('code_challenge')}">
 <label>ISE username</label><input type="text" name="username" autocomplete="username" required>
 <label>ISE password</label><input type="password" name="password" autocomplete="current-password" required>
 <button type="submit">Sign in</button>
</form></div></body></html>"""

    @staticmethod
    def redirect_with_code(redirect_uri: str, code: str, state: str) -> str:
        q = {"code": code}
        if state:
            q["state"] = state
        sep = "&" if urllib.parse.urlparse(redirect_uri).query else "?"
        return f"{redirect_uri}{sep}{urllib.parse.urlencode(q)}"


def demo() -> None:
    """Self-check for PKCE + code/refresh logic (no network, fake provider)."""
    import asyncio

    class _Sess:
        def __init__(self, sid):
            self.session_id = sid

    class _Provider:
        async def login(self, u, p):
            if p == "good":
                return _Sess("sess-" + u)
            raise ValueError("bad creds")

    cfg = Config(
        ise_base_url="https://x",
        oauth_client_id="cid",
        oauth_client_secret="csec",
        oauth_redirect_uris=["https://cb/redirect"],
        session_ttl_seconds=3600,
    )
    srv = OAuthServer(cfg, _Provider())
    assert srv.enabled
    assert srv.client_ok("cid", "csec") and not srv.client_ok("cid", "nope")
    assert srv.redirect_ok("https://cb/redirect") and not srv.redirect_ok("https://evil")

    async def run():
        # PKCE flow
        verifier = "verifier-string-1234567890"
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        code = await srv.login_and_issue_code(
            username="alice", password="good", client_id="cid",
            redirect_uri="https://cb/redirect", scope="ise.read", challenge=challenge,
        )
        # wrong client rejected
        r, e = await srv.exchange_code(code=code, redirect_uri="https://cb/redirect",
                                       client_id="cid", client_secret="nope", verifier=verifier)
        assert r is None and e == "invalid_client"
        # wrong PKCE rejected (code consumed above? no—invalid_client returns before pop)
        r, e = await srv.exchange_code(code=code, redirect_uri="https://cb/redirect",
                                       client_id="cid", client_secret="csec", verifier="wrong")
        assert r is None and e == "invalid_grant"
        # fresh code, correct exchange
        code = await srv.login_and_issue_code(
            username="alice", password="good", client_id="cid",
            redirect_uri="https://cb/redirect", scope="ise.read", challenge=challenge,
        )
        r, e = await srv.exchange_code(code=code, redirect_uri="https://cb/redirect",
                                       client_id="cid", client_secret="csec", verifier=verifier)
        assert e is None and r["access_token"] == "sess-alice" and "refresh_token" in r
        rt = r["refresh_token"]
        # refresh works
        r2, e2 = await srv.refresh(refresh_token=rt, client_id="cid", client_secret="csec")
        assert e2 is None and r2["access_token"] == "sess-alice"
        # bad login -> raises inside login_and_issue_code
        try:
            await srv.login_and_issue_code(username="bob", password="bad", client_id="cid",
                                           redirect_uri="https://cb/redirect", scope="", challenge="")
            raise AssertionError("expected failure")
        except ValueError:
            pass
        print("oauth demo: OK")

    asyncio.run(run())


if __name__ == "__main__":
    demo()
