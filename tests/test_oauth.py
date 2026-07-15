import asyncio
import base64
import hashlib

from cisco_ise_mcp.config import Config
from cisco_ise_mcp.oauth import OAuthServer


class _Sess:
    def __init__(self, sid):
        self.session_id = sid


class _Provider:
    async def login(self, u, p):
        if p == "good":
            return _Sess("sess-" + u)
        raise ValueError("bad creds")


def _srv():
    cfg = Config(
        ise_base_url="https://x",
        oauth_client_id="cid",
        oauth_client_secret="csec",
        oauth_redirect_uris=["https://cb/redirect"],
        session_ttl_seconds=3600,
    )
    return OAuthServer(cfg, _Provider())


def test_client_and_redirect_validation():
    s = _srv()
    assert s.enabled
    assert s.client_ok("cid", "csec")
    assert not s.client_ok("cid", "wrong")
    assert not s.client_ok("", "")
    assert s.redirect_ok("https://cb/redirect")
    assert not s.redirect_ok("https://evil/cb")


def test_auth_code_exchange_and_refresh():
    s = _srv()
    verifier = "verifier-string-1234567890abcdef"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    async def go():
        code = await s.login_and_issue_code(
            username="alice", password="good", client_id="cid",
            redirect_uri="https://cb/redirect", scope="ise.read", challenge=challenge)
        resp, err = await s.exchange_code(
            code=code, redirect_uri="https://cb/redirect",
            client_id="cid", client_secret="csec", verifier=verifier)
        assert err is None
        assert resp["access_token"] == "sess-alice"
        assert resp["token_type"] == "Bearer"
        assert "refresh_token" in resp
        r2, e2 = await s.refresh(refresh_token=resp["refresh_token"], client_id="cid", client_secret="csec")
        assert e2 is None and r2["access_token"] == "sess-alice"

    asyncio.run(go())


def test_bad_client_secret_rejected_on_exchange():
    s = _srv()

    async def go():
        code = await s.login_and_issue_code(
            username="a", password="good", client_id="cid",
            redirect_uri="https://cb/redirect", scope="", challenge="")
        resp, err = await s.exchange_code(
            code=code, redirect_uri="https://cb/redirect",
            client_id="cid", client_secret="WRONG", verifier=None)
        assert resp is None and err == "invalid_client"

    asyncio.run(go())


def test_pkce_mismatch_rejected():
    s = _srv()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"right-verifier").digest()).rstrip(b"=").decode()

    async def go():
        code = await s.login_and_issue_code(
            username="a", password="good", client_id="cid",
            redirect_uri="https://cb/redirect", scope="", challenge=challenge)
        resp, err = await s.exchange_code(
            code=code, redirect_uri="https://cb/redirect",
            client_id="cid", client_secret="csec", verifier="wrong-verifier")
        assert resp is None and err == "invalid_grant"

    asyncio.run(go())


def test_bad_ise_login_raises():
    s = _srv()

    async def go():
        try:
            await s.login_and_issue_code(
                username="bob", password="bad", client_id="cid",
                redirect_uri="https://cb/redirect", scope="", challenge="")
            raise AssertionError("expected failure")
        except ValueError:
            pass

    asyncio.run(go())


def test_redirect_with_code_builds_query():
    s = _srv()
    assert s.redirect_with_code("https://cb/redirect", "CODE", "ST") == \
        "https://cb/redirect?code=CODE&state=ST"
    # existing query -> uses &
    assert "&code=CODE" in s.redirect_with_code("https://cb/redirect?x=1", "CODE", "")
