import asyncio

import pytest

from cisco_ise_mcp.auth.passthrough import PassthroughProvider
from cisco_ise_mcp.auth.session_store import SessionStore
from cisco_ise_mcp.ise.errors import AuthError, SessionError


def _store(clock=None):
    return SessionStore(3600, 900, clock=clock) if clock else SessionStore(3600, 900)


def test_login_success_creates_session_and_resolves():
    async def good(_u, _p):
        return True

    prov = PassthroughProvider(_store(), good)

    async def go():
        sess = await prov.login("alice", "pw")
        assert sess.session_id
        ctx = await prov.resolve(session_id=sess.session_id)
        assert ctx.username == "alice"
        assert ctx.basic_auth() == ("alice", "pw")
        # password must not leak via repr
        assert "pw" not in repr(ctx)
        return sess

    asyncio.run(go())


def test_login_rejects_bad_credentials():
    async def bad(_u, _p):
        return False

    prov = PassthroughProvider(_store(), bad)
    with pytest.raises(AuthError):
        asyncio.run(prov.login("alice", "wrong"))


def test_resolve_without_session_raises():
    async def good(_u, _p):
        return True

    prov = PassthroughProvider(_store(), good)
    with pytest.raises(SessionError):
        asyncio.run(prov.resolve(session_id=None))


def test_logout_invalidates():
    async def good(_u, _p):
        return True

    store = _store()
    prov = PassthroughProvider(store, good)

    async def go():
        sess = await prov.login("bob", "pw")
        assert prov.logout(sess.session_id) is True
        with pytest.raises(SessionError):
            await prov.resolve(session_id=sess.session_id)

    asyncio.run(go())


def test_idle_timeout_expires_session():
    t = {"now": 1000.0}
    store = SessionStore(ttl_seconds=3600, idle_timeout_seconds=10, clock=lambda: t["now"])

    async def good(_u, _p):
        return True

    prov = PassthroughProvider(store, good)

    async def go():
        sess = await prov.login("carol", "pw")
        t["now"] += 11  # exceed idle timeout
        with pytest.raises(SessionError):
            await prov.resolve(session_id=sess.session_id)

    asyncio.run(go())
