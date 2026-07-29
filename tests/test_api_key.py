"""Static API key -> fixed ISE service account (no session, no stored user creds)."""
import asyncio

from cisco_ise_mcp.config import load_config
from cisco_ise_mcp.tools import Deps


def _deps(**over):
    env = {
        "ISE_BASE_URL": "https://x",
        "MCP_API_KEYS": "key-abc, key-def",
        "ISE_USERNAME": "svc-readonly",
        "ISE_PASSWORD": "svc-pass",
    }
    env.update(over)
    cfg = load_config(env)
    cfg.validate()
    return Deps(cfg=cfg, ers=None, mnt=None, provider=None)


def test_is_api_key_constant_match():
    d = _deps()
    assert d._is_api_key("key-abc") is True
    assert d._is_api_key("key-def") is True
    assert d._is_api_key("nope") is False
    assert d._is_api_key(None) is False


def test_session_valid_accepts_api_key_without_provider():
    d = _deps()
    # api key is valid at the gate even though provider is None
    assert d.session_valid("key-abc") is True
    assert d.session_valid("bad") is False


def test_api_key_resolves_to_fixed_account():
    d = _deps()
    d.session_id = lambda: "key-abc"  # simulate the presented token
    ctx = asyncio.run(d.resolve_auth())
    assert ctx.mode == "api_key"
    assert ctx.username == "svc-readonly"
    assert ctx.basic_auth() == ("svc-readonly", "svc-pass")
    assert "svc-pass" not in repr(ctx)


def test_config_requires_fixed_account_for_api_keys():
    import pytest

    with pytest.raises(ValueError):
        load_config({"ISE_BASE_URL": "https://x", "MCP_API_KEYS": "k"}).validate()
