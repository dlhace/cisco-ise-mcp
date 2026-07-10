import asyncio
import base64

from cisco_ise_mcp.auth.service_account import ServiceAccountProvider
from cisco_ise_mcp.config import load_config


def test_service_account_resolves_config_identity():
    cfg = load_config(
        {
            "ISE_BASE_URL": "https://x",
            "ISE_AUTH_MODE": "service_account",
            "ISE_USERNAME": "svc",
            "ISE_PASSWORD": "pw",
        }
    )
    prov = ServiceAccountProvider(cfg)
    ctx = asyncio.run(prov.resolve(session_id=None))
    assert ctx.username == "svc"
    assert ctx.basic_auth() == ("svc", "pw")
    assert "pw" not in repr(ctx)


def test_encoded_auth_decodes():
    enc = base64.b64encode(b"user1:secretpw").decode()
    cfg = load_config(
        {"ISE_BASE_URL": "https://x", "ISE_AUTH_MODE": "service_account", "ISE_ENCODED_AUTH": enc}
    )
    prov = ServiceAccountProvider(cfg)
    ctx = asyncio.run(prov.resolve(session_id=None))
    assert ctx.basic_auth() == ("user1", "secretpw")
