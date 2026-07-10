import pytest

from cisco_ise_mcp.config import load_config
from cisco_ise_mcp.ise.errors import ToolDisabledError, WriteNotAllowedError
from cisco_ise_mcp.validation import assert_write_allowed


def _cfg(**over):
    env = {"ISE_BASE_URL": "https://x"}
    env.update(over)
    return load_config(env)


def test_readonly_blocks_write_tool():
    with pytest.raises(WriteNotAllowedError):
        assert_write_allowed(_cfg(ISE_MCP_MODE="readonly"), "ise_create_endpoint")


def test_readwrite_allows_write_tool():
    assert_write_allowed(_cfg(ISE_MCP_MODE="readwrite"), "ise_create_endpoint")


def test_delete_requires_dangerous_flag():
    # readwrite alone is not enough for delete
    with pytest.raises(WriteNotAllowedError):
        assert_write_allowed(_cfg(ISE_MCP_MODE="readwrite"), "ise_delete_endpoint")
    # with the dangerous flag it passes
    assert_write_allowed(
        _cfg(ISE_MCP_MODE="readwrite", ISE_ENABLE_DANGEROUS_TOOLS="true"), "ise_delete_endpoint"
    )


def test_disabled_tool_blocked_even_readwrite():
    with pytest.raises(ToolDisabledError):
        assert_write_allowed(
            _cfg(ISE_MCP_MODE="readwrite", ISE_DISABLED_TOOLS="ise_create_endpoint"),
            "ise_create_endpoint",
        )


def test_allowlist_blocks_unlisted():
    with pytest.raises(ToolDisabledError):
        assert_write_allowed(
            _cfg(ISE_MCP_MODE="readwrite", ISE_ALLOWED_TOOLS="ise_get_endpoint_by_mac"),
            "ise_create_endpoint",
        )
