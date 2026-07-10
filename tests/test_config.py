from cisco_ise_mcp.config import load_config

import pytest


def test_defaults_and_derived_urls():
    cfg = load_config({"ISE_BASE_URL": "https://ise-vip.example.local/"})
    assert cfg.auth_mode == "passthrough"
    assert cfg.mcp_mode == "readonly"
    assert cfg.is_readonly is True
    # trailing slash stripped; ers/mnt derive from base when unset
    assert cfg.ers_base == "https://ise-vip.example.local"
    assert cfg.mnt_base == "https://ise-vip.example.local"


def test_explicit_ers_mnt_override():
    cfg = load_config(
        {
            "ISE_BASE_URL": "https://vip.example",
            "ISE_ERS_BASE_URL": "https://ers.example/",
            "ISE_MNT_BASE_URL": "https://mnt.example/",
        }
    )
    assert cfg.ers_base == "https://ers.example"
    assert cfg.mnt_base == "https://mnt.example"


def test_bool_and_int_parsing():
    cfg = load_config(
        {"ISE_BASE_URL": "https://x", "ISE_VERIFY_SSL": "false", "ISE_TIMEOUT_SECONDS": "5"}
    )
    assert cfg.verify_ssl is False
    assert cfg.timeout_seconds == 5


def test_csv_lists():
    cfg = load_config({"ISE_BASE_URL": "https://x", "ISE_DISABLED_TOOLS": "a, b ,c"})
    assert cfg.disabled_tools == ["a", "b", "c"]


def test_validate_requires_base_url():
    with pytest.raises(ValueError):
        load_config({}).validate()


def test_service_account_requires_creds():
    with pytest.raises(ValueError):
        load_config({"ISE_BASE_URL": "https://x", "ISE_AUTH_MODE": "service_account"}).validate()
    # with creds it validates
    load_config(
        {
            "ISE_BASE_URL": "https://x",
            "ISE_AUTH_MODE": "service_account",
            "ISE_USERNAME": "svc",
            "ISE_PASSWORD": "pw",
        }
    ).validate()
