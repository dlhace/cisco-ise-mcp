"""Endpoint summarization + MAC validation. Stdlib-only (no httpx/mcp needed)."""
import json
import pathlib

import pytest

from cisco_ise_mcp.ise.ers import summarize_endpoint
from cisco_ise_mcp.validation import normalize_mac

FIX = pathlib.Path(__file__).parent / "fixtures"


def test_summarize_ers_endpoint_wrapper():
    raw = json.loads((FIX / "endpoint_ers.json").read_text())
    s = summarize_endpoint(raw)
    assert s.mac == "AA:BB:CC:DD:EE:FF"
    assert s.endpoint_id == "00000000-0000-0000-0000-000000000000"
    assert s.static_group_assignment is True
    assert s.identity_group_id


def test_normalize_mac_variants():
    assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_rejects_bad():
    with pytest.raises(Exception):
        normalize_mac("nope")
