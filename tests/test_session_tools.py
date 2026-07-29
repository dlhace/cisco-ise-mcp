"""MNT XML parsing + session summarization. Stdlib-only."""
import pathlib

from cisco_ise_mcp.ise.mnt import _xml_to_dict, summarize_session

FIX = pathlib.Path(__file__).parent / "fixtures"


def test_parse_and_summarize_session_xml():
    xml = (FIX / "session_mnt.xml").read_text()
    parsed = _xml_to_dict(xml)
    assert parsed  # non-empty dict
    summary = summarize_session(parsed)
    assert summary.username == "host/example-printer"
    assert summary.ip_address == "192.0.2.77"
    assert summary.nas_ip == "192.0.2.1"


def test_empty_xml_is_empty_dict():
    assert _xml_to_dict("") == {}
    assert _xml_to_dict("   ") == {}
