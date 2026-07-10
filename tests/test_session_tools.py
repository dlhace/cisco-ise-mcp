"""MNT XML parsing + session summarization. Stdlib-only."""
import pathlib

from cisco_ise_mcp.ise.mnt import _xml_to_dict, summarize_session

FIX = pathlib.Path(__file__).parent / "fixtures"


def test_parse_and_summarize_session_xml():
    xml = (FIX / "session_mnt.xml").read_text()
    parsed = _xml_to_dict(xml)
    assert parsed  # non-empty dict
    summary = summarize_session(parsed)
    assert summary.username == "host/printer-r7-117"
    assert summary.ip_address == "10.89.26.77"
    assert summary.nas_ip == "10.89.0.1"


def test_empty_xml_is_empty_dict():
    assert _xml_to_dict("") == {}
    assert _xml_to_dict("   ") == {}
