"""Incident narrative builder. Stdlib-only."""
from cisco_ise_mcp.ise.models import EndpointSummary, PolicyContext, SessionSummary
from cisco_ise_mcp.tools.policy import _narrative


def test_narrative_with_endpoint_and_session():
    ctx = PolicyContext(
        mac="F8:ED:FC:F6:3C:3E",
        endpoint=EndpointSummary(
            mac="F8:ED:FC:F6:3C:3E",
            name="F8:ED:FC:F6:3C:3E",
            ip_address="10.89.26.77",
            identity_group="Campus_TEST_GROUP",
            profile="HP-JetDirect-Printer",
            static_group_assignment=True,
        ),
        active_session=SessionSummary(username="host/printer", nas_ip="10.89.0.1", state="STARTED"),
        security_group="Printers",
    )
    text = _narrative(ctx)
    assert "HP-JetDirect-Printer" in text
    assert "Campus_TEST_GROUP" in text
    assert "statically grouped" in text
    assert "SGT: Printers" in text


def test_narrative_endpoint_not_found():
    ctx = PolicyContext(mac="AA:BB:CC:DD:EE:FF")
    ctx.notes.append("endpoint lookup failed: NotFoundError")
    text = _narrative(ctx)
    assert "not found" in text.lower()
