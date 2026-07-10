from cisco_ise_mcp.redaction import MASK, redact


def test_masks_sensitive_keys_nested():
    data = {
        "username": "svc",
        "password": "hunter2",
        "nested": {"api_key": "abc", "authorization": "Bearer xyz", "ok": 1},
        "list": [{"token": "t"}, {"mac": "AA:BB"}],
    }
    out = redact(data)
    assert out["username"] == "svc"
    assert out["password"] == MASK
    assert out["nested"]["api_key"] == MASK
    assert out["nested"]["authorization"] == MASK
    assert out["nested"]["ok"] == 1
    assert out["list"][0]["token"] == MASK
    assert out["list"][1]["mac"] == "AA:BB"


def test_redact_is_nonmutating():
    data = {"password": "x"}
    redact(data)
    assert data["password"] == "x"
