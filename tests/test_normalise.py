"""normalise() should keep the alert-relevant fields and tolerate missing ones."""
from ct_monitor import normalise


def test_normalise_preserves_known_fields():
    entry = {
        "id": 42,
        "issuer_ca_id": 7,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "serial_number": "01ab02cd",
    }
    out = normalise(entry)
    assert out["id"] == 42
    assert out["issuer_ca_id"] == 7
    assert out["issuer_name"] == "C=US, O=Let's Encrypt, CN=R3"
    assert out["common_name"] == "example.com"
    assert out["name_value"] == "example.com\nwww.example.com"
    assert out["not_before"] == "2026-01-01T00:00:00"
    assert out["not_after"] == "2026-04-01T00:00:00"
    assert out["serial"] == "01ab02cd"


def test_normalise_defaults_when_keys_missing():
    out = normalise({"id": 1})
    assert out["id"] == 1
    assert out["issuer_name"] == ""
    assert out["common_name"] == ""
    assert out["name_value"] == ""
    assert out["serial"] is None  # serial_number missing -> None
    assert out["issuer_ca_id"] is None


def test_normalise_drops_unknown_keys():
    out = normalise({"id": 1, "raw_html": "<garbage>", "extra": True})
    assert "raw_html" not in out
    assert "extra" not in out
