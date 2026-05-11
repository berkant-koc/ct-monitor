"""Alert body should be human-readable + carry the crt.sh deep-link per cert."""
from ct_monitor import build_alert


def _cert(cid=1, common="example.com", san="example.com", issuer="Let's Encrypt"):
    return {
        "id": cid,
        "issuer_ca_id": 7,
        "issuer_name": issuer,
        "common_name": common,
        "name_value": san,
        "not_before": "2026-05-01T00:00:00",
        "not_after": "2026-07-30T23:59:59",
        "serial": "deadbeef",
    }


def test_build_alert_has_header_and_per_cert_block():
    body = build_alert({"example.com": [_cert()]})
    assert "CT-monitor alert" in body
    assert "1 new certificate(s) detected" in body
    assert "=== example.com (1 new) ===" in body
    assert "https://crt.sh/?id=1" in body
    assert "Let's Encrypt" in body
    assert "deadbeef" in body


def test_build_alert_counts_across_domains():
    body = build_alert({
        "a.com": [_cert(cid=1), _cert(cid=2)],
        "b.com": [_cert(cid=3)],
    })
    assert "3 new certificate(s) detected" in body
    assert "=== a.com (2 new) ===" in body
    assert "=== b.com (1 new) ===" in body


def test_build_alert_san_newlines_become_comma():
    body = build_alert({
        "example.com": [_cert(san="example.com\nwww.example.com\napi.example.com")]
    })
    assert "example.com, www.example.com, api.example.com" in body
    # And the literal newline should not survive in that field
    assert "example.com\nwww.example.com" not in body
