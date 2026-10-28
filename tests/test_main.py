"""main(): per-domain and per-source seeding, alerting on known domains, state carry-over on fetch errors,
the October 2026 false alarms (incomplete crt.sh lists, two crt.sh IDs for one cert), and the second
source (Cert Spotter) deduplicated against crt.sh by serial number."""
import json
import urllib.error
from pathlib import Path

import ct_monitor

# koc-rv.de, Let's Encrypt cert of 2026-09-15: crt.sh listed it as 29970679251 and later 30034611347.
KOC_SERIAL = "06089c2395cb19f5d987c502db34f3a14801"
KOC_DER = (Path(__file__).parent / "data" / "koc-rv.de_2026-09-15.der.b64").read_text().strip()
OFF = urllib.error.URLError("source disabled in this test")


def _entry(cid, name="example.com", serial=None, issuer=1):
    return {"id": cid, "common_name": name, "name_value": name, "issuer_name": "Let's Encrypt",
            "issuer_ca_id": issuer, "serial_number": f"{cid:x}" if serial is None else serial}


def _cs(serial_hex=None, name="example.com", der=None, sha="ab" * 32):
    """Cert Spotter issuance; the serial goes in through a minimal DER certificate unless `der` is given."""
    if der is None:
        serial = bytes.fromhex(serial_hex if len(serial_hex) % 2 == 0 else "0" + serial_hex)
        integer = b"\x02" + bytes([len(serial)]) + serial
        tbs = b"\x30" + bytes([len(integer)]) + integer
        cert = b"\x30" + bytes([len(tbs)]) + tbs
        import base64
        der = base64.b64encode(cert).decode()
    return {"id": "cs1", "dns_names": [name], "issuer": {"name": "C=US, O=Let's Encrypt, CN=R13"},
            "not_before": "2026-11-01T00:00:00Z", "not_after": "2027-01-30T00:00:00Z",
            "cert_der": der, "cert_sha256": sha}


def _key(serial):
    return ct_monitor.canonical_serial(serial)


def _run(monkeypatch, tmp_path, domains, state, certs_by_domain, cs_by_domain=None):
    state_path = tmp_path / "state.json"
    if state is not None:
        state_path.write_text(json.dumps(state))
    alerts = []

    def fake(table):
        def fetch(domain, timeout):
            result = (table or {}).get(domain, OFF)
            if isinstance(result, Exception):
                raise result
            return result
        return fetch

    monkeypatch.setenv("CT_MONITOR_DOMAINS", domains)
    monkeypatch.setenv("CT_MONITOR_STATE", str(state_path))
    monkeypatch.delenv("CT_MONITOR_ALERT_CMD", raising=False)
    monkeypatch.delenv("CT_MONITOR_SOURCES", raising=False)
    monkeypatch.setattr(ct_monitor, "fetch_crt", fake(certs_by_domain))
    monkeypatch.setattr(ct_monitor, "fetch_certspotter", fake(cs_by_domain))
    monkeypatch.setattr(ct_monitor, "dispatch_alert", lambda body, cmd: alerts.append(body))
    assert ct_monitor.main() == 0
    return json.loads(state_path.read_text()), alerts


def _st(ids, serials, sources=("crtsh",)):
    return {"ids": sorted(ids), "serials": sorted(_key(s) for s in serials), "sources": sorted(sources)}


def test_first_run_seeds_without_alert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", None, {"a.com": [_entry(1), _entry(2)]})
    assert state == {"a.com": _st([1, 2], ["1", "2"])}
    assert alerts == []


def test_new_domain_is_seeded_silently(monkeypatch, tmp_path):
    known_a = _st([1], ["1"])
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": known_a},
                         {"a.com": [_entry(1)], "b.com": [_entry(5, "b.com"), _entry(6, "b.com")]})
    assert state == {"a.com": known_a, "b.com": _st([5, 6], ["5", "6"])}
    assert alerts == []


def test_known_domain_alerts_on_new_cert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": _st([1], ["1"])},
                         {"a.com": [_entry(1), _entry(2)], "b.com": [_entry(5, "b.com")]})
    assert state["a.com"] == _st([1, 2], ["1", "2"])
    assert len(alerts) == 1 and "a.com" in alerts[0] and "b.com" not in alerts[0]


def test_fetch_error_keeps_previous_state(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": [1, 2]},
                         {"a.com": urllib.error.URLError("down")})
    assert state == {"a.com": [1, 2]}
    assert alerts == []


def test_unusable_crtsh_response_skips_domain_and_keeps_state(monkeypatch, tmp_path):
    known = _st([1], ["1"])
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": known, "b.com": [5]},
                         {"a.com": json.JSONDecodeError("Expecting value", "<html>", 0),
                          "b.com": [_entry(5, "b.com")]})
    assert state["a.com"] == known
    assert state["b.com"] == _st([5], ["5"])
    assert alerts == []


def test_incomplete_crtsh_list_does_not_forget_or_realert(monkeypatch, tmp_path):
    known = _st([1, 2], ["1", "2"])
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": known}, {"a.com": [_entry(1)]})
    assert state["a.com"] == known and alerts == []
    state, alerts = _run(monkeypatch, tmp_path, "a.com", state, {"a.com": [_entry(1), _entry(2)]})
    assert state["a.com"] == known and alerts == []


def test_second_crtsh_id_for_known_certificate_is_not_new(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", {"koc-rv.de": _st([29970679251], [KOC_SERIAL])},
                         {"koc-rv.de": [_entry(29970679251, serial=KOC_SERIAL),
                                        _entry(30034611347, serial=KOC_SERIAL)]})
    assert state["koc-rv.de"] == _st([29970679251, 30034611347], [KOC_SERIAL])
    assert alerts == []


def test_legacy_state_is_migrated_without_alert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", {"koc-rv.de": [29970679251]},
                         {"koc-rv.de": [_entry(29970679251, serial=KOC_SERIAL),
                                        _entry(30034611347, serial=KOC_SERIAL.upper())]})
    assert state["koc-rv.de"] == _st([29970679251, 30034611347], [KOC_SERIAL])
    assert alerts == []


def test_issuer_prefixed_keys_of_pr2_are_migrated(monkeypatch, tmp_path):
    old = {"ids": [29970679251], "serials": [f"432477:{KOC_SERIAL}"]}
    state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", {"koc-rv.de": old},
                         {"koc-rv.de": [_entry(30034611347, serial=KOC_SERIAL)]})
    assert state["koc-rv.de"] == _st([29970679251, 30034611347], [KOC_SERIAL])
    assert alerts == []


def test_new_certificate_with_two_crtsh_entries_alerts_once(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": _st([1], ["1"])},
                         {"a.com": [_entry(1), _entry(10, serial="aa"), _entry(11, serial="aa")]})
    assert len(alerts) == 1
    assert "id=10" in alerts[0] and "id=11" not in alerts[0]
    assert state["a.com"] == _st([1, 10, 11], ["1", "aa"])


def test_entry_without_serial_falls_back_to_crtsh_id(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": {"ids": [1], "serials": []}},
                         {"a.com": [_entry(1, serial=""), _entry(2, serial="")]})
    assert len(alerts) == 1 and "id=2" in alerts[0]
    assert state["a.com"] == {"ids": [1, 2], "serials": [], "sources": ["crtsh"]}


def test_koc_rv_october_2026_sequence_stays_silent(monkeypatch, tmp_path):
    """Replays the real runs: seed 22.10, crt.sh drops the entry 24.10, back 25.10, second ID 27.10."""
    other = [_entry(i, "koc-rv.de") for i in (101, 102, 103, 104, 105, 106)]
    cert = _entry(29970679251, "koc-rv.de", serial=KOC_SERIAL)
    twin = _entry(30034611347, "koc-rv.de", serial=KOC_SERIAL)
    state = {"koc-rv.de": [e["id"] for e in other] + [29970679251]}  # old ID-list format
    for response in (other, other + [cert], other + [cert, twin]):
        state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", state, {"koc-rv.de": response})
        assert alerts == []
    assert 29970679251 in state["koc-rv.de"]["ids"] and 30034611347 in state["koc-rv.de"]["ids"]


# --- second source: Cert Spotter ---------------------------------------------------------------------

def test_der_serial_reads_the_real_koc_rv_certificate():
    assert ct_monitor.der_serial(KOC_DER) == _key(KOC_SERIAL)
    assert ct_monitor.der_serial("not base64!") is None
    assert ct_monitor.der_serial(None) is None


def test_certspotter_is_seeded_silently_then_alerts_new_certs(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": _st([1], ["1"])},
                         {"a.com": urllib.error.HTTPError("u", 502, "Bad Gateway", {}, None)},
                         {"a.com": [_cs("1"), _cs("77")]})
    assert alerts == []                                   # first Cert Spotter run on a known domain
    assert state["a.com"] == _st([1], ["1", "77"], ("certspotter", "crtsh"))
    state, alerts = _run(monkeypatch, tmp_path, "a.com", state, None,
                         {"a.com": [_cs("1"), _cs("77"), _cs("88", sha="cd" * 32)]})
    assert len(alerts) == 1 and "Cert Spotter" in alerts[0]
    assert f"https://crt.sh/?sha256={'cd' * 32}" in alerts[0] and "88" in alerts[0]


def test_certspotter_covers_a_crtsh_outage(monkeypatch, tmp_path):
    known = _st([1], ["1"], ("certspotter", "crtsh"))
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": known},
                         {"a.com": urllib.error.HTTPError("u", 502, "Bad Gateway", {}, None)},
                         {"a.com": [_cs("1"), _cs("99")]})
    assert len(alerts) == 1 and "99" in alerts[0]
    assert state["a.com"] == _st([1], ["1", "99"], ("certspotter", "crtsh"))


def test_certificate_seen_by_both_sources_alerts_once(monkeypatch, tmp_path):
    known = _st([1], ["1"], ("certspotter", "crtsh"))
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": known},
                         {"a.com": [_entry(1), _entry(10, serial="0bad")]},
                         {"a.com": [_cs("1"), _cs("bad")]})
    assert len(alerts) == 1
    assert "id=10" in alerts[0] and "Cert Spotter" not in alerts[0]
    assert state["a.com"] == _st([1, 10], ["1", "bad"], ("certspotter", "crtsh"))


def test_real_koc_rv_cert_from_both_sources_is_one_certificate(monkeypatch, tmp_path):
    known = _st([29970679251], [KOC_SERIAL], ("certspotter", "crtsh"))
    state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", {"koc-rv.de": known},
                         {"koc-rv.de": [_entry(29970679251, serial=KOC_SERIAL)]},
                         {"koc-rv.de": [_cs(der=KOC_DER, name="koc-rv.de")]})
    assert alerts == []
    assert state["koc-rv.de"]["serials"] == [_key(KOC_SERIAL)]


def test_both_sources_down_keeps_state(monkeypatch, tmp_path):
    known = _st([1], ["1"], ("certspotter", "crtsh"))
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": known},
                         {"a.com": urllib.error.URLError("down")}, {"a.com": TimeoutError("slow")})
    assert state["a.com"] == known and alerts == []


def test_sources_can_be_limited(monkeypatch, tmp_path):
    monkeypatch.setenv("CT_MONITOR_SOURCES", "crtsh")
    calls = []
    monkeypatch.setattr(ct_monitor, "fetch_certspotter", lambda d, t: calls.append(d) or [])
    state_path = tmp_path / "state.json"
    monkeypatch.setenv("CT_MONITOR_DOMAINS", "a.com")
    monkeypatch.setenv("CT_MONITOR_STATE", str(state_path))
    monkeypatch.delenv("CT_MONITOR_ALERT_CMD", raising=False)
    monkeypatch.setattr(ct_monitor, "fetch_crt", lambda d, t: [_entry(1)])
    assert ct_monitor.main() == 0
    assert calls == []
    assert json.loads(state_path.read_text())["a.com"]["sources"] == ["crtsh"]
