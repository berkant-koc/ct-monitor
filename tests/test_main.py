"""main(): per-domain seeding, alerting on known domains, state carry-over on fetch errors,
and the October 2026 false alarms (incomplete crt.sh lists, two crt.sh IDs for one cert)."""
import json
import urllib.error

import ct_monitor

# koc-rv.de, Let's Encrypt cert of 2026-09-15: crt.sh listed it as 29970679251 and later 30034611347.
KOC_SERIAL = "06089c2395cb19f5d987c502db34f3a14801"


def _entry(cid, name="example.com", serial=None, issuer=1):
    return {"id": cid, "common_name": name, "name_value": name, "issuer_name": "Let's Encrypt",
            "issuer_ca_id": issuer, "serial_number": f"{cid:x}" if serial is None else serial}


def _key(serial, issuer=1):
    return f"{issuer}:{serial}"


def _run(monkeypatch, tmp_path, domains, state, certs_by_domain):
    state_path = tmp_path / "state.json"
    if state is not None:
        state_path.write_text(json.dumps(state))
    alerts = []

    def fake_fetch(domain, timeout):
        result = certs_by_domain[domain]
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setenv("CT_MONITOR_DOMAINS", domains)
    monkeypatch.setenv("CT_MONITOR_STATE", str(state_path))
    monkeypatch.delenv("CT_MONITOR_ALERT_CMD", raising=False)
    monkeypatch.setattr(ct_monitor, "fetch_crt", fake_fetch)
    monkeypatch.setattr(ct_monitor, "dispatch_alert", lambda body, cmd: alerts.append(body))
    assert ct_monitor.main() == 0
    return json.loads(state_path.read_text()), alerts


def test_first_run_seeds_without_alert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", None, {"a.com": [_entry(1), _entry(2)]})
    assert state == {"a.com": {"ids": [1, 2], "serials": [_key("1"), _key("2")]}}
    assert alerts == []


def test_new_domain_is_seeded_silently(monkeypatch, tmp_path):
    known_a = {"ids": [1], "serials": [_key("1")]}
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": known_a},
                         {"a.com": [_entry(1)], "b.com": [_entry(5, "b.com"), _entry(6, "b.com")]})
    assert state == {"a.com": known_a, "b.com": {"ids": [5, 6], "serials": [_key("5"), _key("6")]}}
    assert alerts == []


def test_known_domain_alerts_on_new_cert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": {"ids": [1], "serials": [_key("1")]}},
                         {"a.com": [_entry(1), _entry(2)], "b.com": [_entry(5, "b.com")]})
    assert state["a.com"] == {"ids": [1, 2], "serials": [_key("1"), _key("2")]}
    assert len(alerts) == 1 and "a.com" in alerts[0] and "b.com" not in alerts[0]


def test_fetch_error_keeps_previous_state(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": [1, 2]},
                         {"a.com": urllib.error.URLError("down")})
    assert state == {"a.com": [1, 2]}
    assert alerts == []


def test_unusable_crtsh_response_skips_domain_and_keeps_state(monkeypatch, tmp_path):
    known = {"ids": [1], "serials": [_key("1")]}
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": known, "b.com": [5]},
                         {"a.com": json.JSONDecodeError("Expecting value", "<html>", 0),
                          "b.com": [_entry(5, "b.com")]})
    assert state["a.com"] == known
    assert state["b.com"] == {"ids": [5], "serials": [_key("5")]}
    assert alerts == []


def test_incomplete_crtsh_list_does_not_forget_or_realert(monkeypatch, tmp_path):
    known = {"ids": [1, 2], "serials": [_key("1"), _key("2")]}
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": known}, {"a.com": [_entry(1)]})
    assert state["a.com"] == known and alerts == []
    state, alerts = _run(monkeypatch, tmp_path, "a.com", state, {"a.com": [_entry(1), _entry(2)]})
    assert state["a.com"] == known and alerts == []


def test_second_crtsh_id_for_known_certificate_is_not_new(monkeypatch, tmp_path):
    known = {"ids": [29970679251], "serials": [_key(KOC_SERIAL)]}
    state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", {"koc-rv.de": known},
                         {"koc-rv.de": [_entry(29970679251, serial=KOC_SERIAL),
                                        _entry(30034611347, serial=KOC_SERIAL)]})
    assert state["koc-rv.de"] == {"ids": [29970679251, 30034611347], "serials": [_key(KOC_SERIAL)]}
    assert alerts == []


def test_legacy_state_is_migrated_without_alert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", {"koc-rv.de": [29970679251]},
                         {"koc-rv.de": [_entry(29970679251, serial=KOC_SERIAL),
                                        _entry(30034611347, serial=KOC_SERIAL.upper())]})
    assert state["koc-rv.de"] == {"ids": [29970679251, 30034611347], "serials": [_key(KOC_SERIAL)]}
    assert alerts == []


def test_new_certificate_with_two_crtsh_entries_alerts_once(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": {"ids": [1], "serials": [_key("1")]}},
                         {"a.com": [_entry(1), _entry(10, serial="aa"), _entry(11, serial="aa")]})
    assert len(alerts) == 1
    assert "id=10" in alerts[0] and "id=11" not in alerts[0]
    assert state["a.com"] == {"ids": [1, 10, 11], "serials": [_key("1"), _key("aa")]}


def test_entry_without_serial_falls_back_to_crtsh_id(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": {"ids": [1], "serials": []}},
                         {"a.com": [_entry(1, serial=""), _entry(2, serial="")]})
    assert len(alerts) == 1 and "id=2" in alerts[0]
    assert state["a.com"] == {"ids": [1, 2], "serials": []}


def test_koc_rv_october_2026_sequence_stays_silent(monkeypatch, tmp_path):
    """Replays the real runs: seed 22.10, crt.sh drops the entry 24.10, back 25.10, second ID 27.10."""
    other = [_entry(i, "koc-rv.de") for i in (101, 102, 103, 104, 105, 106)]
    cert = _entry(29970679251, "koc-rv.de", serial=KOC_SERIAL)
    twin = _entry(30034611347, "koc-rv.de", serial=KOC_SERIAL)
    seed = {"koc-rv.de": [e["id"] for e in other] + [29970679251]}  # old ID-list format
    state = seed
    for response in (other, other + [cert], other + [cert, twin]):
        state, alerts = _run(monkeypatch, tmp_path, "koc-rv.de", state, {"koc-rv.de": response})
        assert alerts == []
    assert 29970679251 in state["koc-rv.de"]["ids"] and 30034611347 in state["koc-rv.de"]["ids"]
