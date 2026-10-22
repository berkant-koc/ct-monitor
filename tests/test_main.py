"""main(): per-domain seeding, alerting on known domains, state carry-over on fetch errors."""
import json
import urllib.error

import ct_monitor


def _entry(cid, name="example.com"):
    return {"id": cid, "common_name": name, "name_value": name, "issuer_name": "Let's Encrypt"}


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
    assert state == {"a.com": [1, 2]}
    assert alerts == []


def test_new_domain_is_seeded_silently(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": [1]},
                         {"a.com": [_entry(1)], "b.com": [_entry(5, "b.com"), _entry(6, "b.com")]})
    assert state == {"a.com": [1], "b.com": [5, 6]}
    assert alerts == []


def test_known_domain_alerts_on_new_cert(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com,b.com", {"a.com": [1]},
                         {"a.com": [_entry(1), _entry(2)], "b.com": [_entry(5, "b.com")]})
    assert state == {"a.com": [1, 2], "b.com": [5]}
    assert len(alerts) == 1 and "a.com" in alerts[0] and "b.com" not in alerts[0]


def test_fetch_error_keeps_previous_state(monkeypatch, tmp_path):
    state, alerts = _run(monkeypatch, tmp_path, "a.com", {"a.com": [1, 2]},
                         {"a.com": urllib.error.URLError("down")})
    assert state == {"a.com": [1, 2]}
    assert alerts == []
