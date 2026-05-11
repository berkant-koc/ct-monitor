#!/usr/bin/env python3
"""
Certificate Transparency monitor for self-hosted domains.

Polls crt.sh for the configured domains, diffs against locally cached
known-cert IDs, and dispatches an alert when a previously unseen cert
appears in any public CT log. Catches silently issued phishing certs
or registrar/CA compromise before the cert goes live.

Cron / systemd-timer friendly: idempotent, exits 0, no stdout when
nothing is new.

Configuration is environment-only:

    CT_MONITOR_DOMAINS     comma-separated list of apex domains
                           (e.g. "example.com,example.org")
    CT_MONITOR_STATE       path to JSON state file
                           (default: ~/.ct-monitor-state.json)
    CT_MONITOR_ALERT_CMD   shell command that receives the alert body on
                           stdin. Examples:
                             sendmail you@example.com
                             /usr/local/bin/notify
                             python3 mail.py you@example.com "CT alert"
                           Omit to print alerts to stdout instead.
    CT_MONITOR_HTTP_TIMEOUT  seconds, default 30

Typical systemd-timer line:
    OnCalendar=*-*-* 08,20:00:00
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CRT_SH_URL = "https://crt.sh/?{}"
DEFAULT_STATE = Path.home() / ".ct-monitor-state.json"
DEFAULT_TIMEOUT = 30
USER_AGENT = "ct-monitor/1.0 (+https://github.com/)"


def fetch_crt(domain: str, timeout: int) -> list[dict]:
    """Fetch all certs ever logged for `*.domain` from crt.sh."""
    url = CRT_SH_URL.format(urllib.parse.urlencode({
        "q": "%." + domain,
        "output": "json",
    }))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def normalise(entry: dict) -> dict:
    """Keep only the fields a human reviewer needs in the alert mail."""
    return {
        "id": entry.get("id"),
        "issuer_ca_id": entry.get("issuer_ca_id"),
        "issuer_name": entry.get("issuer_name", ""),
        "common_name": entry.get("common_name", ""),
        "name_value": entry.get("name_value", ""),
        "not_before": entry.get("not_before"),
        "not_after": entry.get("not_after"),
        "serial": entry.get("serial_number"),
    }


def load_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True))
    try:
        path.chmod(0o600)
    except OSError:
        pass


def build_alert(new_by_domain: dict[str, list[dict]]) -> str:
    total = sum(len(v) for v in new_by_domain.values())
    lines = [
        f"CT-monitor alert: {total} new certificate(s) detected",
        "",
        "If you did not provision these certificates, this may indicate",
        "a phishing setup, a registrar account compromise, or a mis-issuance",
        "by a CA. Investigate before the certs are observed in the wild.",
        "",
    ]
    for domain, certs in new_by_domain.items():
        lines.append(f"=== {domain} ({len(certs)} new) ===")
        for c in certs:
            lines.append(f"  ID:        https://crt.sh/?id={c['id']}")
            lines.append(f"  Issuer:    {c['issuer_name']}")
            lines.append(f"  CN:        {c['common_name']}")
            san = c["name_value"].replace("\n", ", ")
            lines.append(f"  SAN:       {san}")
            lines.append(f"  Valid:     {c['not_before']} -> {c['not_after']}")
            lines.append(f"  Serial:    {c['serial']}")
            lines.append("")
        lines.append("")
    lines += [
        "---",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
    ]
    return "\n".join(lines)


def dispatch_alert(body: str, alert_cmd: str | None) -> None:
    if not alert_cmd:
        print(body)
        return
    result = subprocess.run(
        alert_cmd,
        shell=True,
        input=body,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            f"alert command failed (exit {result.returncode}): {result.stderr}",
            file=sys.stderr,
        )


def main() -> int:
    raw = os.environ.get("CT_MONITOR_DOMAINS", "").strip()
    if not raw:
        print("error: set CT_MONITOR_DOMAINS=example.com,example.org", file=sys.stderr)
        return 2
    domains = [d.strip() for d in raw.split(",") if d.strip()]

    state_path = Path(os.environ.get("CT_MONITOR_STATE", DEFAULT_STATE))
    alert_cmd = os.environ.get("CT_MONITOR_ALERT_CMD")
    timeout = int(os.environ.get("CT_MONITOR_HTTP_TIMEOUT", DEFAULT_TIMEOUT))

    state = load_state(state_path)
    seeded = bool(state)
    new_state: dict[str, list[int]] = {}
    new_alerts: dict[str, list[dict]] = {}

    for domain in domains:
        try:
            certs = fetch_crt(domain, timeout)
        except urllib.error.HTTPError as e:
            print(f"[{domain}] crt.sh HTTP {e.code}, skipping", file=sys.stderr)
            continue
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"[{domain}] network error: {e}", file=sys.stderr)
            continue

        seen_ids: set[int] = set()
        domain_new: list[dict] = []
        known = set(state.get(domain, []))

        for entry in certs:
            cid = entry.get("id")
            if cid is None:
                continue
            seen_ids.add(cid)
            if cid not in known:
                domain_new.append(normalise(entry))

        new_state[domain] = sorted(seen_ids)
        if domain_new and seeded:
            new_alerts[domain] = domain_new
            print(f"[{domain}] {len(domain_new)} new", file=sys.stderr)

    save_state(state_path, new_state)

    if new_alerts:
        dispatch_alert(build_alert(new_alerts), alert_cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
