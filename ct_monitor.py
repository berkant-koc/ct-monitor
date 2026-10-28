#!/usr/bin/env python3
"""
Certificate Transparency monitor for self-hosted domains.

Polls crt.sh and SSLMate Cert Spotter for the configured domains, diffs
against the locally cached known certificates (crt.sh IDs plus serial
numbers), and dispatches an alert when a previously unseen cert appears in
any public CT log. Catches silently issued phishing certs or registrar/CA
compromise before the cert goes live. Two sources keep the watch running
when one of them is down; a certificate seen by both alerts once.

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
    CT_MONITOR_SOURCES     comma-separated, default "crtsh,certspotter"

Typical systemd-timer line:
    OnCalendar=*-*-* 08,20:00:00
"""
from __future__ import annotations

import base64
import http.client
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
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?{}"
DEFAULT_STATE = Path.home() / ".ct-monitor-state.json"
DEFAULT_TIMEOUT = 30
DEFAULT_SOURCES = "crtsh,certspotter"
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


def fetch_certspotter(domain: str, timeout: int) -> list[dict]:
    """Fetch the unexpired certs for `domain` and its subdomains from Cert Spotter.

    The unauthenticated API allows about 10 subdomain queries per hour, plenty
    for a few domains polled twice a day.
    """
    url = CERTSPOTTER_URL.format(urllib.parse.urlencode([
        ("domain", domain),
        ("include_subdomains", "true"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
        ("expand", "cert_der"),
    ]))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def canonical_serial(value) -> str | None:
    """Serial number as lowercase hex without leading zeros, so crt.sh and
    Cert Spotter agree. Accepts the older "<issuer_ca_id>:<serial>" keys."""
    if not value:
        return None
    try:
        return format(int(str(value).split(":")[-1], 16), "x")
    except ValueError:
        return None


def _der_length(der: bytes, i: int) -> tuple[int, int]:
    first = der[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    return int.from_bytes(der[i + 1:i + 1 + n], "big"), i + 1 + n


def der_serial(cert_der_b64: str | None) -> str | None:
    """Serial number of a base64 DER certificate (stdlib only, no ASN.1 library)."""
    if not cert_der_b64:
        return None
    try:
        der = base64.b64decode(cert_der_b64)
        if der[0] != 0x30:                      # Certificate SEQUENCE
            return None
        _, i = _der_length(der, 1)
        if der[i] != 0x30:                      # tbsCertificate SEQUENCE
            return None
        _, i = _der_length(der, i + 1)
        if der[i] == 0xA0:                      # [0] EXPLICIT version
            length, j = _der_length(der, i + 1)
            i = j + length
        if der[i] != 0x02:                      # serialNumber INTEGER
            return None
        length, j = _der_length(der, i + 1)
        return format(int.from_bytes(der[j:j + length], "big"), "x")
    except (ValueError, IndexError):
        return None


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


def normalise_certspotter(entry: dict, serial: str | None) -> dict:
    """Cert Spotter issuance in the same shape as normalise(), linked to crt.sh by SHA-256."""
    names = entry.get("dns_names") or []
    issuer = entry.get("issuer") or {}
    sha256 = entry.get("cert_sha256")
    return {
        "id": None,
        "issuer_ca_id": None,
        "issuer_name": issuer.get("name", "") if isinstance(issuer, dict) else "",
        "common_name": names[0] if names else "",
        "name_value": "\n".join(names),
        "not_before": entry.get("not_before"),
        "not_after": entry.get("not_after"),
        "serial": serial,
        "link": f"https://crt.sh/?sha256={sha256}" if sha256 else "",
        "source": "Cert Spotter",
    }


def observations(source: str, raw: list[dict]) -> list[tuple[int | None, str | None, dict]]:
    """(crt.sh ID or None, certificate key, alert entry) for every usable record of one source."""
    out = []
    if source == "crtsh":
        for entry in raw:
            cid = entry.get("id")
            if cid is None:
                continue
            out.append((cid, canonical_serial(entry.get("serial_number")), normalise(entry)))
    else:
        for entry in raw:
            serial = der_serial(entry.get("cert_der"))
            key = serial or (f"sha256:{entry['cert_sha256']}" if entry.get("cert_sha256") else None)
            if key:
                out.append((None, key, normalise_certspotter(entry, serial)))
    return out


SOURCES = {
    "crtsh": ("crt.sh", lambda domain, timeout: fetch_crt(domain, timeout)),
    "certspotter": ("Cert Spotter", lambda domain, timeout: fetch_certspotter(domain, timeout)),
}


def domain_state(raw) -> tuple[set[int], set[str] | None, set[str]]:
    """Known crt.sh IDs, certificate keys and already seeded sources of one domain.

    Accepts the current {"ids", "serials", "sources"} form, the form without
    "sources" (crt.sh only, keys "<issuer_ca_id>:<serial>"), and the oldest plain
    list of crt.sh IDs, for which the certificate keys are unknown (None).
    """
    if isinstance(raw, dict):
        keys = {canonical_serial(k) if not str(k).startswith("sha256:") else k for k in raw.get("serials", [])}
        return set(raw.get("ids", [])), keys - {None}, set(raw.get("sources", ["crtsh"]))
    if isinstance(raw, list):
        return set(raw), None, {"crtsh"}
    return set(), set(), set()


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
            link = c.get("link") or f"https://crt.sh/?id={c['id']}"
            lines.append(f"  ID:        {link}")
            lines.append(f"  Source:    {c.get('source', 'crt.sh')}")
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
    wanted = [s.strip() for s in os.environ.get("CT_MONITOR_SOURCES", DEFAULT_SOURCES).split(",") if s.strip()]
    for s in wanted:
        if s not in SOURCES:
            print(f"warning: unknown source {s!r} ignored", file=sys.stderr)
    sources = [s for s in SOURCES if s in wanted]  # crt.sh first, so its IDs win in the alert

    state = load_state(state_path)
    new_state: dict = {}
    new_alerts: dict[str, list[dict]] = {}

    for domain in domains:
        results: dict[str, list[dict]] = {}
        for name in sources:
            label, fetch = SOURCES[name]
            try:
                results[name] = fetch(domain, timeout)
            except urllib.error.HTTPError as e:
                print(f"[{domain}] {label} HTTP {e.code}, skipping", file=sys.stderr)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                print(f"[{domain}] {label} network error: {e}", file=sys.stderr)
            except (ValueError, http.client.HTTPException) as e:
                # An HTML error page with status 200 or a cut-off body: skip
                # this source for the domain instead of failing the whole run.
                print(f"[{domain}] unusable {label} response ({type(e).__name__}), skipping", file=sys.stderr)
        if not results:
            if domain in state:
                new_state[domain] = state[domain]
            continue

        known_ids, known_keys, seeded = domain_state(state.get(domain))
        # Every crt.sh entry we already know by ID tells us its certificate's
        # serial. Record those first, so a second ID of the same certificate is
        # never new, whatever order crt.sh lists them in. This also fills in the
        # serials of ID-only state written while crt.sh was unreachable.
        known_keys = (known_keys or set()) | ({canonical_serial(e.get("serial_number"))
                                               for e in results.get("crtsh", [])
                                               if e.get("id") in known_ids} - {None})
        ids, keys = set(known_ids), set(known_keys)
        domain_new: list[dict] = []

        for name, raw_entries in results.items():
            # A source seen for the first time on a known domain is recorded
            # silently, like a new domain, so adding it never floods the inbox.
            alerting = domain in state and name in seeded
            for cid, key, alert_entry in observations(name, raw_entries):
                # crt.sh lists a precertificate and its final certificate under two
                # IDs and may index a certificate again later; both sources report
                # the same certificates. A known serial is not a new certificate.
                is_new = (cid is None or cid not in ids) and (key is None or key not in keys)
                if is_new and alerting:
                    domain_new.append(alert_entry)
                if cid is not None:
                    ids.add(cid)
                if key:
                    keys.add(key)

        # Never forget: a source sometimes returns an incomplete list, and an
        # entry dropped from the state would alert again when it reappears.
        new_state[domain] = {"ids": sorted(ids), "serials": sorted(keys),
                             "sources": sorted(seeded | set(results))}
        if domain_new:
            new_alerts[domain] = domain_new
            print(f"[{domain}] {len(domain_new)} new", file=sys.stderr)

    save_state(state_path, new_state)

    if new_alerts:
        dispatch_alert(build_alert(new_alerts), alert_cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
