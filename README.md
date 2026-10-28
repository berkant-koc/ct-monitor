# ct-monitor

[![test](https://github.com/berkant-koc/ct-monitor/actions/workflows/test.yml/badge.svg)](https://github.com/berkant-koc/ct-monitor/actions/workflows/test.yml)

Polls [crt.sh](https://crt.sh) and [Cert Spotter](https://sslmate.com/certspotter/)
for new TLS certificates issued for a list of domains you own, diffs against
a local state file, and alerts you on any previously-unseen certificate
before it appears in the wild. Two sources keep the watch going when one is
down or lags behind; a certificate both report alerts once.

Catches:

- **Phishing certs** silently issued for `paypal-secure-yourdomain.com`
- **Registrar account compromise** issuing valid certs you did not request
- **CA mis-issuance** showing up in Certificate Transparency logs

Idempotent, dependency-free (stdlib only), built for `cron` or
`systemd-timer` use. Exit code 0, no stdout when nothing is new.

## Quickstart

```bash
git clone https://github.com/YOU/ct-monitor.git
cd ct-monitor

# First run — seeds the state file, NO alerts on initial run
CT_MONITOR_DOMAINS=example.com,example.org python3 ct_monitor.py

# Subsequent runs — alerts on any new cert
CT_MONITOR_DOMAINS=example.com,example.org \
CT_MONITOR_ALERT_CMD="sendmail you@example.com" \
  python3 ct_monitor.py
```

## Configuration (env vars only)

| Variable | Default | Description |
|---|---|---|
| `CT_MONITOR_DOMAINS` | *(required)* | Comma-separated apex domains |
| `CT_MONITOR_STATE` | `~/.ct-monitor-state.json` | Path to JSON state file |
| `CT_MONITOR_ALERT_CMD` | *(stdout)* | Shell command that receives the alert body on stdin |
| `CT_MONITOR_HTTP_TIMEOUT` | `30` | Seconds per HTTP request |
| `CT_MONITOR_SOURCES` | `crtsh,certspotter` | Which CT sources to query |

Cert Spotter's free API allows about 10 subdomain queries per hour without
an account, enough for a handful of domains polled twice a day.

## systemd-timer example

`~/.config/systemd/user/ct-monitor.service`:

```ini
[Unit]
Description=Certificate Transparency monitor

[Service]
Type=oneshot
Environment="CT_MONITOR_DOMAINS=example.com,example.org"
Environment="CT_MONITOR_ALERT_CMD=mail -s 'CT alert' you@example.com"
ExecStart=/usr/bin/python3 %h/ct-monitor/ct_monitor.py
```

`~/.config/systemd/user/ct-monitor.timer`:

```ini
[Unit]
Description=Run ct-monitor twice daily

[Timer]
OnCalendar=*-*-* 08,20:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Then:

```bash
systemctl --user daemon-reload
systemctl --user enable --now ct-monitor.timer
```

## State file

Stores per domain the crt.sh IDs, the serial numbers of the certificates
already seen, and which sources have been seeded. Initial run seeds the
file with no alert (otherwise you would get a flood for every existing
cert); a source seen for the first time on a known domain is seeded the
same way. Loss of the file resets the seed and triggers a full re-alert on
next run.

Known entries are never dropped, so an incomplete response cannot make an
old certificate alert again when it reappears. A second crt.sh entry for a
known certificate (precertificate vs. final certificate, or a later
re-index) does not alert, and neither does the same certificate reported
by both sources. State files from older versions (plain ID lists or
issuer-prefixed serials) are migrated silently on the next run.

## Output sample (alert body)

```
CT-monitor alert: 1 new certificate(s) detected

If you did not provision these certificates, this may indicate
a phishing setup, a registrar account compromise, or a mis-issuance
by a CA. Investigate before the certs are observed in the wild.

=== example.com (1 new) ===
  ID:        https://crt.sh/?id=12345678
  Issuer:    C=US, O=Let's Encrypt, CN=R3
  CN:        api.example.com
  SAN:       api.example.com, www.api.example.com
  Valid:     2026-05-01T00:00:00 -> 2026-07-30T23:59:59
  Serial:    0a1b2c3d...
```

## Why crt.sh

[crt.sh](https://crt.sh) is the Sectigo-operated CT-log search tool,
de-facto industry standard for cert transparency review. Faster than
running your own CT-log indexer.

## License

MIT. See `LICENSE`.
