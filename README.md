# ct-monitor

[![test](https://github.com/berkant-koc/ct-monitor/actions/workflows/test.yml/badge.svg)](https://github.com/berkant-koc/ct-monitor/actions/workflows/test.yml)

Polls [crt.sh](https://crt.sh) for new TLS certificates issued for a list
of domains you own, diffs against a local state file, and alerts you on
any previously-unseen certificate before it appears in the wild.

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
| `CT_MONITOR_HTTP_TIMEOUT` | `30` | Seconds for crt.sh HTTP timeout |

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

Stores a per-domain set of crt.sh cert IDs already seen. Initial run
seeds the file with no alert (otherwise you would get a flood for every
existing cert). Loss of the file resets the seed and triggers a full
re-alert on next run.

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
