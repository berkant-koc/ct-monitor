#!/usr/bin/env python3
"""Mail-Alert-Wrapper für ct_monitor.

Liest Alert-Body von stdin und versendet als Mail via STARTTLS-SMTP.
Konfiguration ausschließlich über ENV-Variablen (GH-Action-Secrets):

    SMTP_HOST       (z.B. mail.1984.is)
    SMTP_PORT       (z.B. 587)
    SMTP_USER       (z.B. me@berkoc.com)
    SMTP_PASS       SMTP-Passwort
    SMTP_FROM       Absender (default: SMTP_USER)
    ALERT_TO        Empfänger
    ALERT_SUBJECT   default: "CT-Monitor: new cert detected"
"""
import os
import smtplib
import ssl
import sys
from email.message import EmailMessage


def main() -> int:
    body = sys.stdin.read()
    if not body.strip():
        print("mail_alert: empty body, nothing to send", file=sys.stderr)
        return 0

    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    password = os.environ["SMTP_PASS"]
    sender = os.environ.get("SMTP_FROM", user)
    recipient = os.environ["ALERT_TO"]
    subject = os.environ.get("ALERT_SUBJECT", "CT-Monitor: new cert detected")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.ehlo()
        s.starttls(context=ctx)
        s.login(user, password)
        s.send_message(msg)

    print(f"mail_alert: sent to {recipient}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
