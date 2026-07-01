""" 
Alert System

Layer 3 of the Cyber Defense Arsenal.

Job: take a detection from the Pattern Engine and (a) persist it so the 
dashboard can show it, and (b) notify a human through Telegram and/or 
email if it meets the configured severity threshold.
"""

import json 
import os 
import smtplib 
from email.mime.text import MIMEText

import requests

from pattern_engine import PatternEngine


class AlertSystem: 
    def __init__(self, config): 
        self.config = config 
        self.detections_file = config["storage"]["detections_file"] 
        os.makedirs(os.path.dirname(self.detections_file), exist_ok=True)

    def dispatch(self, detection):
        self._persist(detection)

        min_severity = self.config["alert_thresholds"]["min_severity_to_alert"]
        if not PatternEngine.meets_threshold(detection["severity"], min_severity):
            return

        message = self._format_message(detection)

        if self.config["telegram"]["enabled"]:
            self._send_telegram(message)

        if self.config["email"]["enabled"]:
            self._send_email(
                subject=f"[{detection['severity'].upper()}] {detection['description']}",
                body=message,
            )

        print(f"[ALERT] {message}")

    def _format_message(self, d):
        ip_line = f"\nSource IP: {d['source_ip']}" if d.get("source_ip") else ""
        return (
            f"Cyber Defense Arsenal — {d['severity'].upper()} severity\n"
            f"{d['description']}\n"
            f"Pattern: {d['pattern']} (MITRE {d['mitre_id']} – {d['mitre_name']})"
            f"{ip_line}\n"
            f"Time: {d['timestamp']}\n"
            f"Matched: {d['matched_text']}"
        )

    def _persist(self, detection):
        with open(self.detections_file, "a") as f:
            f.write(json.dumps(detection) + "\n")

    def _send_telegram(self, message):
        token = self.config["telegram"]["bot_token"]
        chat_id = self.config["telegram"]["chat_id"]
        if "YOUR_BOT_TOKEN" in token or "YOUR_CHAT_ID" in str(chat_id):
            print("[AlertSystem] Telegram enabled but not configured — skipping send.")
            return
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            requests.post(url, data={"chat_id": chat_id, "text": message}, timeout=10)
        except requests.RequestException as e:
            print(f"[AlertSystem] Telegram send failed: {e}")

    def _send_email(self, subject, body):
        cfg = self.config["email"]
        if not cfg["username"] or not cfg["to_address"]:
            print("[AlertSystem] Email enabled but not configured — skipping send.")
            return
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = cfg["username"]
            msg["To"] = cfg["to_address"]
            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.send_message(msg)
        except Exception as e:
            print(f"[AlertSystem] Email send failed: {e}")
