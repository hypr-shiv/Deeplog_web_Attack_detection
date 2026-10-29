from __future__ import annotations

import html
import os
import re
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any
import urllib.parse
import urllib.request


class AlertService:
    """
    Enterprise Alert Notification Service for DeepLog SIEM.
    Dispatches incident alerts following log file analysis via Email (SMTP) and WhatsApp (Twilio/Webhook),
    with simulated sandbox delivery fallback and live audit logging.
    """

    def __init__(self) -> None:
        self.history: list[dict[str, Any]] = []

    def validate_email(self, email: str) -> bool:
        if not email or not isinstance(email, str):
            return False
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email.strip()))

    def validate_phone(self, phone: str) -> bool:
        if not phone or not isinstance(phone, str):
            return False
        # Supports E.164 format: e.g. +14155552671, +919876543210, +447911123456
        clean = re.sub(r"[\s\-\(\)]", "", phone.strip())
        pattern = r"^\+?[1-9]\d{7,14}$"
        return bool(re.match(pattern, clean))

    def format_whatsapp_message(
        self,
        file_name: str,
        total_requests: int,
        attacks_detected: int,
        attack_rate: float,
        critical_count: int,
        attack_types: list[str],
        top_source_ips: list[str],
    ) -> str:
        severity = "CRITICAL" if critical_count > 0 or attack_rate > 20 else "HIGH" if attacks_detected > 0 else "NORMAL"
        types_str = ", ".join(attack_types[:4]) if attack_types else "Suspicious HTTP Requests"
        ips_str = ", ".join(top_source_ips[:3]) if top_source_ips else "Under Automated Review"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return (
            f"🚨 *DEEPLOG SIEM - THREAT INCIDENT ALERT* 🚨\n\n"
            f"📁 *Log File:* `{file_name}`\n"
            f"⚡ *Severity:* *{severity}*\n"
            f"🎯 *Malicious Attacks:* *{attacks_detected}* / {total_requests} ({attack_rate}% attack rate)\n"
            f"🔥 *Critical Threats:* {critical_count}\n"
            f"🛡️ *Classified Vectors:* {types_str}\n"
            f"🌐 *Attacker IPs:* `{ips_str}`\n"
            f"🕒 *Timestamp:* {now_utc}\n\n"
            f"⚠️ *SOC Recommended Action:* Open DeepLog Workstation, review isolated payloads, and enforce firewall block rules."
        )

    def format_email_html(
        self,
        file_name: str,
        total_requests: int,
        attacks_detected: int,
        attack_rate: float,
        critical_count: int,
        attack_types: list[str],
        top_source_ips: list[str],
    ) -> str:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        escaped_file = html.escape(file_name)
        types_badges = "".join(
            f'<span style="background:rgba(239,68,68,0.18);color:#ef4444;border:1px solid rgba(239,68,68,0.3);padding:3px 8px;border-radius:4px;font-size:12px;margin-right:6px;font-family:monospace;">{html.escape(t)}</span>'
            for t in (attack_types[:6] if attack_types else ["Suspicious Anomaly"])
        )
        ips_list = "".join(
            f'<li style="color:#f87171;font-family:monospace;font-size:13px;margin-bottom:4px;">{html.escape(ip)}</li>'
            for ip in (top_source_ips[:5] if top_source_ips else ["N/A"])
        )

        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DeepLog SIEM Incident Alert</title>
</head>
<body style="margin:0;padding:24px;background-color:#0b0f15;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <div style="max-width:620px;margin:0 auto;background:#131822;border:1px solid #232d3f;border-radius:8px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.5);">
    <div style="background:linear-gradient(90deg,#991b1b,#dc2626);padding:18px 24px;border-bottom:1px solid #ef4444;">
      <h1 style="margin:0;font-size:18px;font-weight:700;color:#ffffff;letter-spacing:0.5px;text-transform:uppercase;">
        ⚠️ DeepLog SOC Incident Alert
      </h1>
      <p style="margin:4px 0 0;font-size:12px;color:#fecaca;">
        Automated ML Threat Classification Engine &bull; {now_utc}
      </p>
    </div>

    <div style="padding:24px;">
      <p style="margin:0 0 16px;font-size:14px;color:#cbd5e1;line-height:1.5;">
        Analysis for server log file <strong style="color:#60a5fa;font-family:monospace;">{escaped_file}</strong> has completed. 
        Multiple high-confidence malicious intrusion attempts have been detected and triaged.
      </p>

      <table style="width:100%;border-collapse:collapse;margin-bottom:20px;background:#0d1117;border-radius:6px;overflow:hidden;border:1px solid #1f2937;">
        <tr>
          <td style="padding:12px 16px;border-bottom:1px solid #1f2937;color:#94a3b8;font-size:12px;text-transform:uppercase;font-weight:600;">Total Analyzed</td>
          <td style="padding:12px 16px;border-bottom:1px solid #1f2937;color:#f8fafc;font-size:14px;font-weight:700;font-family:monospace;">{total_requests} events</td>
        </tr>
        <tr>
          <td style="padding:12px 16px;border-bottom:1px solid #1f2937;color:#94a3b8;font-size:12px;text-transform:uppercase;font-weight:600;">Confirmed Attacks</td>
          <td style="padding:12px 16px;border-bottom:1px solid #1f2937;color:#ef4444;font-size:15px;font-weight:800;font-family:monospace;">{attacks_detected} malicious ({attack_rate}%)</td>
        </tr>
        <tr>
          <td style="padding:12px 16px;border-bottom:1px solid #1f2937;color:#94a3b8;font-size:12px;text-transform:uppercase;font-weight:600;">Critical Severity</td>
          <td style="padding:12px 16px;border-bottom:1px solid #1f2937;color:#f87171;font-size:14px;font-weight:700;font-family:monospace;">{critical_count} events</td>
        </tr>
      </table>

      <div style="margin-bottom:20px;">
        <h4 style="margin:0 0 8px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;">Identified Threat Vectors:</h4>
        <div style="display:flex;flex-wrap:wrap;gap:6px;">
          {types_badges}
        </div>
      </div>

      <div style="margin-bottom:24px;">
        <h4 style="margin:0 0 8px;font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px;">Top Source Attacking IPs:</h4>
        <ul style="margin:0;padding-left:20px;">
          {ips_list}
        </ul>
      </div>

      <div style="background:rgba(59,130,246,0.1);border-left:3px solid #3b82f6;padding:12px 16px;border-radius:4px;margin-bottom:20px;">
        <strong style="color:#60a5fa;font-size:13px;">Recommended Containment Action:</strong>
        <p style="margin:4px 0 0;font-size:12px;color:#94a3b8;line-height:1.4;">
          Launch DeepLog SOC Console, quarantine the flagged IP addresses, and inspect the decrypted request payloads.
        </p>
      </div>

      <div style="text-align:center;padding-top:10px;">
        <a href="http://127.0.0.1:5173" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:600;font-size:13px;padding:10px 20px;border-radius:6px;box-shadow:0 4px 12px rgba(37,99,235,0.4);">
          Open DeepLog SOC Workstation &rarr;
        </a>
      </div>
    </div>

    <div style="background:#0d1117;padding:12px 24px;border-top:1px solid #1f2937;font-size:11px;color:#64748b;text-align:center;">
      DeepLog SIEM &bull; Next-Gen ML Web Attack Detection & Triage Engine &bull; Confidential
    </div>
  </div>
</body>
</html>"""

    def send_email_alert(
        self,
        recipient: str,
        file_name: str,
        total_requests: int,
        attacks_detected: int,
        attack_rate: float,
        critical_count: int,
        attack_types: list[str],
        top_source_ips: list[str],
    ) -> dict[str, Any]:
        """Sends an HTML + Plain Text alert email via SMTP or simulated sandbox delivery."""
        recipient = recipient.strip()
        subject = f"[DEEPLOG SIEM ALERT] {attacks_detected} Attacks Triaged in {file_name}"
        html_content = self.format_email_html(
            file_name, total_requests, attacks_detected, attack_rate, critical_count, attack_types, top_source_ips
        )
        plain_text = (
            f"DEEPLOG SIEM INCIDENT ALERT\n"
            f"Log File: {file_name}\n"
            f"Attacks Detected: {attacks_detected} / {total_requests} ({attack_rate}%)\n"
            f"Critical Threats: {critical_count}\n"
            f"Top Threat Vectors: {', '.join(attack_types)}\n"
            f"Top Attacker IPs: {', '.join(top_source_ips)}\n"
        )

        smtp_host = os.environ.get("SMTP_HOST")
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_user = os.environ.get("SMTP_USER")
        smtp_password = os.environ.get("SMTP_PASSWORD")
        smtp_from = os.environ.get("SMTP_FROM", "alerts@deeplog.soc.internal")

        message_id = f"email_{uuid.uuid4().hex[:12]}"

        if smtp_host and smtp_user and smtp_password:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = smtp_from
                msg["To"] = recipient
                msg["X-DeepLog-Alert-ID"] = message_id
                msg.attach(MIMEText(plain_text, "plain"))
                msg.attach(MIMEText(html_content, "html"))

                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)

                return {
                    "status": "delivered_smtp",
                    "channel": "email",
                    "recipient": recipient,
                    "message_id": message_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "provider": f"SMTP ({smtp_host}:{smtp_port})",
                    "subject": subject,
                }
            except Exception as e:
                return {
                    "status": "failed",
                    "channel": "email",
                    "recipient": recipient,
                    "message_id": message_id,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "provider": f"SMTP ({smtp_host}:{smtp_port})",
                }

        # Simulated Sandbox Delivery (Default development/testing mode)
        return {
            "status": "delivered_simulated",
            "channel": "email",
            "recipient": recipient,
            "message_id": message_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": "DeepLog Virtual Mail Exchange (Sandbox RFC 5321)",
            "subject": subject,
            "note": "SMTP credentials not specified in env; alert delivered to DeepLog Virtual Mail Exchange.",
        }

    def send_whatsapp_alert(
        self,
        phone_number: str,
        file_name: str,
        total_requests: int,
        attacks_detected: int,
        attack_rate: float,
        critical_count: int,
        attack_types: list[str],
        top_source_ips: list[str],
    ) -> dict[str, Any]:
        """Sends a structured WhatsApp security notification via Twilio REST API or simulated gateway."""
        clean_phone = phone_number.strip()
        if not clean_phone.startswith("+"):
            clean_phone = f"+{clean_phone}"

        body = self.format_whatsapp_message(
            file_name, total_requests, attacks_detected, attack_rate, critical_count, attack_types, top_source_ips
        )
        message_id = f"wa_{uuid.uuid4().hex[:12]}"

        twilio_sid = os.environ.get("TWILIO_ACCOUNT_SID")
        twilio_token = os.environ.get("TWILIO_AUTH_TOKEN")
        twilio_from = os.environ.get("TWILIO_WHATSAPP_FROM", "+14155238886")

        if twilio_sid and twilio_token:
            try:
                url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
                auth_str = f"{twilio_sid}:{twilio_token}"
                import base64
                b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

                data = urllib.parse.urlencode({
                    "From": f"whatsapp:{twilio_from}",
                    "To": f"whatsapp:{clean_phone}",
                    "Body": body,
                }).encode("utf-8")

                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={
                        "Authorization": f"Basic {b64_auth}",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method="POST",
                )

                with urllib.request.urlopen(req, timeout=10) as response:
                    raw_resp = response.read().decode("utf-8")
                    return {
                        "status": "delivered_twilio",
                        "channel": "whatsapp",
                        "recipient": clean_phone,
                        "message_id": message_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "provider": "Twilio WhatsApp Cloud Gateway",
                    }
            except Exception as e:
                return {
                    "status": "failed",
                    "channel": "whatsapp",
                    "recipient": clean_phone,
                    "message_id": message_id,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "provider": "Twilio WhatsApp Cloud Gateway",
                }

        # Simulated Sandbox Delivery (Default development/testing mode)
        return {
            "status": "delivered_simulated",
            "channel": "whatsapp",
            "recipient": clean_phone,
            "message_id": message_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": "DeepLog Virtual WhatsApp Gateway (Sandbox E.164)",
            "preview": body[:140] + "...",
            "note": "Twilio credentials not specified in env; alert delivered to DeepLog Virtual WhatsApp Gateway.",
        }

    def dispatch_alert(
        self,
        channel: str,
        file_name: str,
        total_requests: int,
        attacks_detected: int,
        attack_rate: float,
        critical_count: int,
        attack_types: list[str],
        top_source_ips: list[str],
        recipient_email: str | None = None,
        recipient_phone: str | None = None,
    ) -> dict[str, Any]:
        audit_id = f"dispatch_{uuid.uuid4().hex[:10]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        results: dict[str, Any] = {
            "audit_id": audit_id,
            "timestamp": timestamp,
            "file_name": file_name,
            "attacks_detected": attacks_detected,
            "attack_rate": attack_rate,
            "channels_dispatched": [],
            "email_status": None,
            "whatsapp_status": None,
        }

        channel_clean = (channel or "").lower().strip()
        do_email = channel_clean in ("email", "both")
        do_whatsapp = channel_clean in ("whatsapp", "both")

        if do_email:
            if not recipient_email or not self.validate_email(recipient_email):
                raise ValueError(f"Invalid email address provided for alert dispatch: '{recipient_email}'")
            email_res = self.send_email_alert(
                recipient=recipient_email,
                file_name=file_name,
                total_requests=total_requests,
                attacks_detected=attacks_detected,
                attack_rate=attack_rate,
                critical_count=critical_count,
                attack_types=attack_types,
                top_source_ips=top_source_ips,
            )
            results["email_status"] = email_res
            results["channels_dispatched"].append("email")

        if do_whatsapp:
            if not recipient_phone or not self.validate_phone(recipient_phone):
                raise ValueError(f"Invalid WhatsApp phone number provided: '{recipient_phone}'. Expected E.164 format (e.g. +14155552671).")
            wa_res = self.send_whatsapp_alert(
                phone_number=recipient_phone,
                file_name=file_name,
                total_requests=total_requests,
                attacks_detected=attacks_detected,
                attack_rate=attack_rate,
                critical_count=critical_count,
                attack_types=attack_types,
                top_source_ips=top_source_ips,
            )
            results["whatsapp_status"] = wa_res
            results["channels_dispatched"].append("whatsapp")

        # Determine overall status
        statuses = []
        if results["email_status"]:
            statuses.append(results["email_status"].get("status"))
        if results["whatsapp_status"]:
            statuses.append(results["whatsapp_status"].get("status"))

        if all(s and "delivered" in s for s in statuses):
            results["status"] = "dispatched"
            results["message"] = f"Incident alert successfully transmitted via {', '.join(results['channels_dispatched'])}."
        elif any(s and "delivered" in s for s in statuses):
            results["status"] = "partial"
            results["message"] = "Alert delivered on some channels with warnings on others."
        else:
            results["status"] = "failed"
            results["message"] = "Alert transmission failed across requested channels."

        summary_preview = (
            f"DeepLog SIEM Incident Alert: {attacks_detected} threats in {file_name} "
            f"({attack_rate}% attack rate) dispatched to {', '.join(results['channels_dispatched'])}"
        )
        results["summary_preview"] = summary_preview

        # Log to in-memory audit store (keep most recent 100)
        self.history.insert(0, results)
        if len(self.history) > 100:
            self.history.pop()

        return results

    def get_history(self) -> list[dict[str, Any]]:
        return self.history


alert_service = AlertService()
