# core/email_utils.py
import os
import requests

SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
DEFAULT_FROM = os.environ.get("DEFAULT_FROM_EMAIL", "noreply@gapypay.com")

def send_via_sendgrid(subject: str, plain_text: str, to_email: str):
    if not SENDGRID_API_KEY:
        raise RuntimeError("SENDGRID_API_KEY not configured")

    payload = {
        "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
        "from": {"email": DEFAULT_FROM},
        "content": [{"type": "text/plain", "value": plain_text}],
    }
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json",
    }
    resp = requests.post(SENDGRID_API_URL, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp
