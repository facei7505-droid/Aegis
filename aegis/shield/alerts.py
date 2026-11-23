"""Real-time alerts. Sending happens on a background thread so requests never wait."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone

from ..models import Incident

ATTACK_NAMES = {
    "sqli": "SQL injection", "xss": "Cross-site scripting", "path_traversal": "Path traversal",
    "command_injection": "Command injection", "ssti": "Template injection",
    "code_injection": "Code injection", "ssrf": "SSRF", "recon": "Vulnerability scanner",
}


class _Throttled:
    """At most one alert per (attack type, path) every `cooldown` seconds."""

    def __init__(self, cooldown: float = 30.0):
        self.cooldown = cooldown
        self._last: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def allow(self, incident: Incident) -> bool:
        key = (incident.attack_type, incident.path)
        now = time.time()
        with self._lock:
            if now - self._last.get(key, 0) < self.cooldown:
                return False
            self._last[key] = now
            return True


def _post(url: str, payload: dict, headers: dict | None = None) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json", **(headers or {})})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:
        pass


def format_alert(incident: Incident, app_name: str = "your app") -> str:
    when = datetime.fromtimestamp(incident.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    action = "BLOCKED" if incident.blocked else "DETECTED (monitor mode)"
    return (
        f"🛡 Aegis — {action}\n"
        f"{ATTACK_NAMES.get(incident.attack_type, incident.attack_type)} on {app_name}\n"
        f"{incident.method} {incident.path}  ·  {incident.location} '{incident.param}'\n"
        f"From: {incident.client}  ·  confidence {incident.score:.0%}\n"
        f"Payload: {incident.payload[:160]}\n"
        f"Incident {incident.id} · {when}"
    )


class TelegramAlerter:
    """Sends incidents to a Telegram chat via the Bot API."""

    def __init__(self, bot_token: str | None = None, chat_id: str | None = None,
                 app_name: str = "your app", cooldown: float = 30.0):
        self.bot_token = bot_token or os.environ.get("AEGIS_TELEGRAM_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("AEGIS_TELEGRAM_CHAT", "")
        self.app_name = app_name
        self.throttle = _Throttled(cooldown)

    def send(self, incident: Incident) -> None:
        if not (self.bot_token and self.chat_id) or not self.throttle.allow(incident):
            return
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": format_alert(incident, self.app_name),
                   "disable_web_page_preview": True}
        threading.Thread(target=_post, args=(url, payload), daemon=True).start()


class WebhookAlerter:
    """POSTs the incident as JSON (Slack-compatible `text` field included)."""

    def __init__(self, url: str | None = None, app_name: str = "your app", cooldown: float = 30.0):
        self.url = url or os.environ.get("AEGIS_WEBHOOK_URL", "")
        self.app_name = app_name
        self.throttle = _Throttled(cooldown)

    def send(self, incident: Incident) -> None:
        if not self.url or not self.throttle.allow(incident):
            return
        payload = {"text": format_alert(incident, self.app_name), "incident": incident.to_dict()}
        threading.Thread(target=_post, args=(self.url, payload), daemon=True).start()
