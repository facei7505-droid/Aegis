"""Telegram: alerts to the owner and each client, and commands to run the service from a phone.

Who can do what:
  * owner chats (settings.json `owner_chats`): every site, every command;
  * a client's chats (site `chats`): only their own sites — status, report, pause/resume, unban;
  * anyone else: /start and /id answer with the chat id, nothing more.

Commands: /status [site]  /sites  /report <site> [YYYY-MM]  /pause <site>  /resume <site>
          /unban <ip> [site]  /id  /help

Alerts never wait on Telegram: they go through a queue on a background thread, and repeats of the
same kind of attack on the same site are folded into one message per cooldown.
"""
from __future__ import annotations

import html
import ipaddress
import json
import queue
import threading
import time
import urllib.request
import uuid
from datetime import date, datetime
from typing import TYPE_CHECKING

from ..shield.core import REASONS_RU

if TYPE_CHECKING:
    from .server import Edge

HELP = """<b>{brand}</b>

/status — что с сайтами сейчас
/report <i>сайт</i> [ГГГГ-ММ] — отчёт за месяц (PDF)
/pause <i>сайт</i> — выключить блокировки (атаки продолжат записываться)
/resume <i>сайт</i> — включить блокировки сейчас (и закончить обучение)
/unban <i>IP</i> [сайт] — снять блокировку с адреса
/id — номер этого чата"""


def esc(value) -> str:
    return html.escape(str(value), quote=False)


class Bot:
    def __init__(self, edge: "Edge", api: str = "https://api.telegram.org", poll_timeout: int = 25):
        self.edge = edge
        self.base = f"{api.rstrip('/')}/bot{edge.settings.telegram_token}"
        self.poll_timeout = poll_timeout
        self.outbox: queue.Queue = queue.Queue(maxsize=1000)
        self._offset = 0
        self._stop = threading.Event()
        self._last: dict[tuple[str, str], float] = {}
        self._folded: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()
        self.sent = 0

    # -------------------------------------------------------------- API --
    def call(self, method: str, payload: dict | None = None, timeout: float = 30) -> dict:
        data = json.dumps(payload or {}).encode("utf-8")
        req = urllib.request.Request(f"{self.base}/{method}", data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def send(self, chat: int, text: str) -> None:
        self.outbox.put_nowait(("sendMessage", {"chat_id": chat, "text": text[:4000], "parse_mode": "HTML",
                                                "disable_web_page_preview": True}))

    def send_document(self, chat: int, filename: str, data: bytes, caption: str = "") -> None:
        self.outbox.put_nowait(("sendDocument", {"chat_id": chat, "filename": filename, "data": data,
                                                 "caption": caption[:1000]}))

    def _post_document(self, payload: dict) -> None:
        boundary = uuid.uuid4().hex
        parts = []
        for name in ("chat_id", "caption"):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{payload[name]}\r\n'.encode())
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{payload["filename"]}"\r\n'
                     f'Content-Type: application/pdf\r\n\r\n'.encode() + payload["data"] + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        req = urllib.request.Request(f"{self.base}/sendDocument", data=b"".join(parts),
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        urllib.request.urlopen(req, timeout=60).read()

    def _deliver(self) -> None:
        while not self._stop.is_set():
            try:
                method, payload = self.outbox.get(timeout=1)
            except queue.Empty:
                continue
            for attempt in range(3):
                try:
                    if method == "sendDocument":
                        self._post_document(payload)
                    else:
                        self.call(method, payload)
                    self.sent += 1
                    break
                except Exception:
                    time.sleep(1 + attempt * 2)

    # ----------------------------------------------------------- alerts --
    def alert(self, spec, inc) -> None:
        site = self.edge.site(spec.name)
        if site is None:
            return
        chats = sorted(set(self.edge.settings.owner_chats) | set(site.chats))
        if not chats:
            return
        key = (site.domain, inc.attack_type)
        now = time.time()
        with self._lock:
            if now - self._last.get(key, 0) < self.edge.settings.alert_cooldown:
                self._folded[key] = self._folded.get(key, 0) + 1
                return
            self._last[key] = now
            folded = self._folded.pop(key, 0)
        text = self.format_alert(site.domain, inc, folded)
        for chat in chats:
            try:
                self.send(chat, text)
            except queue.Full:
                return

    @staticmethod
    def format_alert(domain: str, inc, folded: int = 0) -> str:
        when = datetime.fromtimestamp(inc.timestamp).strftime("%d.%m %H:%M")
        what = REASONS_RU.get(inc.attack_type, "подозрительный запрос")
        if inc.attack_type == "virtual_patch" and inc.signals[1:]:
            what = inc.signals[1]
        if inc.attack_type == "brute_force":
            head = f"<b>{esc(domain)}</b>: подбор пароля остановлен"
            body = (f"С адреса {esc(inc.client)} — больше попыток входа, чем разрешено. Вход для этого адреса "
                    f"закрыт на время, остальной сайт работает.")
        elif inc.attack_type == "rate_limit":
            head = f"<b>{esc(domain)}</b>: слишком частые запросы"
            body = f"Адрес {esc(inc.client)} притормозили на минуту."
        else:
            verb = "атака заблокирована" if inc.blocked else "атака записана (режим обучения, не блокировалась)"
            head = f"<b>{esc(domain)}</b>: {verb}"
            body = f"{esc(what[:1].upper() + what[1:])}\nАдрес: <code>{esc(inc.path[:120])}</code>\nОткуда: {esc(inc.client)}"
        extra = f"\nИ ещё похожих с прошлого сообщения: {folded}" if folded else ""
        return f"{head}\n{body}\nВремя: {when} · код {esc(inc.id)}{extra}"

    # --------------------------------------------------------- commands --
    def _sites_for(self, chat: int) -> list:
        if chat in self.edge.settings.owner_chats:
            return list(self.edge.sites.values())
        return [s for s in self.edge.sites.values() if chat in s.chats]

    def _pick(self, chat: int, arg: str | None):
        """The site a command is about: named, or the only site this chat has."""
        mine = self._sites_for(chat)
        if arg:
            site = self.edge.site(arg.strip().lower())
            return site if site and site in mine else None
        return mine[0] if len(mine) == 1 else None

    def handle(self, chat: int, text: str) -> str | None:
        parts = text.strip().split()
        if not parts or not parts[0].startswith("/"):
            return None
        cmd, args = parts[0].split("@")[0].lower(), parts[1:]
        brand = esc(self.edge.settings.brand)
        mine = self._sites_for(chat)
        if cmd in ("/start", "/id"):
            if not mine and chat not in self.edge.settings.owner_chats:
                return (f"{brand}\nНомер этого чата: <code>{chat}</code>\n"
                        "Отправьте его администратору защиты, чтобы получать уведомления о вашем сайте.")
            return HELP.format(brand=brand) + f"\n\nНомер чата: <code>{chat}</code>"
        if not mine and chat not in self.edge.settings.owner_chats:
            return None
        if cmd == "/help":
            return HELP.format(brand=brand)
        if cmd == "/sites":
            if chat not in self.edge.settings.owner_chats:
                return None
            lines = [f"{esc(s.domain)} — {esc(s.status_ru())} ({esc(s.cms)})" for s in mine]
            return "<b>Сайты</b>\n" + ("\n".join(lines) if lines else "пока ни одного: aegis edge add")
        if cmd == "/status":
            sites = [self._pick(chat, args[0])] if args else mine
            sites = [s for s in sites if s]
            if not sites:
                return "Такого сайта нет среди ваших."
            return "\n\n".join(self.status_text(s) for s in sites[:10])
        if cmd in ("/pause", "/resume"):
            site = self._pick(chat, args[0] if args else None)
            if site is None:
                return "Укажите сайт: " + cmd + " shop.kz"
            mode = "monitor" if cmd == "/pause" else "block"
            changes = {"mode": mode} if mode == "monitor" else {"mode": mode, "learn_until": ""}
            updated = self.edge.registry.update(site.domain, **changes)
            self.edge.reload(force=True)
            if mode == "monitor":
                return (f"<b>{esc(site.domain)}</b>: блокировки выключены. Атаки продолжают записываться.\n"
                        f"Включить обратно: /resume {esc(site.domain)}")
            return f"<b>{esc(site.domain)}</b>: {esc(updated.status_ru())}."
        if cmd == "/unban":
            if not args:
                return "Укажите адрес: /unban 203.0.113.7"
            try:
                ip = str(ipaddress.ip_address(args[0]))
            except ValueError:
                return "Это не IP-адрес."
            targets = [self._pick(chat, args[1])] if len(args) > 1 else mine
            freed = []
            for site in [s for s in targets if s]:
                shield = self.edge.shield(site.domain)
                if shield is not None and shield.core.unlock(ip):
                    freed.append(site.domain)
            return (f"Адрес {esc(ip)} разблокирован: {esc(', '.join(freed))}." if freed
                    else f"Адрес {esc(ip)} сейчас нигде не заблокирован.")
        if cmd == "/report":
            site = self._pick(chat, args[0] if args else None)
            if site is None:
                return "Укажите сайт: /report shop.kz 2026-11"
            month = args[1] if len(args) > 1 else date.today().strftime("%Y-%m")
            try:
                from .report import build_report
                pdf = build_report(self.edge, site, month)
            except ValueError as exc:
                return esc(str(exc))
            except ImportError:
                return "Для отчётов на сервере нужен пакет reportlab: pip install 'aegis-selfheal[edge]'"
            self.send_document(chat, f"aegis-{site.domain}-{month}.pdf", pdf, f"Отчёт о защите {site.domain} за {month}")
            return None
        return "Не знаю такой команды. /help"

    def status_text(self, site) -> str:
        today = self.edge.stats.day(site.domain, date.today().isoformat())
        top = sorted(today["by_type"].items(), key=lambda kv: -kv[1])[:3]
        kinds = ", ".join(f"{REASONS_RU.get(k, k)} — {v}" for k, v in top) or "атак не было"
        return (f"<b>{esc(site.domain)}</b>: {esc(site.status_ru())}\n"
                f"Сегодня: {today['requests']} запросов, остановлено {today['blocked']} из {today['attacks']} атак\n"
                f"{esc(kinds)}")

    # ------------------------------------------------------------ polling --
    def poll_once(self) -> int:
        result = self.call("getUpdates", {"offset": self._offset, "timeout": self.poll_timeout,
                                          "allowed_updates": ["message"]}, timeout=self.poll_timeout + 10)
        handled = 0
        for update in result.get("result", []):
            self._offset = max(self._offset, update["update_id"] + 1)
            message = update.get("message") or {}
            chat = (message.get("chat") or {}).get("id")
            text = message.get("text") or ""
            if chat is None:
                continue
            try:
                reply = self.handle(int(chat), text)
            except Exception:
                reply = "Что-то пошло не так. Попробуйте ещё раз через минуту."
            if reply:
                self.send(int(chat), reply)
            handled += 1
        return handled

    def _poll(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                self._stop.wait(5)

    def start(self) -> None:
        threading.Thread(target=self._deliver, daemon=True, name="aegis-telegram-send").start()
        threading.Thread(target=self._poll, daemon=True, name="aegis-telegram-poll").start()

    def stop(self) -> None:
        self._stop.set()
