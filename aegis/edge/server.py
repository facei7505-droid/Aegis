"""Aegis Edge: one server that protects many client sites.

    visitor ─► Caddy (HTTPS, certificates for every client domain) ─► Aegis Edge :8080 ─► client's server
                                                                     │  shield per site (CMS preset)
                                                                     ├─ Telegram: alerts and commands
                                                                     └─ stats per day ─► monthly report

Everything lives in one folder (default /var/lib/aegis):
    sites.json      the sites (aegis edge add / remove / pause / resume)
    settings.json   Telegram token, owner chats, retention
    logs/           incidents per site (attacks only, personal data masked)
    stats/          counts per site per day
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from ..gateway import Gateway, serve
from .sites import Registry, Site
from .stats import Stats, prune_jsonl


@dataclass
class Settings:
    telegram_token: str = ""
    owner_chats: list[int] = field(default_factory=list)   # you: every site, every command
    server_ip: str = ""                                    # shown in DNS instructions
    brand: str = "Aegis Щит"
    contact: str = ""                                      # shown to clients in reports (@telegram, phone)
    retention_days: int = 90
    alert_cooldown: int = 600                              # seconds between alerts of one kind per site

    @classmethod
    def load(cls, path: Path) -> "Settings":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8") or "{}")
        return cls(**{k: v for k, v in raw.items() if k in cls.__dataclass_fields__})

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


class Edge:
    """The running edge: gateway, registry watcher, stats, Telegram bot."""

    def __init__(self, home: str | Path, telegram_api: str = "https://api.telegram.org"):
        self.home = Path(home)
        self.registry = Registry(self.home / "sites.json")
        self.settings = Settings.load(self.home / "settings.json")
        self.stats = Stats(self.home / "stats")
        self.sites: dict[str, Site] = {}
        self._mtime = 0.0
        self._day = date.today()
        self._counted: dict[str, int] = {}
        self._stop = threading.Event()
        self.gateway = Gateway([], log_dir=str(self.home / "logs"))
        self.gateway.tls_names = self.knows
        self.gateway.on_incident.append(lambda spec, inc: self.stats.incident(spec.name, inc))
        self.bot = None
        if self.settings.telegram_token:
            from .telegram import Bot
            self.bot = Bot(self, api=telegram_api)
            self.gateway.on_incident.append(self.bot.alert)
        self.reload(force=True)

    # ------------------------------------------------------------ sites --
    def knows(self, domain: str) -> bool:
        return any(domain in s.hosts() for s in self.sites.values())

    def site(self, domain: str) -> Site | None:
        domain = domain.lower()
        return next((s for s in self.sites.values() if domain in s.hosts()), None)

    def reload(self, force: bool = False) -> dict | None:
        """Re-read sites.json when it changed, or when a day passed (learning periods end at midnight)."""
        mtime, today = self.registry.mtime(), date.today()
        if not force and mtime == self._mtime and today == self._day:
            return None
        self._mtime, self._day = mtime, today
        sites = self.registry.load()
        self.sites = {s.domain: s for s in sites}
        return self.gateway.set_apps([s.to_spec(today) for s in sites])

    def shield(self, domain: str):
        site = self.site(domain)
        return self.gateway.shields.get(site.domain) if site else None

    # ------------------------------------------------------------- loops --
    def _tick(self) -> None:
        last_flush = last_prune = 0.0
        while not self._stop.wait(2.0):
            try:
                self.reload()
                now = time.time()
                if now - last_flush >= 10:
                    with self.gateway._lock:
                        counts = dict(self.gateway.requests)
                    for name, total in counts.items():
                        self.stats.requests(name, total - self._counted.get(name, 0))
                        self._counted[name] = total
                    self.stats.flush()
                    last_flush = now
                if now - last_prune >= 86400:
                    keep = self.settings.retention_days
                    self.stats.prune(keep)
                    for log in (self.home / "logs").glob("*.incidents.jsonl"):
                        prune_jsonl(log, keep)
                    last_prune = now
            except Exception:  # the watcher must survive anything a bad file can do
                pass

    def start(self, port: int = 8080, host: str = "127.0.0.1") -> list:
        servers = serve(self.gateway, port, host)
        threading.Thread(target=self._tick, daemon=True, name="aegis-edge-tick").start()
        if self.bot:
            self.bot.start()
        return servers

    def stop(self) -> None:
        self._stop.set()
        if self.bot:
            self.bot.stop()
        self.stats.flush()
