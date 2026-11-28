"""The sites Aegis protects for clients, kept in one JSON file the edge server watches.

A site goes live in two steps, so a new client's shop never breaks on day one:
  1. learning (default 7 days): every request passes, attacks are recorded and reported;
  2. protection: attacks are blocked.
`aegis edge add` writes the file; the running server picks the change up within seconds.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from ..gateway import AppSpec
from ..shield.policy import PRESETS
from ..shield.signing import new_secret

DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
PLANS = {"start": "Старт", "business": "Бизнес", "studio": "Студия"}


def normalize_domain(value: str) -> str:
    """`https://WWW.Shop.kz/path` -> `www.shop.kz`; Cyrillic domains become punycode (магазин.kz)."""
    host = value.strip().lower()
    host = re.sub(r"^[a-z]+://", "", host).split("/")[0].split(":")[0].rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"это не домен: {value!r}") from None
    if not DOMAIN.match(host):
        raise ValueError(f"это не домен: {value!r}")
    return host


@dataclass
class Site:
    domain: str
    origin: str                               # https://203.0.113.5 (the site's real server)
    cms: str = "generic"                      # preset: generic | wordpress | bitrix | opencart
    aliases: list[str] = field(default_factory=list)
    client: str = ""                          # who pays, for reports ("ИП Ромашка")
    plan: str = "start"
    chats: list[int] = field(default_factory=list)  # Telegram chats that get this site's alerts
    mode: str = "block"                       # block | monitor (paused)
    learn_until: str = ""                     # ISO date: monitor-only until then
    tls_verify: bool = True                   # check the origin's certificate
    rate_limit: int = 300                     # page requests per minute per visitor address
    login_limit: int = 10                     # login attempts per 10 minutes per address
    created: str = ""
    secret: str = ""                          # signs requests to the origin (origin lock, editor passes)
    connector: bool = False                   # the site runs the Aegis connector: editors are known by its
                                              # signed pass, not by a cookie name anyone can send

    def __post_init__(self):
        self.domain = normalize_domain(self.domain)
        self.aliases = sorted({normalize_domain(a) for a in self.aliases} - {self.domain})
        if self.cms not in PRESETS:
            raise ValueError(f"cms: один из {', '.join(PRESETS)}")
        if self.mode not in ("block", "monitor"):
            raise ValueError("mode: block или monitor")
        if not re.match(r"^https?://", self.origin):
            self.origin = "https://" + self.origin
        if self.plan not in PLANS:
            raise ValueError(f"plan: один из {', '.join(PLANS)}")

    # ------------------------------------------------------------ state --
    def learning(self, today: date | None = None) -> bool:
        return bool(self.learn_until) and (today or date.today()) < date.fromisoformat(self.learn_until)

    def effective_mode(self, today: date | None = None) -> str:
        return "monitor" if self.mode == "monitor" or self.learning(today) else "block"

    def status_ru(self, today: date | None = None) -> str:
        if self.mode == "monitor":
            return "на паузе: атаки записываются, но не блокируются"
        if self.learning(today):
            return f"обучение до {date.fromisoformat(self.learn_until).strftime('%d.%m.%Y')}: атаки записываются"
        return "защита включена"

    def hosts(self) -> list[str]:
        return [self.domain, *self.aliases]

    def to_spec(self, today: date | None = None) -> AppSpec:
        options = {"preset": self.cms, "rate_limit": self.rate_limit, "login_limit": self.login_limit,
                   "trust_proxy": True, "proxy_hops": 1, "ban_after": 5, "ban_seconds": 900.0}
        if self.connector and self.secret:
            options["editor_secret"] = self.secret
        return AppSpec(
            name=self.domain, upstream=self.origin, hosts=self.hosts(), shield=self.effective_mode(today),
            heal="off", preserve_host=True, tls_verify=self.tls_verify, origin_secret=self.secret or None,
            options=options,
        )


class Registry:
    """sites.json: a list of sites. Writes are atomic, so the server never reads half a file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def load(self) -> list[Site]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text(encoding="utf-8") or "[]")
        return [Site(**{k: v for k, v in raw.items() if k in Site.__dataclass_fields__}) for raw in data]

    def save(self, sites: list[Site]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([asdict(s) for s in sorted(sites, key=lambda s: s.domain)], ensure_ascii=False, indent=1)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".sites.", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        os.replace(tmp, self.path)

    def get(self, domain: str) -> Site | None:
        domain = normalize_domain(domain)
        return next((s for s in self.load() if domain in s.hosts()), None)

    def add(self, site: Site, learn_days: int = 7) -> Site:
        with self._lock:
            sites = self.load()
            taken = {h for s in sites for h in s.hosts()}
            clash = [h for h in site.hosts() if h in taken]
            if clash:
                raise ValueError(f"уже защищается: {', '.join(clash)}")
            if not site.created:
                site.created = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if not site.secret:
                site.secret = new_secret()
            if learn_days and not site.learn_until:
                site.learn_until = (date.today() + timedelta(days=learn_days)).isoformat()
            sites.append(site)
            self.save(sites)
            return site

    def update(self, domain: str, **changes) -> Site:
        with self._lock:
            sites = self.load()
            target = normalize_domain(domain)
            for i, s in enumerate(sites):
                if target in s.hosts():
                    data = {**asdict(s), **changes}
                    sites[i] = Site(**data)
                    self.save(sites)
                    return sites[i]
            raise KeyError(f"нет такого сайта: {domain}")

    def remove(self, domain: str) -> Site:
        with self._lock:
            sites = self.load()
            target = normalize_domain(domain)
            keep = [s for s in sites if target not in s.hosts()]
            if len(keep) == len(sites):
                raise KeyError(f"нет такого сайта: {domain}")
            self.save(keep)
            return next(s for s in sites if target in s.hosts())

    def mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except FileNotFoundError:
            return 0.0
