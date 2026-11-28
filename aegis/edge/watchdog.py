"""Failover watchdog: if the Aegis server dies, client sites keep working (unprotected) instead of going dark.

Runs on a second, cheap machine, never on the Aegis server itself:

    # on the Aegis server: what the watchdog needs (includes site secrets: copy it privately)
    aegis edge failover-export > failover.json
    # on the watchdog machine
    aegis edge watchdog --config failover.json

How it works. Every client site points its DNS at a name in your zone (CNAME www.shop.kz ->
shop-kz.<edge_domain>); that name normally has an A record with the Aegis server's address. The
watchdog asks Aegis `/_aegis/ping` every `interval` seconds. After `fail_after` failed checks in a
row it, for every site:
  1. sends the site's connector a signed X-Aegis-Failover token, so the connector (origin lock)
     lets direct visitors in for a while (renewed while Aegis stays down);
  2. points <label>.<edge_domain> at the site's own server (TTL 60 s);
and tells you in Telegram. After `recover_after` good checks it points the names back at Aegis.

DNS changes go through a provider: Cloudflare's API, or any command (your registrar's CLI or API
script) that receives the record in environment variables.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import ssl
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from ..shield.signing import FAILOVER_HEADER, failover_token

RECORD_TTL = 60
OPEN_FOR = 1800  # seconds a failover token opens a site; renewed on every check while Aegis is down


def label(domain: str) -> str:
    """shop.kz -> shop-kz: the site's name inside your zone."""
    return domain.replace(".", "-")


def _host_of(origin: str) -> tuple[str, str, int]:
    scheme, _, rest = origin.partition("://")
    if not rest:
        scheme, rest = "https", origin
    hostport = rest.split("/")[0]
    if hostport.startswith("["):
        host, _, port = hostport[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = hostport.partition(":")
    return scheme, host, int(port) if port else (443 if scheme == "https" else 80)


def record_for(target: str) -> tuple[str, str]:
    """(record type, content) pointing a name at `target` (an IP address or a host name)."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return "CNAME", target
    return ("AAAA" if ip.version == 6 else "A"), str(ip)


# ------------------------------------------------------------------ DNS --

class Cloudflare:
    """Cloudflare DNS API (free plan is enough). Token needs Zone.DNS:Edit for the zone."""

    def __init__(self, token: str, zone_id: str, api: str = "https://api.cloudflare.com/client/v4"):
        self.token, self.zone, self.api = token, zone_id, api.rstrip("/")

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        req = urllib.request.Request(f"{self.api}/zones/{self.zone}{path}", method=method,
                                     data=json.dumps(payload).encode() if payload is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read() or b"{}")
        if not data.get("success", False):
            raise RuntimeError(f"Cloudflare: {data.get('errors')}")
        return data

    def set(self, name: str, rtype: str, content: str) -> None:
        found = self._call("GET", f"/dns_records?name={name}")["result"]
        record = {"type": rtype, "name": name, "content": content, "ttl": RECORD_TTL, "proxied": False}
        same = [r for r in found if r.get("type") in ("A", "AAAA", "CNAME")]
        if same:
            self._call("PUT", f"/dns_records/{same[0]['id']}", record)
            for extra in same[1:]:  # an A and a CNAME cannot live side by side: keep exactly one
                self._call("DELETE", f"/dns_records/{extra['id']}")
        else:
            self._call("POST", "/dns_records", record)


class Command:
    """Any DNS host: runs your command with AEGIS_DNS_NAME, AEGIS_DNS_TYPE, AEGIS_DNS_CONTENT, AEGIS_DNS_TTL."""

    def __init__(self, command: str):
        self.command = command

    def set(self, name: str, rtype: str, content: str) -> None:
        env = {**os.environ, "AEGIS_DNS_NAME": name, "AEGIS_DNS_TYPE": rtype, "AEGIS_DNS_CONTENT": content,
               "AEGIS_DNS_TTL": str(RECORD_TTL)}
        # The owner's own command from the watchdog config; record values travel in the environment only.
        subprocess.run(self.command, shell=True, env=env, check=True, timeout=60)  # aegis: ignore[AEG002]


def provider_from(config: dict):
    dns = config.get("dns") or {}
    if dns.get("provider") == "cloudflare":
        return Cloudflare(dns.get("token") or os.environ.get("CLOUDFLARE_API_TOKEN", ""), dns["zone_id"],
                          dns.get("api", "https://api.cloudflare.com/client/v4"))
    if dns.get("provider") == "command":
        return Command(dns["command"])
    raise ValueError("dns.provider: cloudflare или command")


# ------------------------------------------------------------- watchdog --

@dataclass
class Site:
    domain: str
    origin: str
    secret: str = ""
    tls_verify: bool = True


@dataclass
class Watchdog:
    server: str                       # how to reach Aegis: https://203.0.113.10 (SNI = a site name)
    edge_domain: str                  # your zone: shop-kz.<edge_domain>
    sites: list[Site]
    dns: object
    notify: Callable[[str], None] = lambda text: None
    interval: float = 30.0
    fail_after: int = 3
    recover_after: int = 5
    timeout: float = 10.0
    failed: bool = False
    _bad: int = 0
    _good: int = 0
    log: list[str] = field(default_factory=list)

    # ------------------------------------------------------------ checks --
    def _connect(self, scheme: str, host: str, port: int, server_name: str, verify: bool):
        if scheme == "http":
            return http.client.HTTPConnection(host, port, timeout=self.timeout)
        from ..proxy import _TLSConnection
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        return _TLSConnection(host, port, server_name, ctx, self.timeout)

    def aegis_alive(self) -> bool:
        """Aegis answers its ping for at least one site (one site's certificate trouble is not an outage)."""
        scheme, host, port = _host_of(self.server)
        for site in self.sites[:3]:
            try:
                conn = self._connect(scheme, host, port, site.domain, True)
                conn.request("GET", "/_aegis/ping", headers={"Host": site.domain, "User-Agent": "AegisWatchdog/1.0"})
                resp = conn.getresponse()
                resp.read()
                conn.close()
                if resp.status == 204 and resp.getheader("X-Aegis-Edge") == "alive":
                    return True
            except (OSError, http.client.HTTPException):
                continue
        return False

    def open_origin(self, site: Site, now: float, close: bool = False) -> bool:
        """Send the connector its failover token (or the closing one). False when the site did not accept it."""
        if not site.secret:
            return False
        scheme, host, port = _host_of(site.origin)
        token = failover_token(site.secret, site.domain, 0 if close else int(now) + OPEN_FOR, issued=int(now))
        try:
            conn = self._connect(scheme, host, port, site.domain, site.tls_verify)
            conn.request("GET", "/", headers={"Host": site.domain, FAILOVER_HEADER: token,
                                              "User-Agent": "AegisWatchdog/1.0"})
            resp = conn.getresponse()
            resp.read(4096)
            conn.close()
            answer = resp.getheader("X-Aegis-Connector")
            # stale: a token from this same second was already taken
            return answer in (("failover-closed",) if close else ("failover-open",)) or answer == "failover-stale"
        except (OSError, http.client.HTTPException):
            return False

    # ------------------------------------------------------------ actions --
    def _name(self, site: Site) -> str:
        return f"{label(site.domain)}.{self.edge_domain}"

    def fail_over(self, now: float) -> list[str]:
        problems = []
        for site in self.sites:
            if not self.open_origin(site, now) and site.secret:
                problems.append(f"{site.domain}: коннектор не открылся (сайт может отдавать 403 напрямую)")
            rtype, content = record_for(_host_of(site.origin)[1])
            try:
                self.dns.set(self._name(site), rtype, content)
            except Exception as exc:  # one site's DNS trouble must not stop the others
                problems.append(f"{site.domain}: DNS не переключён ({exc})")
        return problems

    def restore(self, now: float | None = None) -> list[str]:
        problems = []
        rtype, content = record_for(_host_of(self.server)[1])
        for site in self.sites:
            try:
                self.dns.set(self._name(site), rtype, content)
            except Exception as exc:
                problems.append(f"{site.domain}: DNS не вернулся ({exc})")
            # Close the side door now rather than when the last token runs out.
            if site.secret and not self.open_origin(site, now if now is not None else time.time(), close=True):
                problems.append(f"{site.domain}: коннектор не закрылся, прямой доступ закроется сам за "
                                f"{OPEN_FOR // 60} мин")
        return problems

    def tick(self, now: float | None = None) -> str:
        """One check. Returns what happened: ok | down | failed-over | still-down | recovering | restored."""
        now = now if now is not None else time.time()
        alive = self.aegis_alive()
        if alive:
            self._bad = 0
            if not self.failed:
                return "ok"
            self._good += 1
            if self._good < self.recover_after:
                return "recovering"
            problems = self.restore(now)
            self.failed, self._good = False, 0
            self.notify("✅ Aegis снова работает. Сайты переключены обратно на защиту."
                        + ("\n" + "\n".join(problems) if problems else ""))
            return "restored"
        self._good = 0
        if self.failed:
            for site in self.sites:  # keep the connectors open while Aegis is away
                self.open_origin(site, now)
            return "still-down"
        self._bad += 1
        if self._bad < self.fail_after:
            return "down"
        problems = self.fail_over(now)
        self.failed = True
        self.notify(f"🚨 Aegis не отвечает {self._bad} проверки подряд. {len(self.sites)} сайт(ов) переключены "
                    "напрямую на свои серверы: работают, но без защиты.\nКак только Aegis оживёт, вернём."
                    + ("\n" + "\n".join(problems) if problems else ""))
        return "failed-over"

    def run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception as exc:  # the watchdog itself must not die on one bad check
                self.notify(f"watchdog: ошибка проверки: {exc}")
            time.sleep(self.interval)


def telegram_notifier(token: str, chats: list[int], api: str = "https://api.telegram.org") -> Callable[[str], None]:
    def send(text: str) -> None:
        for chat in chats:
            try:
                data = json.dumps({"chat_id": chat, "text": text[:4000]}).encode()
                req = urllib.request.Request(f"{api}/bot{token}/sendMessage", data=data,
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=20).read()
            except OSError:
                pass
        print(text, flush=True)
    return send


def from_config(config: dict) -> Watchdog:
    tg = config.get("telegram") or {}
    notify = telegram_notifier(tg["token"], tg.get("chats", [])) if tg.get("token") else (lambda t: print(t, flush=True))
    return Watchdog(
        server=config["server"], edge_domain=config["edge_domain"],
        sites=[Site(**{k: v for k, v in s.items() if k in Site.__dataclass_fields__}) for s in config["sites"]],
        dns=provider_from(config), notify=notify, interval=float(config.get("interval", 30)),
        fail_after=int(config.get("fail_after", 3)), recover_after=int(config.get("recover_after", 5)))
