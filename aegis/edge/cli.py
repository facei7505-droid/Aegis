"""`aegis edge ...`: run the protection service for client sites.

    aegis edge init --telegram-token ... --owner-chat 123 --server-ip 203.0.113.10
    aegis edge add shop.kz --origin 198.51.100.7 --cms wordpress --client "ИП Ромашка"
    aegis edge origin-test shop.kz        # before the client changes DNS
    aegis edge serve                      # behind Caddy (deploy/)
    aegis edge report shop.kz --month 2026-11
"""
from __future__ import annotations

import os
import re
import ssl
import sys
import time
from datetime import date
from pathlib import Path

DEFAULT_HOME = os.environ.get("AEGIS_HOME", "/var/lib/aegis")

CADDYFILE = """# Caddy in front of Aegis Edge: HTTPS certificates for every client domain, on demand.
# A certificate is requested only for domains Aegis knows (the `ask` check), so nobody can make
# this server fetch certificates for random names.
{{
	email {email}
	on_demand_tls {{
		ask http://{aegis}/_aegis/tls-ask
	}}
	servers {{
		timeouts {{
			read_header 10s
			read_body 120s
			idle 2m
		}}
	}}
}}

https:// {{
	tls {{
		on_demand
	}}
	encode zstd gzip
	reverse_proxy {aegis} {{
		header_up X-Forwarded-Proto {{scheme}}
		transport http {{
			read_timeout 75s
		}}
	}}
}}

http:// {{
	redir https://{{host}}{{uri}} permanent
}}
"""


def register(sub) -> None:
    edge = sub.add_parser("edge", help="protect client sites from one server (managed service)")
    edge.add_argument("--home", default=DEFAULT_HOME, help=f"data folder (default {DEFAULT_HOME}, or $AEGIS_HOME)")
    edge.set_defaults(func=run)
    cmds = edge.add_subparsers(dest="edge_command", required=True)

    i = cmds.add_parser("init", help="create the data folder and settings")
    i.add_argument("--telegram-token", default="")
    i.add_argument("--owner-chat", type=int, action="append", default=[])
    i.add_argument("--server-ip", default="")
    i.add_argument("--contact", default="", help="shown to clients in reports (@telegram or phone)")
    i.add_argument("--brand", default="Aegis Щит")

    a = cmds.add_parser("add", help="protect a site")
    a.add_argument("domain")
    a.add_argument("--origin", required=True, help="the site's real server: IP or https://IP")
    a.add_argument("--cms", default="generic", choices=["generic", "wordpress", "bitrix", "opencart"])
    a.add_argument("--alias", action="append", default=[], help="other names (www. is added automatically)")
    a.add_argument("--no-www", action="store_true", help="do not add www.<domain>")
    a.add_argument("--client", default="")
    a.add_argument("--plan", default="start", choices=["start", "business", "studio"])
    a.add_argument("--chat", type=int, action="append", default=[], help="client's Telegram chat id")
    a.add_argument("--learn-days", type=int, default=7, help="record only for this many days (0 = block now)")
    a.add_argument("--no-verify", action="store_true", help="origin has a self-signed certificate")
    a.add_argument("--rate-limit", type=int, default=300)
    a.add_argument("--login-limit", type=int, default=10)

    cmds.add_parser("list", help="list protected sites")
    for name, text in (("remove", "stop protecting a site"), ("pause", "stop blocking (keep recording)"),
                       ("resume", "block attacks now (also ends the learning period)"), ("origin-test", "check the origin before DNS moves")):
        c = cmds.add_parser(name, help=text)
        c.add_argument("domain")
    s = cmds.add_parser("serve", help="run the edge server")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--host", default="127.0.0.1", help="0.0.0.0 inside Docker")
    r = cmds.add_parser("report", help="monthly PDF report for a client")
    r.add_argument("domain")
    r.add_argument("--month", default=date.today().strftime("%Y-%m"))
    r.add_argument("--output", default=None)
    c = cmds.add_parser("caddyfile", help="print the Caddy config for HTTPS on demand")
    c.add_argument("--email", required=True, help="for Let's Encrypt")
    c.add_argument("--aegis", default="aegis:8080", help="where Caddy reaches Aegis (127.0.0.1:8080 without Docker)")


def run(args) -> int:
    from .server import Edge, Settings
    from .sites import Registry, Site

    home = Path(args.home)
    registry = Registry(home / "sites.json")
    cmd = args.edge_command

    if cmd == "init":
        home.mkdir(parents=True, exist_ok=True)
        (home / "logs").mkdir(exist_ok=True)
        (home / "stats").mkdir(exist_ok=True)
        settings = Settings.load(home / "settings.json")
        for key in ("telegram_token", "server_ip", "contact", "brand"):
            value = getattr(args, key)
            if value:
                setattr(settings, key, value)
        settings.owner_chats = sorted(set(settings.owner_chats) | set(args.owner_chat))
        settings.save(home / "settings.json")
        if not registry.path.exists():
            registry.save([])
        print(f"Aegis Edge: {home}")
        print("  settings.json  " + ("Telegram подключён" if settings.telegram_token else
                                     "без Telegram (добавьте --telegram-token от @BotFather)"))
        print("Дальше: aegis edge add shop.kz --origin <IP сервера сайта> --cms wordpress")
        return 0

    if cmd == "add":
        try:
            aliases = list(args.alias)
            bare = re.sub(r"^www\.", "", args.domain.lower())
            if not args.no_www and not args.domain.lower().startswith("www."):
                aliases.append(f"www.{bare}")
            site = Site(args.domain, args.origin, cms=args.cms, aliases=aliases, client=args.client, plan=args.plan,
                        chats=args.chat, tls_verify=not args.no_verify, rate_limit=args.rate_limit,
                        login_limit=args.login_limit)
            site = registry.add(site, learn_days=args.learn_days)
        except ValueError as exc:
            print(f"aegis edge: {exc}", file=sys.stderr)
            return 2
        settings = Settings.load(home / "settings.json")
        ip = settings.server_ip or "<IP этого сервера>"
        print(f"{site.domain}: добавлен ({site.cms}), {site.status_ru()}")
        print("\nПроверьте origin до смены DNS:  aegis edge origin-test " + site.domain)
        print("\nКлиенту — изменить DNS (у регистратора или хостинга):")
        for host in site.hosts():
            label = "@" if host == site.domain else host[: -len(site.domain) - 1]
            print(f"  A  {label:<6} →  {ip}")
        print("  (AAAA-записи для этих имён удалить; TTL можно поставить 300)")
        return 0

    if cmd == "list":
        sites = registry.load()
        if not sites:
            print("Сайтов пока нет: aegis edge add shop.kz --origin <IP>")
            return 0
        for s in sites:
            print(f"{s.domain:<32} {s.cms:<10} {s.status_ru():<48} {s.client}")
        return 0

    if cmd in ("remove", "pause", "resume"):
        try:
            if cmd == "remove":
                site = registry.remove(args.domain)
                print(f"{site.domain}: больше не защищается. Верните DNS клиента на {site.origin}.")
            else:
                changes = {"mode": "monitor"} if cmd == "pause" else {"mode": "block", "learn_until": ""}
                site = registry.update(args.domain, **changes)  # resume = block now, learning or not
                print(f"{site.domain}: {site.status_ru()}")
        except (KeyError, ValueError) as exc:
            print(f"aegis edge: {exc.args[0] if exc.args else exc}", file=sys.stderr)
            return 2
        return 0

    if cmd == "origin-test":
        site = registry.get(args.domain)
        if site is None:
            print(f"aegis edge: нет такого сайта: {args.domain}", file=sys.stderr)
            return 2
        return origin_test(site)

    if cmd == "serve":
        edge = Edge(home)
        edge.start(args.port, args.host)
        print(f"Aegis Edge: {len(edge.sites)} сайт(ов), http://{args.host}:{args.port}"
              + (", Telegram включён" if edge.bot else ""), flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            edge.stop()
        return 0

    if cmd == "report":
        site = registry.get(args.domain)
        if site is None:
            print(f"aegis edge: нет такого сайта: {args.domain}", file=sys.stderr)
            return 2
        from .report import build_report
        edge_like = _Offline(home)
        try:
            pdf = build_report(edge_like, site, args.month)
        except ValueError as exc:
            print(f"aegis edge: {exc}", file=sys.stderr)
            return 2
        out = Path(args.output or f"aegis-{site.domain}-{args.month}.pdf")
        out.write_bytes(pdf)
        print(f"{out} ({len(pdf) // 1024} КБ)")
        return 0

    if cmd == "caddyfile":
        print(CADDYFILE.format(email=args.email, aegis=args.aegis), end="")
        return 0
    return 2


class _Offline:
    """Enough of an Edge for building reports from the files on disk."""

    def __init__(self, home: Path):
        from .server import Settings
        from .stats import Stats
        self.settings = Settings.load(home / "settings.json")
        self.stats = Stats(home / "stats")


def origin_test(site) -> int:
    """Fetch the home page from the origin the way Aegis will: Host and SNI = the site name."""
    import http.client

    from ..proxy import Origin, _TLSConnection

    origin = Origin(site.origin, preserve_host=True, tls_verify=site.tls_verify)
    print(f"{site.domain} → {origin.scheme}://{origin.host}:{origin.port}")
    try:
        if origin.scheme == "https":
            ctx = ssl.create_default_context()
            if not site.tls_verify:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = _TLSConnection(origin.host, origin.port, site.domain, ctx, 15)
        else:
            conn = http.client.HTTPConnection(origin.host, origin.port, timeout=15)
        t0 = time.time()
        conn.request("GET", "/", headers={"Host": site.domain, "User-Agent": "AegisEdge-origin-test/1.0",
                                          "Accept": "text/html"})
        resp = conn.getresponse()
        body = resp.read(200_000)
        ms = (time.time() - t0) * 1000
    except ssl.SSLCertVerificationError as exc:
        print(f"  ✗ сертификат origin не подходит для {site.domain}: {exc.verify_message}")
        print("    Если у сайта самоподписанный сертификат: aegis edge remove и add с --no-verify")
        return 1
    except (OSError, http.client.HTTPException) as exc:
        print(f"  ✗ origin не отвечает: {exc}")
        return 1
    title = re.search(rb"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    print(f"  ✓ {resp.status} {resp.reason} за {ms:.0f} мс")
    if title:
        print(f"  заголовок страницы: {title.group(1).decode('utf-8', 'replace').strip()[:100]}")
    if resp.status in (301, 302, 307, 308):
        print(f"  редирект на {resp.getheader('Location')} — это нормально, если ведёт на тот же домен")
    if resp.status >= 500:
        print("  ✗ origin отвечает ошибкой — DNS пока не переключайте")
        return 1
    print("Можно переключать DNS.")
    return 0
