"""Site guard: down/up, new outside scripts (skimmers), obfuscated loaders, SEO spam, defacement."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from aegis.edge.guard import Baseline, Guard, Snapshot, compare, fetch, snapshot
from aegis.shield.signing import verify_origin

SHOP = """<html><head><title>Ромашка — магазин одежды в Шымкенте</title>
<script src="https://mc.yandex.ru/metrika/tag.js"></script>
<script src="/bitrix/js/main/core.js"></script><script src="https://cdn.shop.kz/app.js"></script>
<script>window.dataLayer=[];</script></head><body><h1>Платья и костюмы</h1>
<iframe src="https://yandex.ru/map-widget/v1/?um=1"></iframe></body></html>"""
SKIMMER = SHOP.replace("</head>", '<script src="https://cdn-jsdelivr-analytics.top/s.js"></script></head>')
PACKED = SHOP.replace("</head>", "<script>eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHBzOi8vZXZpbCc='))</script></head>")
SPAM = SHOP.replace("</body>", '<div style="display:none">лучшее онлайн-казино 1xbet и vavada</div></body>')
DEFACED = "<html><title>Hacked by Gh0st</title><body>Hacked by Gh0st team</body></html>"


def test_snapshot_reads_what_matters():
    snap = snapshot(SHOP, "shop.kz")
    assert snap.title == "Ромашка — магазин одежды в Шымкенте"
    assert snap.script_domains == ["mc.yandex.ru"]           # cdn.shop.kz is the site's own subdomain
    assert snap.iframe_domains == ["yandex.ru"]
    assert snap.loaders == [] and snap.spam == [] and snap.defaced == ""


def look(base, html, learning=False, first=False):
    return [kind for kind, _ in compare(base, snapshot(html, "shop.kz"), learning, first)]


def test_first_look_and_learning_only_record():
    base = Baseline()
    assert look(base, SKIMMER, first=True) == []
    assert "cdn-jsdelivr-analytics.top" in base.script_domains
    base = Baseline()
    assert look(base, SHOP, first=True) == []
    assert look(base, SKIMMER, learning=True) == []           # learning: the owner may be adding widgets


def test_alerts_once_per_new_thing():
    base = Baseline()
    look(base, SHOP, first=True)
    assert look(base, SHOP) == []
    assert look(base, SKIMMER) == ["new_script"]
    assert look(base, SKIMMER) == []                           # told once, then remembered
    assert look(base, PACKED) == ["loader"]
    assert look(base, SPAM) == ["spam"]
    assert look(base, DEFACED) == ["deface", "title"]


def test_down_twice_then_up():
    base = Baseline()
    look(base, SHOP, first=True)
    down = Snapshot(error="Connection refused")
    assert compare(base, down, False, False) == []             # one miss is not an outage
    assert [k for k, _ in compare(base, down, False, False)] == ["down"]
    assert compare(base, down, False, False) == []             # reported once
    assert look(base, SHOP) == ["up"]


class Origin(BaseHTTPRequestHandler):
    page = SHOP
    seen: list = []

    def do_GET(self):
        Origin.seen.append(dict(self.headers))
        body = Origin.page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_guard_fetches_signed_and_tells_the_owner(tmp_path):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        site = SimpleNamespace(domain="shop.kz", origin=f"http://127.0.0.1:{srv.server_address[1]}", tls_verify=True,
                               secret="e" * 64, chats=[555], learning=lambda today: False)
        sent = []
        edge = SimpleNamespace(home=tmp_path, sites={"shop.kz": site}, settings=SimpleNamespace(owner_chats=[111]),
                               bot=SimpleNamespace(send=lambda chat, text: sent.append((chat, text))))
        guard = Guard(edge)
        assert guard.run_once() == {"shop.kz": []}
        headers = Origin.seen[-1]
        assert headers["Host"] == "shop.kz" and verify_origin("e" * 64, headers["X-Aegis-Auth"], "shop.kz", "127.0.0.1")
        Origin.page = SKIMMER
        assert [k for k, _ in guard.run_once()["shop.kz"]] == ["new_script"]
        assert {chat for chat, _ in sent} == {111, 555} and "cdn-jsdelivr-analytics.top" in sent[0][1]
        assert (tmp_path / "guard" / "shop.kz.json").is_file()
    finally:
        srv.shutdown()
        Origin.page = SHOP


def test_fetch_reports_an_unreachable_site():
    site = SimpleNamespace(domain="shop.kz", origin="http://127.0.0.1:9", tls_verify=True, secret="")
    snap = fetch(site, timeout=2)
    assert not snap.up and snap.error
