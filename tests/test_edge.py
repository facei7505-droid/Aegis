"""Aegis Edge: client sites, learning period, hot reload, TLS check, stats, Telegram, reports, CLI."""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.cli import main
from aegis.edge.server import Edge, Settings
from aegis.edge.sites import Registry, Site, normalize_domain
from aegis.edge.stats import Stats, prune_jsonl
from aegis.models import Incident


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Shop(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = f"<title>Магазин {self.headers.get('Host')}</title>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


@pytest.fixture(scope="module")
def shop():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Shop)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def get(port, host, path="/", method="GET", headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers={"Host": host, **(headers or {})})
    resp = conn.getresponse()
    return resp.status, resp.read()


def wait_for(cond, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


# ------------------------------------------------------------------ sites --

def test_domains_are_normalised():
    assert normalize_domain("https://WWW.Shop.KZ/catalog") == "www.shop.kz"
    assert normalize_domain("магазин.kz") == "xn--80aairftm.kz"
    for bad in ("shop", "-x.kz", "a..kz", "http://"):
        with pytest.raises(ValueError):
            normalize_domain(bad)


def test_site_validation_and_learning_period():
    site = Site("shop.kz", "198.51.100.7", "wordpress", aliases=["www.shop.kz", "shop.kz"])
    assert site.origin == "https://198.51.100.7" and site.aliases == ["www.shop.kz"]
    with pytest.raises(ValueError):
        Site("shop.kz", "1.2.3.4", cms="joomla")
    site.learn_until = (date.today() + timedelta(days=3)).isoformat()
    assert site.effective_mode() == "monitor" and "обучение" in site.status_ru()
    assert site.effective_mode(date.today() + timedelta(days=3)) == "block"
    site.mode = "monitor"
    assert site.effective_mode(date.today() + timedelta(days=30)) == "monitor"
    spec = site.to_spec()
    assert spec.preserve_host and spec.heal == "off" and spec.options["preset"] == "wordpress"
    assert spec.options["trust_proxy"] is True


def test_registry_is_atomic_and_refuses_duplicates(tmp_path):
    reg = Registry(tmp_path / "sites.json")
    reg.add(Site("shop.kz", "1.2.3.4", aliases=["www.shop.kz"]), learn_days=7)
    with pytest.raises(ValueError):
        reg.add(Site("www.shop.kz", "5.6.7.8"))
    assert reg.get("www.shop.kz").domain == "shop.kz"
    assert reg.update("shop.kz", mode="monitor").mode == "monitor"
    assert json.loads((tmp_path / "sites.json").read_text(encoding="utf-8"))[0]["learn_until"]
    reg.remove("shop.kz")
    assert reg.load() == [] and not list(tmp_path.glob(".sites.*"))
    with pytest.raises(KeyError):
        reg.remove("shop.kz")


# ------------------------------------------------------------------- edge --

@pytest.fixture
def edge(tmp_path, shop):
    reg = Registry(tmp_path / "sites.json")
    reg.add(Site("shop.kz", shop, "wordpress", aliases=["www.shop.kz"], chats=[222]), learn_days=0)
    e = Edge(tmp_path)
    port = free_port()
    servers = e.start(port)
    yield e, port, reg
    e.stop()
    for s in servers:
        s.shutdown()


def test_edge_serves_blocks_and_answers_caddy(edge):
    e, port, reg = edge
    status, body = get(port, "www.shop.kz")
    assert status == 200 and "www.shop.kz".encode() in body           # public Host reaches the origin
    status, body = get(port, "shop.kz", "/?author=1", headers={"Accept": "text/html"})
    assert status == 403 and "Запрос остановлен".encode() in body
    assert get(port, "127.0.0.1", "/_aegis/tls-ask?domain=www.shop.kz")[0] == 200
    assert get(port, "127.0.0.1", "/_aegis/tls-ask?domain=evil.example")[0] == 404
    assert json.loads(get(port, "127.0.0.1", "/_aegis/health")[1])["sites"] == 1
    status, body = get(port, "unknown.kz")        # from this machine an unknown name is the dashboard,
    assert status == 200 and b"Magazin" not in body and "Магазин".encode() not in body  # never a site


def test_new_sites_and_pauses_apply_without_restart(edge, shop):
    e, port, reg = edge
    time.sleep(0.05)
    reg.add(Site("second.kz", shop), learn_days=0)
    assert wait_for(lambda: get(port, "second.kz")[0] == 200)
    shield_before = e.gateway.shields["shop.kz"]
    reg.update("shop.kz", mode="monitor")
    assert wait_for(lambda: get(port, "shop.kz", "/?author=1")[0] == 200)  # paused: recorded, not blocked
    assert e.gateway.shields["shop.kz"] is not shield_before
    assert e.gateway.shields["second.kz"] is not None


def test_stats_count_requests_and_attacks(edge):
    e, port, _ = edge
    for _ in range(5):
        get(port, "shop.kz")
    get(port, "shop.kz", "/wp-content/uploads/x.php")
    e.stats.flush()
    with e.gateway._lock:
        e.stats.requests("shop.kz", e.gateway.requests["shop.kz"])
    day = e.stats.day("shop.kz", date.today().isoformat())
    assert day["requests"] >= 6 and day["blocked"] == 1 and day["patches"] == {"php-in-uploads": 1}


def test_stats_files_and_retention(tmp_path):
    stats = Stats(tmp_path)
    inc = Incident(id="a1", timestamp=time.time(), client="203.0.113.5", method="GET", path="/?id=1'",
                   location="query", param="id", payload="1'", attack_type="sqli", score=0.9, blocked=True,
                   detect_ms=0.1)
    stats.incident("shop.kz", inc)
    stats.requests("shop.kz", 100)
    stats.flush()
    stats.incident("shop.kz", inc)
    stats.flush()
    today = date.today()
    d = stats.day("shop.kz", today.isoformat())
    assert d["requests"] == 100 and d["attacks"] == 2 and d["by_type"] == {"sqli": 2}
    old = tmp_path / "shop.kz" / "2020-01-01.json"
    old.write_text("{}")
    assert stats.prune(90) == 1 and not old.exists()
    total = stats.period("shop.kz", today - timedelta(days=2), today)
    assert total["attacks"] == 2 and len(total["series"]) == 3
    log = tmp_path / "x.incidents.jsonl"
    log.write_text(json.dumps({"timestamp": 1}) + "\n" + json.dumps({"timestamp": time.time()}) + "\n")
    assert prune_jsonl(log, 30) == 1 and len(log.read_text().splitlines()) == 1


# --------------------------------------------------------------- Telegram --

class FakeTelegram(BaseHTTPRequestHandler):
    sent: list = []
    updates: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(size)
        method = self.path.rsplit("/", 1)[-1]
        if method == "getUpdates":
            result, FakeTelegram.updates = list(FakeTelegram.updates), []
            body = {"ok": True, "result": result}
        else:
            if self.headers.get("Content-Type", "").startswith("application/json"):
                FakeTelegram.sent.append((method, json.loads(raw)))
            else:
                FakeTelegram.sent.append((method, {"multipart": raw}))
            body = {"ok": True, "result": {}}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def telegram():
    FakeTelegram.sent, FakeTelegram.updates = [], []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeTelegram)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def bot_edge(tmp_path, shop, telegram):
    Settings(telegram_token="TEST:TOKEN", owner_chats=[111], alert_cooldown=600).save(tmp_path / "settings.json")
    Registry(tmp_path / "sites.json").add(Site("shop.kz", shop, "wordpress", chats=[222]), learn_days=0)
    e = Edge(tmp_path, telegram_api=telegram)
    e.bot.poll_timeout = 0
    port = free_port()
    servers = e.start(port)
    yield e, port
    e.stop()
    for s in servers:
        s.shutdown()


def messages(chat=None):
    return [p for m, p in FakeTelegram.sent if m == "sendMessage" and (chat is None or p["chat_id"] == chat)]


def test_alerts_reach_owner_and_client_once_per_kind(bot_edge):
    e, port = bot_edge
    for i in range(4):
        get(port, "shop.kz", f"/?author={i}")
    assert wait_for(lambda: len(messages()) >= 2)
    time.sleep(0.5)
    assert {m["chat_id"] for m in messages()} == {111, 222} and len(messages()) == 2  # repeats folded
    text = messages(222)[0]["text"]
    assert "shop.kz" in text and "перебор имён пользователей" in text.lower()


def test_commands_respect_who_is_asking(bot_edge):
    e, _ = bot_edge
    bot = e.bot
    assert "333" in bot.handle(333, "/start")               # strangers only learn their chat id
    assert bot.handle(333, "/status") is None and bot.handle(333, "/pause shop.kz") is None
    assert "защита включена" in bot.handle(222, "/status")
    assert "блокировки выключены" in bot.handle(222, "/pause")
    assert e.registry.get("shop.kz").mode == "monitor"
    assert "защита включена" in bot.handle(222, "/resume shop.kz")
    assert bot.handle(222, "/sites") is None and "shop.kz" in bot.handle(111, "/sites")
    assert "не IP" in bot.handle(222, "/unban nonsense")
    assert "нигде не заблокирован" in bot.handle(111, "/unban 203.0.113.9")


def test_polling_and_report_delivery(bot_edge):
    pytest.importorskip("reportlab")
    e, port = bot_edge
    get(port, "shop.kz", "/wp-content/uploads/a.php")
    e.stats.flush()
    FakeTelegram.updates = [{"update_id": 7, "message": {"chat": {"id": 222}, "text": "/report"}},
                            {"update_id": 8, "message": {"chat": {"id": 222}, "text": "/id"}}]
    assert wait_for(lambda: any(m == "sendDocument" for m, _ in FakeTelegram.sent), timeout=10)
    doc = next(p for m, p in FakeTelegram.sent if m == "sendDocument")["multipart"]
    assert b"%PDF" in doc and b'name="chat_id"\r\n\r\n222' in doc
    assert e.bot._offset == 9


# ----------------------------------------------------------------- report --

def test_report_pdf_and_advice(tmp_path):
    pytest.importorskip("reportlab")
    from aegis.edge.report import advice, build_report

    Registry(tmp_path / "sites.json").add(Site("shop.kz", "1.2.3.4", "bitrix"), learn_days=0)

    class E:
        settings = Settings(contact="@aegis_kz")
        stats = Stats(tmp_path / "stats")

    inc = Incident(id="b2", timestamp=time.time(), client="45.9.20.1", method="POST", path="/bitrix/tools/vote/uf.php",
                   location="path", param="bx-cve-2022-27228", payload="", attack_type="virtual_patch", score=1.0,
                   blocked=True, detect_ms=0.1)
    E.stats.incident("shop.kz", inc)
    E.stats.flush()
    site = Registry(tmp_path / "sites.json").get("shop.kz")
    pdf = build_report(E, site, date.today().strftime("%Y-%m"))
    assert pdf.startswith(b"%PDF") and len(pdf) > 5000
    tips = advice(site, E.stats.period("shop.kz", date.today(), date.today()))
    assert any("CVE-2022-27228" in t for t in tips)
    with pytest.raises(ValueError):
        build_report(E, site, "2026-13")


# -------------------------------------------------------------------- CLI --

def test_cli_round_trip(tmp_path, shop, capsys):
    home = ["edge", "--home", str(tmp_path)]
    assert main(home + ["init", "--server-ip", "203.0.113.10", "--owner-chat", "111"]) == 0
    assert main(home + ["add", "shop.kz", "--origin", shop, "--cms", "wordpress", "--client", "ИП Ромашка"]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.10" in out and "www" in out and "обучение" in out
    assert main(home + ["add", "www.shop.kz", "--origin", shop]) == 2
    assert main(home + ["origin-test", "shop.kz"]) == 0
    assert "Можно переключать DNS" in capsys.readouterr().out
    assert main(home + ["pause", "shop.kz"]) == 0 and main(home + ["resume", "shop.kz"]) == 0
    assert main(home + ["list"]) == 0 and "ИП Ромашка" in capsys.readouterr().out
    assert main(home + ["caddyfile", "--email", "me@x.kz"]) == 0 and "on_demand" in capsys.readouterr().out
    if pytest.importorskip("reportlab"):
        out_pdf = tmp_path / "r.pdf"
        assert main(home + ["report", "shop.kz", "--output", str(out_pdf)]) == 0 and out_pdf.read_bytes()[:4] == b"%PDF"
    assert main(home + ["remove", "shop.kz"]) == 0 and main(home + ["remove", "shop.kz"]) == 2
