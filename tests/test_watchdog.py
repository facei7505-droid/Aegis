"""Failover watchdog: Aegis down -> sites point at their own servers and stay open; Aegis back -> protected again."""
from __future__ import annotations

import http.client
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.edge import connector
from aegis.edge.watchdog import Cloudflare, Command, Site, Watchdog, label, record_for
from aegis.gateway import AppSpec, Gateway, serve
from aegis.shield.signing import failover_token, verify_failover

PHP = shutil.which("php")
SECRET = "c" * 64


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeDNS:
    def __init__(self):
        self.records: dict[str, tuple[str, str]] = {}

    def set(self, name, rtype, content):
        self.records[name] = (rtype, content)


def test_names_and_records():
    assert label("shop.kz") == "shop-kz"
    assert record_for("198.51.100.7") == ("A", "198.51.100.7")
    assert record_for("2001:db8::7") == ("AAAA", "2001:db8::7")
    assert record_for("shop.hoster.kz") == ("CNAME", "shop.hoster.kz")


def test_failover_token():
    now = 1_800_000_000
    token = failover_token(SECRET, "shop.kz", now + 1800)
    assert verify_failover(SECRET, token, "SHOP.kz:443", now)
    assert not verify_failover(SECRET, token, "other.kz", now)
    assert not verify_failover(SECRET, token, "shop.kz", now + 1801)                     # ran out
    assert not verify_failover(SECRET, failover_token(SECRET, "shop.kz", now + 90000), "shop.kz", now)  # > a day


def test_watchdog_fails_over_and_comes_back():
    port = free_port()
    gw = Gateway([AppSpec("shop", "http://127.0.0.1:9", ["shop.kz"], heal="off", preserve_host=True)])
    servers = serve(gw, port)
    dns, messages = FakeDNS(), []
    dog = Watchdog(server=f"http://127.0.0.1:{port}", edge_domain="shield.kz",
                   sites=[Site("shop.kz", "https://198.51.100.7")], dns=dns, notify=messages.append,
                   fail_after=2, recover_after=2, timeout=2)
    try:
        assert dog.tick() == "ok"
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
    assert dog.tick() == "down"
    assert dns.records == {}
    assert dog.tick() == "failed-over"
    assert dns.records == {"shop-kz.shield.kz": ("A", "198.51.100.7")}
    assert "переключены" in messages[-1]
    assert dog.tick() == "still-down"

    servers = serve(gw, port)
    try:
        assert dog.tick() == "recovering"
        assert dog.tick() == "restored"
        assert dns.records == {"shop-kz.shield.kz": ("A", "127.0.0.1")}
        assert "снова работает" in messages[-1]
        assert dog.tick() == "ok"
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


def test_ping_only_for_known_sites():
    port = free_port()
    servers = serve(Gateway([AppSpec("shop", "http://127.0.0.1:9", ["shop.kz"], heal="off")]), port)
    try:
        for host, alive in (("shop.kz", True), ("unknown.kz", False)):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/_aegis/ping", headers={"Host": host})
            resp = conn.getresponse()
            resp.read()
            assert (resp.status == 204 and resp.getheader("X-Aegis-Edge") == "alive") is alive
    finally:
        for s in servers:
            s.shutdown()


class FakeCloudflare(BaseHTTPRequestHandler):
    calls: list = []
    records: dict = {}

    def _reply(self, result):
        body = json.dumps({"success": True, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _payload(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")

    def do_GET(self):
        assert self.headers["Authorization"] == "Bearer tok"
        name = self.path.split("name=")[1]
        self.calls.append(("GET", name))
        self._reply([{"id": k, **v} for k, v in self.records.items() if v["name"] == name])

    def do_POST(self):
        data = self._payload()
        self.records[f"id{len(self.records)}"] = data
        self.calls.append(("POST", data["name"], data["content"]))
        self._reply(data)

    def do_PUT(self):
        data = self._payload()
        self.records[self.path.rsplit("/", 1)[1]] = data
        self.calls.append(("PUT", data["name"], data["content"], data["ttl"]))
        self._reply(data)

    def log_message(self, *a):
        pass


def test_cloudflare_provider_creates_then_updates():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeCloudflare)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cf = Cloudflare("tok", "zone1", api=f"http://127.0.0.1:{srv.server_address[1]}")
        cf.set("shop-kz.shield.kz", "A", "203.0.113.10")
        cf.set("shop-kz.shield.kz", "A", "198.51.100.7")
        assert FakeCloudflare.calls == [("GET", "shop-kz.shield.kz"), ("POST", "shop-kz.shield.kz", "203.0.113.10"),
                                        ("GET", "shop-kz.shield.kz"), ("PUT", "shop-kz.shield.kz", "198.51.100.7", 60)]
    finally:
        srv.shutdown()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
def test_command_provider(tmp_path):
    out = tmp_path / "dns.txt"
    Command(f'echo "$AEGIS_DNS_NAME $AEGIS_DNS_TYPE $AEGIS_DNS_CONTENT $AEGIS_DNS_TTL" > {out}').set(
        "shop-kz.shield.kz", "A", "198.51.100.7")
    assert out.read_text().strip() == "shop-kz.shield.kz A 198.51.100.7 60"


@pytest.mark.skipif(PHP is None or sys.platform == "win32", reason="php not installed")
def test_failover_opens_a_locked_site(tmp_path):
    """The connector refuses direct visitors until the watchdog's signed token arrives, then lets them in."""
    name, source = connector.render("generic", SECRET, "enforce")
    (tmp_path / name).write_text(source)
    (tmp_path / "index.php").write_text("<?php define('AEGIS_TRUST_LOCAL', false); require __DIR__ . '/" + name +
                                        "'; echo 'shop';")
    port = free_port()
    env = {"TMPDIR": str(tmp_path)}
    srv = subprocess.Popen([PHP, "-S", f"127.0.0.1:{port}", "-t", str(tmp_path)], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)

        def visit():
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/", headers={"Host": "shop.kz"})
            resp = conn.getresponse()
            return resp.status, resp.read().decode()

        assert visit()[0] == 403
        dog = Watchdog(server="http://127.0.0.1:9", edge_domain="shield.kz", dns=FakeDNS(),
                       sites=[Site("shop.kz", f"http://127.0.0.1:{port}", "d" * 64)])
        assert not dog.open_origin(dog.sites[0], time.time())      # wrong secret: stays locked
        assert visit()[0] == 403
        dog.sites[0].secret = SECRET
        assert dog.open_origin(dog.sites[0], time.time())
        assert visit() == (200, "shop")
    finally:
        srv.terminate()
        srv.wait(10)
