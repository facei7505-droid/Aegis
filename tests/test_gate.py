"""Siege mode: a proof-of-work gate. People pass after a second of work, bots without a browser do not."""
from __future__ import annotations

import hashlib
import http.client
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.gateway import AppSpec, Gateway, serve
from aegis.shield.gate import Gate, leading_zero_bits

ENV = {"HTTP_USER_AGENT": "Mozilla/5.0 Chrome/130", "HTTP_ACCEPT": "text/html"}


def solve(challenge: str, bits: int) -> int:
    n = 0
    while leading_zero_bits(hashlib.sha256(f"{challenge}{n}".encode()).digest()) < bits:
        n += 1
    return n


def test_zero_bits():
    assert leading_zero_bits(b"\x00\x00\x80") == 16
    assert leading_zero_bits(b"\x00\x0f") == 12
    assert leading_zero_bits(b"\xff") == 0


def test_challenge_pass_and_binding():
    gate = Gate("s" * 64, bits=8)
    c = gate.challenge("203.0.113.5", ENV, now=1_000_000)
    n = str(solve(c, 8))
    assert gate.solved("203.0.113.5", ENV, c, n, now=1_000_000)
    assert gate.solved("203.0.113.5", ENV, c, n, now=1_000_000 + 300)          # the previous window still counts
    assert not gate.solved("203.0.113.5", ENV, c, n, now=1_000_000 + 900)      # stale
    assert not gate.solved("203.0.113.6", ENV, c, n, now=1_000_000)            # another address
    assert not gate.solved("203.0.113.5", {**ENV, "HTTP_USER_AGENT": "curl"}, c, n, now=1_000_000)
    assert not gate.solved("203.0.113.5", ENV, c, "x1", now=1_000_000)
    token = gate.issue_pass("203.0.113.5", ENV, now=1_000_000)
    env = {**ENV, "HTTP_COOKIE": f"a=1; aegis_pass={token}"}
    assert gate.has_pass("203.0.113.5", env, now=1_000_000 + 3600)
    assert not gate.has_pass("203.0.113.5", env, now=1_000_000 + 13 * 3600)   # 12 hours
    assert not gate.has_pass("198.51.100.1", env, now=1_000_000)


@pytest.mark.parametrize("preset, path, query, exempt", [
    ("bitrix", "/bitrix/tools/sale_ps_result.php", "", True),
    ("bitrix", "/bitrix/admin/1c_exchange.php", "type=sale", True),
    ("wordpress", "/", "wc-api=kaspi", True),
    ("generic", "/api/orders", "", True),
    ("generic", "/static/app.css", "", True),
    ("generic", "/catalog/", "", False),
    ("bitrix", "/bitrix/tools/../admin/", "", False),
])
def test_server_to_server_paths_skip_the_gate(preset, path, query, exempt):
    assert Gate(preset=preset).exempt({"PATH_INFO": path, "QUERY_STRING": query}) is exempt


class Shop(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html>shop</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture
def gateway():
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Shop)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    gw = Gateway([AppSpec("shop.kz", f"http://127.0.0.1:{origin.server_address[1]}", ["shop.kz"], heal="off",
                          options={"preset": "bitrix", "siege_bits": 8, "siege_auto": 50})])
    events = []
    gw.on_siege = lambda spec, on, reason: events.append((spec.name, on, reason))
    servers = serve(gw, port)

    def request(method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request(method, path, headers={"Host": "shop.kz", **ENV_HEADERS, **(headers or {})})
        resp = conn.getresponse()
        return resp, resp.read()

    yield gw, request, events
    for s in servers:
        s.shutdown()
    origin.shutdown()


ENV_HEADERS = {"User-Agent": "Mozilla/5.0 Chrome/130", "Accept": "text/html"}


def test_a_person_passes_the_gate(gateway):
    gw, request, events = gateway
    assert request("GET", "/catalog/")[0].status == 200
    assert gw.siege("shop.kz", 10, "test")
    assert events == [("shop.kz", True, "test")]
    resp, page = request("GET", "/catalog/?sort=price")
    assert resp.status == 503 and b"SHA" not in page and b"aegis/gate" in page
    challenge = re.search(rb'C="([0-9a-f]{32})"', page).group(1).decode()
    assert re.search(rb"BACK=\"/catalog/\?sort=price\"", page)
    n = solve(challenge, 8)
    resp, _ = request("GET", f"/_aegis/gate?c={challenge}&n={n}&r=/catalog/%3Fsort%3Dprice")
    assert resp.status == 303 and resp.getheader("Location") == "/catalog/?sort=price"
    cookie = resp.getheader("Set-Cookie").split(";")[0]
    assert request("GET", "/catalog/", {"Cookie": cookie})[0].status == 200
    assert request("GET", "/bitrix/tools/sale_ps_result.php")[0].status == 200       # payment callback
    resp, body = request("POST", "/order/")                                         # a bot posting blind
    assert resp.status == 503 and b"retry" in body
    resp, _ = request("GET", f"/_aegis/gate?c={challenge}&n=1&r=//evil.example/")   # wrong answer, foreign return
    assert resp.status == 303 and resp.getheader("Location") == "/" and resp.getheader("Set-Cookie") is None
    assert gw.lift_siege("shop.kz") and events[-1] == ("shop.kz", False, "manual")
    assert request("GET", "/catalog/")[0].status == 200


def test_a_flood_starts_the_siege_by_itself(gateway):
    gw, request, events = gateway
    for _ in range(60):
        request("GET", "/static/app.css")                     # page assets do not count toward a flood
    assert not gw.siege_active("shop.kz")
    for _ in range(51):
        request("GET", "/")
    assert gw.siege_active("shop.kz") and events[0][1] is True and "50" in events[0][2]
    assert request("GET", "/")[0].status == 503
