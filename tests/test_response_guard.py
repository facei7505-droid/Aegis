"""Response guard: the origin's answer confirms injection points and successful attacks."""
from __future__ import annotations

import gzip
import http.client
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from aegis.gateway import AppSpec, Gateway, serve
from aegis.shield.response import LearnedPatches, decode, examine, request_fields

MYSQL = b"<b>Warning</b>: You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
PHP_WARNING = b"<br />\n<b>Warning</b>:  Undefined variable $cart in <b>/var/www/shop/cart.php</b> on line <b>12</b><br />"


def test_examine():
    assert examine(MYSQL.decode(), {"id": "5'"}).fields == ["id"]
    assert examine(MYSQL.decode(), {"id": "5'"}).block
    leak = examine(MYSQL.decode(), {"q": "кроссовки"})             # the site is broken, not attacked
    assert leak.kind == "sql_error" and not leak.block
    assert examine(PASSWD.decode(), {}).kind == "system_file"
    assert examine("uid=33(www-data) gid=33(www-data) groups=33(www-data)", {}).kind == "system_file"
    assert examine(PHP_WARNING.decode(), {}).kind == "php_error" and not examine(PHP_WARNING.decode(), {}).block
    assert examine("<title>Ani-Shell | India</title>", {}).kind == "web_shell"
    for page in ("<h1>Ошибка SQL в отчёте бухгалтера</h1>", "Warning: low stock", "root of the problem",
                 "You have an error in your order form"):
        assert examine(page, {"q": "1'"}) is None


def test_decode():
    assert decode(gzip.compress(b"hello"), "gzip") == "hello"
    assert decode(gzip.compress(b"x" * 100_000)[:2000], "gzip").startswith("x")   # a partial stream still reads
    assert decode(b"abc", "br") is None


def test_request_fields():
    assert request_fields("/a?id=1&q=x", b"name=O%27Brien", "application/x-www-form-urlencoded") == \
        {"id": "1", "q": "x", "name": "O'Brien"}


def test_learned_patches(tmp_path):
    patches = LearnedPatches(tmp_path / "learned.json")
    assert patches.learn("/catalog/", "id", "5'", "You have an error")
    assert not patches.learn("/catalog", "id", "6'", "again")                # once per field
    assert patches.check("/catalog", {"id": "5"}) is None
    assert patches.check("/catalog", {"id": "5 or 1=1"})["kind"] == "numeric"
    assert patches.learn("/search", "q", "o'brien", "error")
    assert patches.check("/search", {"q": "кроссовки 42"}) is None
    assert patches.check("/search", {"q": "x'--"})["kind"] == "text"
    assert len(LearnedPatches(tmp_path / "learned.json")) == 2                # kept on disk


class Shop(BaseHTTPRequestHandler):
    """A shop with a real bug: `id` goes into SQL unescaped, so a quote breaks the query."""

    def _send(self, body: bytes, ctype="text/html; charset=utf-8", extra=()):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        for k, v in extra:
            self.send_header(k, v)
        if ("Transfer-Encoding", "chunked") in extra:
            self.end_headers()
            self.wfile.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body))
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/product":
            if "'" in q.get("id", "") or '"' in q.get("id", ""):
                return self._send(b"<html>" + MYSQL + b"</html>")
            return self._send(b"<html>product " + q.get("id", "").encode() + b"</html>")
        if url.path == "/download":
            return self._send(PASSWD, "text/plain")
        if url.path == "/cart":
            return self._send(gzip.compress(b"<html>" + PHP_WARNING + b"cart</html>"), extra=[("Content-Encoding", "gzip")])
        if url.path == "/report":
            return self._send(b"<html>" + MYSQL + b"</html>", extra=[("Transfer-Encoding", "chunked")])
        self._send(b"<html>ok</html>")

    def log_message(self, *a):
        pass


@pytest.fixture
def shop_gateway(tmp_path):
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Shop)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    gw = Gateway([AppSpec("shop", f"http://127.0.0.1:{origin.server_address[1]}", ["shop.kz"], heal="off",
                          preserve_host=True, options={"trust_proxy": True, "ban_after": 10})], log_dir=str(tmp_path))
    servers = serve(gw, port)

    def get(path, client="203.0.113.5"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", path, headers={"Host": "shop.kz", "X-Forwarded-For": client, "Accept": "text/html",
                                           "Accept-Encoding": "gzip, br"})
        resp = conn.getresponse()
        return resp.status, resp.read()

    yield gw, get
    for s in servers:
        s.shutdown()
    origin.shutdown()


def test_confirmed_injection_point_is_closed(shop_gateway):
    gw, get = shop_gateway
    core = gw.shields["shop"].core
    assert get("/product?id=5") == (200, b"<html>product 5</html>")
    status, body = get("/product?id=5%27")                      # a lone quote: no signature flags it
    assert status == 403 and b"SQL syntax" not in body           # the attacker never sees the error
    inc = core.incidents[-1]
    assert inc.attack_type == "injection_point" and inc.param == "id" and inc.location == "response"
    status, _ = get("/product?id=5%22", client="203.0.113.6")   # another address, another quote: refused up front
    assert status == 403 and core.incidents[-1].signals[0] == "confirmed injection point"
    assert get("/product?id=7", client="203.0.113.6")[0] == 200  # ordinary use of the page still works


def test_leaked_system_file_is_replaced(shop_gateway):
    gw, get = shop_gateway
    status, body = get("/download?file=report.pdf")
    assert status == 403 and b"root:x" not in body
    assert gw.shields["shop"].core.incidents[-1].attack_type == "exploit_confirmed"
    assert get("/")[0] == 403                                    # that address does not get a second try
    assert get("/", client="203.0.113.77")[0] == 200


def test_php_warnings_are_reported_not_blocked(shop_gateway):
    gw, get = shop_gateway
    status, body = get("/cart")                                   # no fields: streamed, read afterwards
    assert status == 200 and gzip.decompress(body).endswith(b"cart</html>")
    gw.shields["shop"].app.guard.drain()
    inc = gw.shields["shop"].core.incidents[-1]
    assert inc.attack_type == "data_leak" and not inc.blocked
    count = len(gw.shields["shop"].core.incidents)
    get("/cart")
    gw.shields["shop"].app.guard.drain()
    assert len(gw.shields["shop"].core.incidents) == count       # one report per page and hour


def test_streamed_answers_are_read_on_the_way(shop_gateway):
    gw, get = shop_gateway
    status, body = get("/report?id=1%27")
    assert status == 200                                          # already on its way: cannot be stopped...
    gw.shields["shop"].app.guard.drain()
    inc = gw.shields["shop"].core.incidents[-1]                   # ...but the field is closed for next time
    assert inc.attack_type == "injection_point"
    assert get("/report?id=2%27")[0] == 403


def test_origin_never_gets_brotli(shop_gateway):
    from aegis.proxy import Origin, Proxy
    proxy = Proxy(Origin("http://127.0.0.1:9"), guard=lambda *a: None)
    headers = proxy.request_headers({"HTTP_HOST": "shop.kz", "HTTP_ACCEPT_ENCODING": "gzip, deflate, br, zstd",
                                     "REMOTE_ADDR": "127.0.0.1"})
    assert headers["Accept-Encoding"] == "gzip, deflate"


def test_pages_without_fields_stream_and_are_read_later(shop_gateway):
    gw, get = shop_gateway
    guard = gw.shields["shop"].app.guard
    assert guard.inline({}, "/product?id=1", None) and guard.inline({"RAW_URI": "/a/..%2f..%2fetc"}, "/a", None)
    assert not guard.inline({"PATH_INFO": "/catalog/"}, "/catalog/", None)
    status, _ = get("/download")                                  # no fields, still a leaked system file
    guard.drain()
    assert status == 200 and gw.shields["shop"].core.incidents[-1].attack_type == "exploit_confirmed"
