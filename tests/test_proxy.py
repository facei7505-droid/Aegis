"""The proxy in front of real sites: Host, TLS to the origin, streaming, cookies, redirects, failures."""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.gateway import AppSpec, Gateway, serve
from aegis.proxy import Origin, Proxy

BIG = 5 * 1024 * 1024


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen_sni: list = []

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="application/json", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/connector":
            body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
            return self._send(200, body, extra=[("X-Aegis-Connector", "ok")])
        if self.path == "/big":
            return self._send(200, b"x" * BIG, "application/octet-stream")
        if self.path == "/cookies":
            return self._send(200, b"ok", "text/plain", [("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/")])
        if self.path == "/redirect":
            port = self.server.server_address[1]
            return self._send(302, b"", "text/plain", [("Location", f"http://127.0.0.1:{port}/next?x=1")])
        if self.path == "/notmodified":
            self.send_response(304)
            self.end_headers()
            return
        if self.path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"hello ", b"world"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
            return
        body = json.dumps({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self._send(200, body)

    do_HEAD = do_GET

    def do_POST(self):
        size = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(size)
        self._send(200, json.dumps({"received": len(data), "host": self.headers.get("Host")}).encode())


@pytest.fixture(scope="module")
def origin():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def through(spec: AppSpec, method="GET", path="/", headers=None, body=None):
    gw = Gateway([spec])
    port = free_port()
    servers = serve(gw, port)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request(method, path, body=body, headers={"Host": spec.hosts[0], **(headers or {})})
        resp = conn.getresponse()
        return resp, resp.read()
    finally:
        for s in servers:
            s.shutdown()


def test_customer_site_keeps_the_public_host(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, body = through(spec, headers={"X-Forwarded-For": "203.0.113.9"})
    seen = json.loads(body)["headers"]
    assert seen["host"] == "shop.kz"
    assert seen["x-forwarded-for"] == "203.0.113.9, 127.0.0.1"   # appended, never replaced
    assert seen["x-forwarded-host"] == "shop.kz"


def test_lab_app_gets_its_own_host_and_redirects_come_back(origin):
    spec = AppSpec("lab", f"http://127.0.0.1:{origin}", ["lab.localhost"], heal="off")
    resp, body = through(spec)
    assert json.loads(body)["headers"]["host"] == f"127.0.0.1:{origin}"
    resp, _ = through(spec, path="/redirect")
    assert resp.status == 302 and resp.getheader("Location") == "http://lab.localhost/next?x=1"


def test_big_download_is_streamed_whole(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, body = through(spec, path="/big")
    assert resp.status == 200 and len(body) == BIG and resp.getheader("Content-Length") == str(BIG)


def test_chunked_answer_and_every_cookie_pass(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, body = through(spec, path="/chunked")
    assert body == b"hello world"
    resp, _ = through(spec, path="/cookies")
    assert [v for k, v in resp.getheaders() if k.lower() == "set-cookie"] == ["a=1; Path=/", "b=2; Path=/"]


def test_head_304_and_post_body(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, body = through(spec, method="HEAD", path="/big")
    assert resp.status == 200 and body == b""
    resp, body = through(spec, path="/notmodified")
    assert resp.status == 304 and body == b""
    payload = "имя=Айгерим&комментарий=Отличный магазин".encode()
    resp, body = through(spec, method="POST", path="/order", body=payload,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert json.loads(body) == {"received": len(payload), "host": "shop.kz"}


def test_dead_origin_gets_a_page_not_a_traceback():
    spec = AppSpec("shop", f"http://127.0.0.1:{free_port()}", ["shop.kz"], preserve_host=True, heal="off")
    resp, body = through(spec, headers={"Accept": "text/html"})
    assert resp.status == 502 and "Сайт временно недоступен".encode() in body


def test_websocket_upgrade_is_refused_clearly(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, _ = through(spec, headers={"Upgrade": "websocket", "Connection": "Upgrade"})
    assert resp.status == 501


def test_blocked_visitor_sees_a_page_and_api_client_gets_json(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, body = through(spec, path="/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
                         headers={"Accept": "text/html,application/xhtml+xml"})
    assert resp.status == 403 and "Запрос остановлен".encode() in body and resp.getheader("X-Aegis-Incident")
    resp, body = through(spec, path="/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--")
    assert resp.status == 403 and json.loads(body)["reason"] == "sqli"


# --------------------------------------------------------------- TLS origin --

def test_tls_origin_by_ip_with_the_site_name_for_sni(tmp_path, make_cert):
    cert, key = make_cert(tmp_path, "shop.kz")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    names = []
    ctx.sni_callback = lambda sock, name, c: names.append(name)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        # Verified against the site name: our test CA is not trusted, so the origin is refused...
        strict = AppSpec("shop", f"https://127.0.0.1:{port}", ["shop.kz"], preserve_host=True, heal="off")
        resp, _ = through(strict)
        assert resp.status == 502
        # ...and with verification off (self-signed origin), the request goes through, SNI = site name.
        relaxed = AppSpec("shop", f"https://127.0.0.1:{port}", ["shop.kz"], preserve_host=True, tls_verify=False,
                          heal="off")
        resp, body = through(relaxed)
        assert resp.status == 200 and json.loads(body)["headers"]["host"] == "shop.kz"
        assert "shop.kz" in names
    finally:
        srv.shutdown()


def test_origin_url_must_be_http():
    with pytest.raises(ValueError):
        Origin("ftp://example.kz")
    assert Proxy(Origin("https://203.0.113.5")).origin.port == 443


def test_gateway_does_not_announce_itself(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    resp, _ = through(spec)
    server = resp.getheader("Server") or ""
    assert "WSGIServer" not in server and "CPython" not in server


def test_chunked_request_body_is_inspected_and_forwarded(origin):
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    gw = Gateway([spec])
    port = free_port()
    servers = serve(gw, port)
    try:
        def send(body: bytes) -> tuple[int, bytes]:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
                chunks = b"".join(b"%x\r\n%s\r\n" % (len(part), part) for part in (body[:7], body[7:])) + b"0\r\n\r\n"
                sock.sendall(b"POST /order HTTP/1.1\r\nHost: shop.kz\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                             b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + chunks)
                data = b""
                while chunk := sock.recv(65536):
                    data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            return int(head.split()[1]), rest
        status, body = send(b"q=jeans&size=32")
        assert status == 200 and json.loads(body)["received"] == len(b"q=jeans&size=32")
        status, _ = send(b"q=1' UNION SELECT password FROM users--")
        assert status == 403
    finally:
        for s in servers:
            s.shutdown()


def test_silent_clients_are_dropped(origin, monkeypatch):
    from aegis import gateway as gw_mod
    monkeypatch.setattr(gw_mod._Handler, "timeout", 1)
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off")
    port = free_port()
    servers = serve(Gateway([spec]), port)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: shop.kz\r\n")   # headers never finished
            import time as _t
            t0 = _t.time()
            assert sock.recv(1024) == b"" and _t.time() - t0 < 5           # the server hung up on its own
    finally:
        for s in servers:
            s.shutdown()


def test_origin_lock_signs_requests_and_keeps_the_connector_answer_inside(origin):
    from aegis.shield.signing import verify_origin
    spec = AppSpec("shop", f"http://127.0.0.1:{origin}", ["shop.kz"], preserve_host=True, heal="off",
                   origin_secret="s" * 64, options={"trust_proxy": True})
    resp, body = through(spec, path="/connector", headers={"X-Forwarded-For": "203.0.113.9",
                                                            "X-Aegis-Auth": "v1.1.forged"})
    seen = json.loads(body)
    assert verify_origin("s" * 64, seen["x-aegis-auth"], "shop.kz", "203.0.113.9")
    assert seen["x-real-ip"] == "203.0.113.9"
    assert resp.getheader("X-Aegis-Connector") is None
