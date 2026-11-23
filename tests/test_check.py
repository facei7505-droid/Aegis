"""Passive site check: what a visitor can see, judged on local stand-ins for real sites."""
from __future__ import annotations

import datetime as dt
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.cli import main
from aegis.edge.check import as_pdf, as_text, check

TODAY = dt.date(2026, 11, 23)


def serve(handler, tls=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def page_handler(headers, body, login=b""):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            data = login if (login and self.path.startswith(("/wp-login.php", "/bitrix/admin"))) else body
            self.send_response(200)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return H


OLD_WP = page_handler(
    [("Content-Type", "text/html"), ("X-Powered-By", "PHP/7.4.33"), ("Server", "Apache/2.4.41 (Ubuntu)"),
     ("Set-Cookie", "PHPSESSID=abc; path=/")],
    b'<html><head><meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/themes/x.css"></head></html>',
    b'<form><input type="password" name="pwd"></form>')


def test_old_wordpress_over_http_gets_a_low_grade():
    srv = serve(OLD_WP)
    try:
        r = check(f"http://shop.test:{srv.server_address[1]}/", connect_to="127.0.0.1", today=TODAY)
    finally:
        srv.shutdown()
    titles = {f.title: f.severity for f in r.findings}
    assert r.cms == "WordPress" and r.cms_version == "6.4.2"
    assert titles["Сайт работает без HTTPS"] == "high"
    assert titles["PHP 7.4 больше не получает обновлений безопасности"] == "high"
    assert titles["Страница входа в админку открыта всему интернету"] == "medium"
    assert titles["Cookie сессии без защитных флагов"] == "medium"
    assert "Видна версия WordPress: 6.4.2" in titles and r.grade in "DF"
    text = as_text(r)
    assert "оценка" in text and "→" in text


def test_php_close_to_end_of_life_is_a_warning():
    srv = serve(page_handler([("X-Powered-By", "PHP/8.2.20")], b"<html></html>"))
    try:
        r = check(f"http://shop.test:{srv.server_address[1]}/", connect_to="127.0.0.1", today=TODAY)
    finally:
        srv.shutdown()
    assert any(f.title.startswith("PHP 8.2 скоро") and f.severity == "medium" for f in r.findings)


def test_untrusted_certificate_is_reported(tmp_path):
    pytest.importorskip("cryptography")
    from tests.test_proxy import _cert
    cert, key = _cert(tmp_path, "shop.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = serve(page_handler([("Strict-Transport-Security", "max-age=31536000"), ("X-Frame-Options", "DENY"),
                              ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", "default-src 'self'")],
                             b'<html><script src="https://static.tildacdn.com/js/x.js"></script></html>'), ctx)
    try:
        r = check(f"https://shop.test:{srv.server_address[1]}/", connect_to="127.0.0.1", today=TODAY)
    finally:
        srv.shutdown()
    assert r.https and r.cms == "Tilda"
    assert any(f.title == "Сертификат HTTPS не принимается браузерами" for f in r.findings)
    assert not any("HSTS" in f.title or "CSP" in f.title for f in r.findings)


def test_pdf_for_the_owner():
    pytest.importorskip("reportlab")
    srv = serve(OLD_WP)
    try:
        r = check(f"http://shop.test:{srv.server_address[1]}/", connect_to="127.0.0.1", today=TODAY)
    finally:
        srv.shutdown()
    assert as_pdf(r, contact="@aegis_kz").startswith(b"%PDF")


def test_cli_reports_unreachable_sites(capsys):
    assert main(["check", "http://127.0.0.1:9/", "--timeout", "2"]) in (1, 2)
    assert main(["check", "not a domain"]) == 2
