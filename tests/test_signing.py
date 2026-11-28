"""Origin lock and editor pass: Python (Aegis) and PHP (the site connectors) must agree byte for byte."""
from __future__ import annotations

import http.client
import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from aegis.edge import connector
from aegis.proxy import Origin, Proxy
from aegis.shield.core import ShieldCore, ShieldConfig
from aegis.shield.signing import (ORIGIN_HEADER, canonical_host, editor_pass, new_secret, origin_auth, verify_editor,
                                  verify_origin)

PHP = shutil.which("php")
needs_php = pytest.mark.skipif(PHP is None or sys.platform == "win32", reason="php not installed")
SECRET = "a" * 64


def test_origin_signature_round_trip():
    now = 1_800_000_000
    value = origin_auth(SECRET, "Shop.KZ:443", "203.0.113.9", now)
    assert value.startswith("v1.1800000000.")
    assert verify_origin(SECRET, value, "shop.kz", "203.0.113.9", now + 10)
    assert not verify_origin(SECRET, value, "shop.kz", "203.0.113.10", now)       # another visitor address
    assert not verify_origin(SECRET, value, "evil.kz", "203.0.113.9", now)        # another site
    assert not verify_origin("b" * 64, value, "shop.kz", "203.0.113.9", now)      # another secret
    assert not verify_origin(SECRET, value, "shop.kz", "203.0.113.9", now + 301)  # too old
    for junk in ("", "v1", "v1.x.y", "v2.1800000000.ab", "v1.-5.ab", value + ".x"):
        assert not verify_origin(SECRET, junk, "shop.kz", "203.0.113.9", now)


def test_canonical_host():
    assert canonical_host("Shop.KZ:8443") == "shop.kz"
    assert canonical_host("[2001:db8::1]:443") == "[2001:db8::1]"
    assert canonical_host("2001:db8::1") == "2001:db8::1"


def test_editor_pass():
    now = 1_800_000_000
    good = editor_pass(SECRET, 7, now + 3600)
    assert verify_editor(SECRET, good, now)
    assert not verify_editor(SECRET, good, now + 7200)                  # expired
    assert not verify_editor("b" * 64, good, now)
    assert not verify_editor(SECRET, good.replace(".7.", ".1."), now)   # another user, same mac
    assert not verify_editor(SECRET, "v1.9999999999.1.deadbeef", now)
    assert len(new_secret()) == 64


def test_proxy_signs_and_strips_client_supplied_aegis_headers():
    proxy = Proxy(Origin("https://198.51.100.7", preserve_host=True), secret=SECRET)
    environ = {"HTTP_HOST": "shop.kz", "REMOTE_ADDR": "127.0.0.1", "aegis.client_ip": "203.0.113.9",
               "HTTP_X_AEGIS_AUTH": "v1.1.forged", "HTTP_X_AEGIS_CONNECTOR": "ok", "wsgi.url_scheme": "https"}
    headers = proxy.request_headers(environ)
    assert "X-Aegis-Connector" not in headers
    assert verify_origin(SECRET, headers[ORIGIN_HEADER], "shop.kz", "203.0.113.9")
    assert ORIGIN_HEADER not in Proxy(Origin("https://198.51.100.7")).request_headers(environ)


def _wp_shield(secret=None):
    return ShieldCore(ShieldConfig(preset="wordpress", editor_secret=secret))


def _post(shield, cookies):
    inputs = [("cookie", name, value) for name, value in cookies.items()]
    inputs.append(("json", "content", "<p>Акция</p><script>window.kaspi()</script>"))
    return shield.inspect("203.0.113.9", "POST", "/wp-json/wp/v2/posts/12", inputs)


def test_signed_editor_pass_replaces_the_forgeable_cookie():
    forged = {"wordpress_logged_in_x": "admin|1|x|y"}
    assert not _post(_wp_shield(), forged).blocked              # without a connector the cookie name is trusted
    assert _post(_wp_shield(SECRET), forged).blocked            # with one, a forged cookie relaxes nothing
    good = {**forged, "aegis_editor": editor_pass(SECRET, 1, time.time() + 3600)}
    assert not _post(_wp_shield(SECRET), good).blocked
    stale = {**forged, "aegis_editor": editor_pass(SECRET, 1, time.time() - 1)}
    assert _post(_wp_shield(SECRET), stale).blocked


def test_render_fills_in_the_secret():
    [(name, source)] = connector.render("wordpress", SECRET, "report")
    assert name == "aegis-connector.php" and source.startswith("<?php\n/**\n * Plugin Name: Aegis Connector")
    assert SECRET in source and "'report'" in source and "{{" not in source
    assert source.count("<?php") == 1
    (name, source), (editor_name, editor) = connector.render("bitrix", SECRET)
    assert name == "aegis-lock.php" and "'enforce'" in source and "editor" not in source
    assert editor_name == "aegis-editor.php" and SECRET in editor and "OnBeforeProlog" in editor
    with pytest.raises(ValueError):
        connector.render("generic", SECRET, "maybe")


# --------------------------------------------------------------- PHP side --

def _php(code: str) -> str:
    return subprocess.run([PHP, "-r", code], capture_output=True, text=True, timeout=30, check=True).stdout


@needs_php
def test_php_accepts_what_python_signs(tmp_path):
    [(name, source)] = connector.render("generic", SECRET, "off")
    (tmp_path / name).write_text(source)
    value = origin_auth(SECRET, "shop.kz:443", "203.0.113.9")
    out = _php(f"$_SERVER['HTTP_X_AEGIS_AUTH']='{value}';$_SERVER['HTTP_X_REAL_IP']='203.0.113.9';"
               f"$_SERVER['HTTP_HOST']='SHOP.kz:443';require '{tmp_path / name}';"
               "echo aegis_origin_ok() ? 'yes' : 'no'; $_SERVER['HTTP_X_REAL_IP']='1.2.3.4';"
               "echo aegis_origin_ok() ? 'yes' : 'no';")
    assert out == "yesno"


@needs_php
def test_python_accepts_the_php_editor_pass(tmp_path):
    [(_, source)] = connector.render("wordpress", SECRET)
    editor = source.split("Editor pass", 1)[1]
    funcs = editor[editor.index("function aegis_editor_pass"):editor.index("function aegis_editor_cookie")]
    expires = int(time.time()) + 7200
    out = _php(f"define('AEGIS_SECRET','{SECRET}'); {funcs} echo aegis_editor_pass(42, {expires});")
    assert out == editor_pass(SECRET, 42, expires)
    assert verify_editor(SECRET, out)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@needs_php
def test_locked_site_answers_only_through_aegis(tmp_path):
    """A real PHP server with the connector: Aegis gets through and passes the visitor's IP; a direct hit gets 403."""
    [(name, source)] = connector.render("generic", SECRET, "enforce")
    (tmp_path / name).write_text(source)
    (tmp_path / "index.php").write_text("<?php define('AEGIS_TRUST_LOCAL', false); require __DIR__ . '/" + name +
                                        "'; echo 'shop:' . $_SERVER['REMOTE_ADDR'];")
    port = _free_port()
    srv = subprocess.Popen([PHP, "-S", f"127.0.0.1:{port}", "-t", str(tmp_path)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)

        def get(headers):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", "/", headers={"Host": "shop.kz", **headers})
            resp = conn.getresponse()
            return resp.status, resp.getheader("X-Aegis-Connector"), resp.read().decode()

        proxy = Proxy(Origin(f"http://127.0.0.1:{port}", preserve_host=True), secret=SECRET)
        signed = proxy.request_headers({"HTTP_HOST": "shop.kz", "REMOTE_ADDR": "127.0.0.1",
                                        "aegis.client_ip": "203.0.113.9"})
        assert get(signed) == (200, "ok", "shop:203.0.113.9")
        status, answer, _ = get({"X-Real-Ip": "203.0.113.9"})
        assert (status, answer) == (403, "refused")
        status, answer, _ = get({**signed, ORIGIN_HEADER: origin_auth("b" * 64, "shop.kz", "203.0.113.9")})
        assert (status, answer) == (403, "bad-signature") or (status, answer) == (403, "refused")

        site = SimpleNamespace(origin=f"http://127.0.0.1:{port}", tls_verify=True, domain="shop.kz", secret=SECRET)
        check = connector.verify(site)
        assert check.installed and check.enforced
    finally:
        srv.terminate()
        srv.wait(10)
