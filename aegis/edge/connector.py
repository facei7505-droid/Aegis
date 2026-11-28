"""Site connectors: small PHP files the client puts on the site's own server.

    aegis edge connector shop.kz            # writes the file for the site's CMS, prints how to install it
    aegis edge connector shop.kz --verify   # checks the installed connector, then relies on it

What a connector does (shield/signing.py has the algorithm):
  * origin lock: the site answers only requests that came through Aegis, so the server's real IP is
    no back door;
  * the visitor's real address for the CMS (logs, comment spam filters, its own login limits);
  * WordPress: a signed editor pass, so a forged "signed in" cookie no longer relaxes markup checks.
"""
from __future__ import annotations

import http.client
import ssl
import time
from dataclasses import dataclass
from pathlib import Path

from ..shield.signing import ORIGIN_HEADER, origin_auth

HERE = Path(__file__).parent / "connectors"
WP_HEADER = """<?php
/**
 * Plugin Name: Aegis Connector
 * Description: Aegis Щит — сайт принимает трафик только через защиту, видит настоящий IP посетителя и
 *              выдаёт редакторам подписанный пропуск.
 * Version: 1.0
 * License: MIT
 */
if (!defined('ABSPATH')) {
    exit;
}
"""


def render(cms: str, secret: str, mode: str = "enforce") -> list[tuple[str, str]]:
    """[(file name, PHP source)] for this CMS, with the site's secret filled in."""
    if mode not in ("enforce", "report", "off"):
        raise ValueError("mode: enforce, report или off")
    lock = (HERE / "lock.php").read_text(encoding="utf-8")
    lock = lock.replace("{{SECRET}}", secret).replace("{{MODE}}", mode)
    if cms == "wordpress":
        body = lock.split("<?php", 1)[1]
        return [("aegis-connector.php",
                 WP_HEADER + body + (HERE / "wordpress-editor.php").read_text(encoding="utf-8"))]
    if cms == "bitrix":  # the lock runs before the kernel (dbconn.php), the editor pass after it (init.php)
        editor = (HERE / "bitrix-editor.php").read_text(encoding="utf-8").replace("{{SECRET}}", secret)
        return [("aegis-lock.php", lock), ("aegis-editor.php", editor)]
    return [("aegis-lock.php", lock)]


INSTALL = {
    "wordpress": """Установка (WordPress):
  1. Загрузите {name} в папку wp-content/mu-plugins/ на сервере сайта (создайте папку, если её нет).
     Плагины из mu-plugins включаются сами и не выключаются из админки.
  2. Проверьте: aegis edge connector {domain} --verify""",
    "bitrix": """Установка (1С-Битрикс):
  1. Загрузите aegis-lock.php и aegis-editor.php в /bitrix/php_interface/ на сервере сайта.
  2. Первой строкой в /bitrix/php_interface/dbconn.php (после <?php) добавьте:
         require_once __DIR__ . '/aegis-lock.php';
  3. В /bitrix/php_interface/init.php (создайте, если нет) добавьте:
         require_once __DIR__ . '/aegis-editor.php';
  4. Проверьте: aegis edge connector {domain} --verify""",
    "opencart": """Установка (OpenCart):
  1. Загрузите {name} в корень сайта (рядом с config.php).
  2. Первой строкой в config.php и admin/config.php (после <?php) добавьте:
         require_once '/полный/путь/к/сайту/{name}';
  3. Проверьте: aegis edge connector {domain} --verify""",
    "generic": """Установка (любой сайт на PHP):
  1. Загрузите {name} на сервер сайта, например в корень.
  2. Подключите его до кода сайта одним из способов:
       • PHP-FPM: в .user.ini в корне сайта:   auto_prepend_file = /полный/путь/{name}
       • Apache + mod_php: в .htaccess:         php_value auto_prepend_file /полный/путь/{name}
       • или первой строкой index.php:          require_once __DIR__ . '/{name}';
  3. Проверьте: aegis edge connector {domain} --verify""",
}


def firewall_rules(server_ip: str) -> str:
    """The second lock, for clients with their own server: only Aegis may reach ports 80 and 443."""
    ip = server_ip or "<IP сервера Aegis>"
    return f"""Второй замок, если у клиента свой сервер (VPS), а не обычный хостинг:
  nginx (в server {{ }} сайта):   allow {ip}; allow 127.0.0.1; deny all;
  Apache 2.4 (.htaccess):        Require ip {ip} 127.0.0.1
  ufw:                           ufw allow from {ip} to any port 80,443 proto tcp
                                 ufw deny 80/tcp && ufw deny 443/tcp"""


@dataclass
class Check:
    signed_status: int = 0
    signed_answer: str = ""        # X-Aegis-Connector on a signed request: ok | bad-signature | ""
    unsigned_status: int = 0
    unsigned_answer: str = ""      # refused when the lock is enforced
    error: str = ""

    @property
    def installed(self) -> bool:
        return self.signed_answer == "ok"

    @property
    def enforced(self) -> bool:
        return self.unsigned_status == 403 and self.unsigned_answer == "refused"


def verify(site, timeout: float = 15.0) -> Check:
    """Ask the origin directly, as Aegis would and as a stranger would, and read the connector's answer."""
    from ..proxy import Origin, _TLSConnection

    origin = Origin(site.origin, preserve_host=True, tls_verify=site.tls_verify)
    result = Check()

    def ask(signed: bool) -> tuple[int, str]:
        if origin.scheme == "https":
            ctx = ssl.create_default_context()
            if not site.tls_verify:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = _TLSConnection(origin.host, origin.port, site.domain, ctx, timeout)
        else:
            conn = http.client.HTTPConnection(origin.host, origin.port, timeout=timeout)
        headers = {"Host": site.domain, "User-Agent": "AegisEdge-connector-check/1.0", "X-Real-Ip": "192.0.2.10"}
        if signed:
            headers[ORIGIN_HEADER] = origin_auth(site.secret, site.domain, "192.0.2.10", "GET", "/", now=time.time())
        try:
            conn.request("GET", "/", headers=headers)
            resp = conn.getresponse()
            resp.read(65536)
            return resp.status, (resp.getheader("X-Aegis-Connector") or "").strip()
        finally:
            conn.close()

    try:
        result.signed_status, result.signed_answer = ask(True)
        result.unsigned_status, result.unsigned_answer = ask(False)
    except (OSError, http.client.HTTPException) as exc:
        result.error = str(exc) or exc.__class__.__name__
    return result
