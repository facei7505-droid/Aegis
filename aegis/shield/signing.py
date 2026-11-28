"""Signatures shared by Aegis and the site connectors (aegis/edge/connectors/*.php).

Origin lock. Aegis adds `X-Aegis-Auth: v1.<unix time>.<hmac>` to every request it forwards; the HMAC
covers the time, the public host and the visitor address Aegis sends in `X-Real-Ip`. The connector on
the site's own server refuses requests without a valid header, so someone who found the server's real
IP cannot go around Aegis, and it can trust `X-Real-Ip` as the visitor's address.

Editor pass. After a sign-in with editing rights, the connector sets a cookie
`aegis_editor=v1.<expires>.<user id>.<hmac>`. Aegis relaxes markup checks for editors only when this
cookie verifies, so a forged "I am signed in" cookie no longer works.

Both use HMAC-SHA256 with one secret per site, shared by Aegis and that site only. The PHP side
computes exactly the same strings: keep the two in step (tests/test_signing.py checks it with PHP).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

VERSION = "v1"
ORIGIN_HEADER = "X-Aegis-Auth"
EDITOR_COOKIE = "aegis_editor"
MAX_SKEW = 300  # seconds an origin signature stays valid (clock drift plus slow uploads)


def new_secret() -> str:
    return secrets.token_hex(32)


def _mac(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def canonical_host(host: str) -> str:
    """Host as both sides compare it. Mirrors the PHP exactly: trim() characters, ASCII-only lowercase."""
    host = (host or "").strip(" \t\n\r\x00\x0b").translate(_ASCII_LOWER)
    if host.startswith("["):                       # [2001:db8::1]:443
        end = host.find("]")
        return host if end == -1 else host[:end + 1]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _origin_message(ts: int, host: str, client_ip: str, method: str, target: str) -> str:
    # Bound to the request line: a signature that leaks (a phpinfo page shows request headers) opens only
    # that same request again, for a few minutes, not the whole site.
    return f"{VERSION}|{ts}|{canonical_host(host)}|{client_ip}|{method.upper()}|{target}"


def origin_auth(secret: str, host: str, client_ip: str, method: str = "GET", target: str = "/",
                now: float | None = None) -> str:
    ts = int(now if now is not None else time.time())
    return f"{VERSION}.{ts}.{_mac(secret, _origin_message(ts, host, client_ip, method, target))}"


def verify_origin(secret: str, value: str, host: str, client_ip: str, method: str = "GET", target: str = "/",
                  now: float | None = None) -> bool:
    try:
        version, ts, mac = (value or "").split(".")
    except ValueError:
        return False
    if version != VERSION or not ts.isdigit() or abs((now if now is not None else time.time()) - int(ts)) > MAX_SKEW:
        return False
    return hmac.compare_digest(mac, _mac(secret, _origin_message(int(ts), host, client_ip, method, target)))


def editor_pass(secret: str, user_id: int | str, expires: int) -> str:
    return f"{VERSION}.{int(expires)}.{user_id}.{_mac(secret, f'editor|{int(expires)}|{user_id}')}"


def verify_editor(secret: str, value: str, now: float | None = None) -> bool:
    try:
        version, expires, user_id, mac = (value or "").split(".")
        exp_i = int(expires)
    except ValueError:
        return False
    if not expires.isdigit():
        return False
    if version != VERSION or not user_id.isdigit() or exp_i < (now if now is not None else time.time()):
        return False
    return hmac.compare_digest(mac, _mac(secret, f"editor|{exp_i}|{user_id}"))


FAILOVER_HEADER = "X-Aegis-Failover"
FAILOVER_MAX = 24 * 3600  # the longest a site can be opened at once


def failover_token(secret: str, host: str, until: int, issued: int | None = None) -> str:
    """Tells the connector to let direct visitors in until `until` (Aegis is down, DNS points at the site);
    `until` 0 closes it again. Tokens are fresh (issued within MAX_SKEW) and only ever move forward: the
    connector refuses one issued before the last it accepted, so a replayed "open" cannot undo a "close"."""
    issued = int(issued if issued is not None else time.time())
    return f"{VERSION}.{int(until)}.{issued}.{_mac(secret, f'failover|{int(until)}|{issued}|{canonical_host(host)}')}"


def verify_failover(secret: str, value: str, host: str, now: float | None = None) -> tuple[int, int] | None:
    """(until, issued) of a valid, fresh token; None otherwise."""
    now = now if now is not None else time.time()
    try:
        version, until, issued, mac = (value or "").split(".")
    except ValueError:
        return None
    if version != VERSION or not until.isdigit() or not issued.isdigit():
        return None
    until_i, issued_i = int(until), int(issued)
    if abs(now - issued_i) > MAX_SKEW or (until_i and not now < until_i <= issued_i + FAILOVER_MAX):
        return None
    if not hmac.compare_digest(mac, _mac(secret, f"failover|{until_i}|{issued_i}|{canonical_host(host)}")):
        return None
    return until_i, issued_i
